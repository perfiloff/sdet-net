from __future__ import annotations

import logging

from controller.services.player.interface import PlayerInterface
from controller.services.player.context import Context

class PlayerRunner(PlayerInterface):
    """Iterative FSM executor with Redis persistence.
    """

    def __init__(self, app_container: AppContainer):
        self._container = app_container

    # ---- public API ---------------------------------------------------
    async def run(self, context: Context) -> Context:
        self.logger.debug(
            "Running single FSM step for transaction_id=%s in state=%s",
            context.data.transaction_id if context.data else None,
            context.data.state if context.data else None,
        )
        await context.run()
        return context

    async def create(
        self,
        initial_ctx: InitialContext,
        transitions: dict[tuple[str, str], type[State]] | None = None,
    ) -> Context | None:
        context = Context(
            Initialize(),
            request_ctx=initial_ctx,
            app_container=self._container,
            transitions=transitions or TRANSITIONS,
        )
        # run the very first state to set initial context data.
        await self.run(context)
        return context

    async def run(self, context: Context) -> Context:
        while True:
            current_status = context.data.state if context.data else None
            self.logger.debug(
                "Running FSM for transaction_id=%s in state=%s",
                context.data.transaction_id if context.data else None,
                context.state.name,
            )
            await context.run()
            if context.data is None:
                raise FSMRunnerError("Rotation context is empty after state run")


            if self._is_terminal(context):
                self.logger.debug(
                    "Context is terminal: %s", context.data.transaction_id
                )
                return context

    _WAITING_STATES = (PlayerState.WAITING,)
    _TERMINAL_STATES = (PlayerState.TERMINATED,)

    def _is_waiting(self, context: Context) -> bool:
        if context.data is None:
            return False
        return context.data.state in self._WAITING_STATES

    def _is_terminal(self, context: Context) -> bool:
        if context.data is None:
            return False
        return context.data.state in self._TERMINAL_STATES
