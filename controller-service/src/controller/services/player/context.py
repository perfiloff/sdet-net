from __future__ import annotations

import logging



class Context:
    _state = None

    def __init__(
        self,
        state: State,
        app_container: AppContainer,
        transitions: dict[tuple[str, str], type[State]] | None = None,
    ):
        self._app_container = app_container
        self._data: PlayerContext | None = None
        self._pending_event: str | None = None
        # In-memory-only credentials produced by rotation states. They MUST
        # never be persisted to Redis: cache only carries the RotationContext
        # at self._data, while these live on the Context wrapper itself.
        self.set_state(state)

    @property
    def request_ctx(self) -> InitialContext | SpawnContext:
        return self._request_ctx

    @property
    def app_container(self) -> AppContainer:
        return self._app_container

    @property
    def data(self) -> PlayerContext | None:
        return self._data

    @data.setter
    def data(self, data: PlayerContext) -> None:
        self._data = data

    @property
    def state(self) -> "State":
        if self._state is None:
            raise ContextError("State not set in context")
        return self._state

    @property
    def has_pending_event(self) -> bool:
        return self._pending_event is not None

    def set_state(self, state: State) -> None:
        self._state = state
        self._state.context = self

    def upgrade_transitions(self, transitions: dict[tuple[str, str], type[State]]) -> None:
        """Switch to a different transition table for the next phase."""
        self._transitions = transitions

    async def run(self) -> None:
        if self._state is None:
            raise ContextError(
                message="State not set in context",
                detail=ErrorDetail(code=500, tx_id=self.data.x_request_id if self.data else None),
            )
        await self._state.run()

    def __str__(self):
        return f"Context(state={self._state.__class__.__name__ if self._state else None}, data={self._data})"
