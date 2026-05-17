from __future__ import annotations

import logging


class PlayerService:
    """Service facade for player workflows."""

    def __init__(
        self,
        player_interface: PlayerInterface,
        name: str | None = None,
    ):
        self.fsm_interface = fsm_interface
        self.name = name or "player"
    
    async def create(
        self,
        initial_ctx: InitialContext,
        transitions: dict[tuple[str, str], type[State]] | None = None,
    ):
        return await self.fsm_interface.create(initial_ctx, transitions=transitions)

    async def run(self, context):
        return await self.fsm_interface.run(context)
