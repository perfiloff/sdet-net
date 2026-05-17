from __future__ import annotations

from abc import ABC, abstractmethod


class FSMRunnerInterface(ABC):

    @abstractmethod
    async def run(self, context: Context) -> Context:
        """Execute a single state transition for the provided context."""
        pass

    @abstractmethod
    async def create(
        self,
        initial_ctx: InitialContext,
        transitions: dict[tuple[str, str], type[State]] | None = None,
    ) -> Context | None:
        """Create a new FSM context from an initial request."""
        pass


    @abstractmethod
    async def run(self, context: Context) -> Context:
        """Execute state transitions until the FSM reaches waiting, terminal, or pending-event state."""
        pass
