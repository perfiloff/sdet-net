from __future__ import annotations

from controller.services.ssh.frr import FrrVtyshSession, FrrVtyshSshBackend
from controller.services.ssh.interface import VtyshSshBackend


class SSHService:
    """Application service: batch vtysh via backend; interactive sessions via ``new_interactive_session``."""

    def __init__(self, backend: VtyshSshBackend) -> None:
        self._backend = backend

    @property
    def backend(self) -> VtyshSshBackend:
        return self._backend

    async def run_vtysh_commands(
        self,
        commands: list[str],
        *,
        timeout: float | None = None,
    ) -> tuple[str, int]:
        return await self._backend.run_commands(commands, timeout=timeout)

    def new_interactive_session(self) -> FrrVtyshSession:
        b = self._backend
        if not isinstance(b, FrrVtyshSshBackend):
            raise TypeError("Interactive sessions require FrrVtyshSshBackend")
        return FrrVtyshSession(b.settings, b.ssh_override)
