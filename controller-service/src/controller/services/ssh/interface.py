from __future__ import annotations

from typing import Any, Protocol


class VtyshSshBackend(Protocol):
    """Stateless batch vtysh over SSH (separate short-lived `vtysh -c` invocations)."""

    async def run_commands(
        self,
        commands: list[str],
        *,
        timeout: float | None = None,
        existing_conn: object | None = None,
    ) -> tuple[str, int]:
        """Return combined stdout/stderr and remote exit status."""


class VtyshInteractiveShell(Protocol):
    """Interactive vtysh PTY (stdin/stdout) for ``terminal monitor`` and raw I/O."""

    @property
    def stdin(self) -> Any:
        """AsyncSSH writer (async write/drain)."""

    @property
    def stdout(self) -> Any:
        """AsyncSSH reader (async read)."""


class VtyshInteractiveSession(Protocol):
    """Long-lived SSH + interactive vtysh; configure/show use the same PTY as the CLI."""

    async def login(self) -> None:
        """Open SSH and start interactive vtysh (PTY)."""

    async def logout(self) -> None:
        """Tear down vtysh and SSH."""

    async def get_shell(self) -> VtyshInteractiveShell:
        """PTY streams; use WebSocket shell or drive manually. Raises if not logged in."""

    async def show(self, command: str) -> str:
        """Exec a single exec-mode command on the open PTY (not ``vtysh -c``)."""

    async def configure(self, commands: list[str]) -> str:
        """``configure terminal`` then listed lines, then ``end``."""
