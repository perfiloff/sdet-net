"""In-memory registry of interactive vtysh sessions (one DUT PTY per id)."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass

from controller.core.settings import Settings
from controller.models.ssh import SSHConfig
from controller.services.ssh.frr import FrrVtyshSession


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Metadata for a vtysh session (for API listing)."""

    session_id: str
    host: str
    port: int
    bootstrap: bool

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


class VtyshSessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, FrrVtyshSession] = {}
        self._bootstrap_ids: set[str] = set()
        self._endpoint: dict[str, tuple[str, int]] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        settings: Settings,
        ssh: SSHConfig | None = None,
        *,
        bootstrap: bool = False,
    ) -> str:
        session = FrrVtyshSession(settings, ssh)
        await session.login()
        sid = str(uuid.uuid4())
        eff = ssh or SSHConfig(
            host=settings.dut_ssh_host,
            port=settings.dut_ssh_port,
            username=settings.dut_ssh_username,
            password=settings.dut_ssh_password,
        )
        async with self._lock:
            self._sessions[sid] = session
            self._endpoint[sid] = (eff.host, eff.port)
            if bootstrap:
                self._bootstrap_ids.add(sid)
        return sid

    def get(self, session_id: str) -> FrrVtyshSession | None:
        return self._sessions.get(session_id)

    def list_records(self) -> list[SessionRecord]:
        rows: list[SessionRecord] = []
        for sid in sorted(self._sessions.keys()):
            host, port = self._endpoint.get(sid, ("", 0))
            rows.append(
                SessionRecord(
                    session_id=sid,
                    host=host,
                    port=port,
                    bootstrap=sid in self._bootstrap_ids,
                )
            )
        return rows

    async def delete(self, session_id: str) -> None:
        async with self._lock:
            sess = self._sessions.pop(session_id, None)
            self._endpoint.pop(session_id, None)
            self._bootstrap_ids.discard(session_id)
        if sess is not None:
            await sess.logout()

    async def close_all(self) -> None:
        async with self._lock:
            items = list(self._sessions.items())
            self._sessions.clear()
            self._endpoint.clear()
            self._bootstrap_ids.clear()
        for _, sess in items:
            await sess.logout()
