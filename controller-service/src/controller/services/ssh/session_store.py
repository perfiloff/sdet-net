"""In-memory registry of DUT SSH sessions (control vtysh vs monitor log streams)."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass

from controller.core.settings import Settings
from controller.models.schemas import MonitorConfig, SessionKind
from controller.models.ssh import SSHConfig
from controller.services.ssh.device_monitor import DeviceMonitorSession
from controller.services.ssh.frr import FrrVtyshSession


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Metadata for a session (for API listing)."""

    session_id: str
    host: str
    port: int
    bootstrap: bool
    kind: SessionKind

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


class VtyshSessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, FrrVtyshSession | DeviceMonitorSession] = {}
        self._kinds: dict[str, SessionKind] = {}
        self._bootstrap_ids: set[str] = set()
        self._endpoint: dict[str, tuple[str, int]] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        settings: Settings,
        ssh: SSHConfig | None = None,
        *,
        bootstrap: bool = False,
        kind: SessionKind = "control",
        monitor: MonitorConfig | None = None,
    ) -> str:
        eff = ssh or SSHConfig(
            host=settings.dut_ssh_host,
            port=settings.dut_ssh_port,
            username=settings.dut_ssh_username,
            password=settings.dut_ssh_password,
        )
        if kind == "control":
            session: FrrVtyshSession | DeviceMonitorSession = FrrVtyshSession(settings, ssh)
            await session.login()
        else:
            if monitor is None:
                raise ValueError("monitor config required for monitor sessions")
            session = DeviceMonitorSession(settings, ssh, monitor)
            await session.start()

        sid = str(uuid.uuid4())
        async with self._lock:
            self._sessions[sid] = session
            self._kinds[sid] = kind
            self._endpoint[sid] = (eff.host, eff.port)
            if bootstrap:
                self._bootstrap_ids.add(sid)
        return sid

    def get_kind(self, session_id: str) -> SessionKind | None:
        return self._kinds.get(session_id)

    def get(self, session_id: str) -> FrrVtyshSession | DeviceMonitorSession | None:
        return self._sessions.get(session_id)

    def get_control(self, session_id: str) -> FrrVtyshSession | None:
        if self._kinds.get(session_id) != "control":
            return None
        s = self._sessions.get(session_id)
        return s if isinstance(s, FrrVtyshSession) else None

    def get_monitor(self, session_id: str) -> DeviceMonitorSession | None:
        if self._kinds.get(session_id) != "monitor":
            return None
        s = self._sessions.get(session_id)
        return s if isinstance(s, DeviceMonitorSession) else None

    def list_records(self) -> list[SessionRecord]:
        rows: list[SessionRecord] = []
        for sid in sorted(self._sessions.keys()):
            host, port = self._endpoint.get(sid, ("", 0))
            kind = self._kinds.get(sid, "control")
            rows.append(
                SessionRecord(
                    session_id=sid,
                    host=host,
                    port=port,
                    bootstrap=sid in self._bootstrap_ids,
                    kind=kind,
                )
            )
        return rows

    async def delete(self, session_id: str) -> None:
        async with self._lock:
            sess = self._sessions.pop(session_id, None)
            self._endpoint.pop(session_id, None)
            self._bootstrap_ids.discard(session_id)
            self._kinds.pop(session_id, None)
        if sess is not None:
            await sess.logout()

    async def close_all(self) -> None:
        async with self._lock:
            items = list(self._sessions.items())
            self._sessions.clear()
            self._endpoint.clear()
            self._bootstrap_ids.clear()
            self._kinds.clear()
        for _, sess in items:
            await sess.logout()
