"""Dedicated SSH session for streaming device logs (vtysh ``terminal monitor`` or ``tail -f``)."""

from __future__ import annotations

import asyncio
import logging

import asyncssh
from asyncssh import STDOUT
from asyncssh.process import SSHClientProcess

from controller.core.settings import Settings
from controller.models.schemas import MonitorConfig
from controller.models.ssh import SSHConfig
from controller.services.ssh.frr import connect_kwargs

logger = logging.getLogger(__name__)


class DeviceMonitorSession:
    """SSH connection with a long-running process whose stdout is streamed to a WebSocket."""

    def __init__(
        self,
        settings: Settings,
        ssh: SSHConfig | None,
        monitor: MonitorConfig,
    ) -> None:
        self._settings = settings
        self._ssh = ssh
        self._monitor = monitor
        self._conn: asyncssh.SSHClientConnection | None = None
        self._proc: SSHClientProcess | None = None
        self._proc_cm: object | None = None
        self._streaming = False

    @property
    def mode(self) -> str:
        return self._monitor.mode

    def _effective_ssh(self) -> SSHConfig:
        if self._ssh:
            return self._ssh
        s = self._settings
        return SSHConfig(
            host=s.dut_ssh_host,
            port=s.dut_ssh_port,
            username=s.dut_ssh_username,
            password=s.dut_ssh_password,
        )

    async def start(self) -> None:
        if self._proc is not None:
            return
        s = self._settings
        cfg = self._effective_ssh()
        kw = connect_kwargs(
            cfg,
            s.dut_ssh_known_hosts,
            accept_unknown_host=not s.dut_ssh_known_hosts,
        )
        self._conn = await asyncssh.connect(**kw)
        assert self._conn is not None

        if self._monitor.mode == "terminal_monitor":
            self._proc_cm = self._conn.create_process(
                "vtysh",
                term_type="xterm",
                stderr=STDOUT,
                encoding="utf-8",
            )
            self._proc = await self._proc_cm.__aenter__()
            await self._drain_initial()
            await self._write_line("terminal monitor")
        else:
            path = self._monitor.tail_path or ""
            if not path.strip():
                raise ValueError("tail_path is required for tail mode")
            self._proc_cm = self._conn.create_process(
                ["tail", "-n", "200", "-f", path],
                stderr=STDOUT,
            )
            self._proc = await self._proc_cm.__aenter__()

        assert self._proc is not None

    async def _drain_initial(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        deadline = asyncio.get_running_loop().time() + 5.0
        idle = 0.2
        while asyncio.get_running_loop().time() < deadline:
            try:
                chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=idle)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break

    async def _write_line(self, line: str) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise RuntimeError("monitor process not available")
        raw = line if line.endswith("\n") else line + "\n"
        proc.stdin.write(raw)
        await proc.stdin.drain()

    @property
    def stdout(self):
        if self._proc is None:
            raise RuntimeError("monitor session not started")
        out = self._proc.stdout
        if out is None:
            raise RuntimeError("monitor process has no stdout")
        return out

    def try_acquire_stream(self) -> bool:
        if self._streaming:
            return False
        self._streaming = True
        return True

    def release_stream(self) -> None:
        self._streaming = False

    async def logout(self) -> None:
        self._streaming = False
        if self._proc_cm is not None:
            try:
                await self._proc_cm.__aexit__(None, None, None)
            except (OSError, asyncssh.Error, asyncio.CancelledError):
                pass
            self._proc_cm = None
            self._proc = None
        if self._conn is not None:
            self._conn.close()
            try:
                await self._conn.wait_closed()
            except (OSError, asyncssh.Error):
                pass
            self._conn = None
