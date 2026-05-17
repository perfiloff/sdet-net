"""Dedicated SSH session for streaming device logs (vtysh ``terminal monitor`` or ``tail -f``)."""

from __future__ import annotations

import asyncio
import logging
import shlex

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
        self._runner_capture = False

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
            for cmd in self._monitor.pre_commands:
                await self._write_line(cmd)
                await self._drain_initial()
            await self._write_line(self._monitor.monitor_command)
        else:
            path = (self._monitor.tail_path or "").strip()
            if not path:
                raise ValueError("tail_path is required for tail mode")
            # Use a single remote command string (quoted argv). Some AsyncSSH builds
            # mis-encode list argv and raise TypeError in packet.String when concat'ing.
            remote_cmd = "exec " + " ".join(
                shlex.quote(p) for p in ("tail", "-n", "200", "-f", path)
            )
            self._proc_cm = self._conn.create_process(
                remote_cmd,
                stderr=STDOUT,
                encoding="utf-8",
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
        if self._streaming or self._runner_capture:
            return False
        self._streaming = True
        return True

    def release_stream(self) -> None:
        self._streaming = False

    def try_acquire_runner(self) -> bool:
        if self._streaming or self._runner_capture:
            return False
        self._runner_capture = True
        return True

    def release_runner(self) -> None:
        self._runner_capture = False

    @property
    def runner_capture_active(self) -> bool:
        return self._runner_capture

    def is_alive(self) -> bool:
        if self._conn is None or self._proc is None:
            return False
        if self._proc.returncode is not None:
            return False
        return True

    async def send_lines(self, lines: list[str], *, idle: float = 0.35) -> None:
        for line in lines:
            await self._write_line(line)
            await self._drain_initial()
        if idle > 0:
            await asyncio.sleep(idle)

    async def logout(self) -> None:
        self._streaming = False
        self._runner_capture = False
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
