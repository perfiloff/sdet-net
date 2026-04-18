"""FRR DUT access: batch vtysh and interactive PTY sessions."""

from __future__ import annotations

import asyncio
import shlex
import asyncssh
from asyncssh import STDOUT
from asyncssh.process import SSHClientProcess

from controller.core.settings import Settings
from controller.models.ssh import SSHConfig
from controller.services.router_mgr import RouterClient


def connect_kwargs(
    cfg: SSHConfig,
    known_hosts_path: str | None,
    accept_unknown_host: bool,
) -> dict:
    opts: dict = {
        "host": cfg.host,
        "port": cfg.port,
        "username": cfg.username,
    }
    if known_hosts_path:
        opts["known_hosts"] = known_hosts_path
    elif accept_unknown_host:
        opts["known_hosts"] = None
    if cfg.password:
        opts["password"] = cfg.password
    if cfg.private_key:
        opts["client_keys"] = [cfg.private_key]
    return opts


class FrrVtyshSshBackend:
    """Stateless batch ``vtysh -c`` invocations (health checks, simple exec)."""

    def __init__(
        self,
        settings: Settings,
        ssh: SSHConfig | None = None,
    ) -> None:
        self._settings = settings
        self._ssh = ssh

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def ssh_override(self) -> SSHConfig | None:
        return self._ssh

    def effective_ssh_config(self) -> SSHConfig:
        if self._ssh:
            return self._ssh
        s = self._settings
        return SSHConfig(
            host=s.dut_ssh_host,
            port=s.dut_ssh_port,
            username=s.dut_ssh_username,
            password=s.dut_ssh_password,
        )

    async def run_commands(
        self,
        commands: list[str],
        *,
        timeout: float | None = None,
        existing_conn: asyncssh.SSHClientConnection | None = None,
    ) -> tuple[str, int]:
        s = self._settings
        t = timeout if timeout is not None else s.dut_command_timeout
        cfg = self.effective_ssh_config()

        argv: list[str] = ["vtysh"]
        for c in commands:
            argv.extend(["-c", c])
        remote_cmd = " ".join(shlex.quote(a) for a in argv)

        close_after = False
        conn = existing_conn
        if conn is None:
            kw = connect_kwargs(
                cfg,
                s.dut_ssh_known_hosts,
                accept_unknown_host=not s.dut_ssh_known_hosts,
            )
            conn = await asyncssh.connect(**kw)
            close_after = True

        try:
            result = await conn.run(remote_cmd, check=False, timeout=t)
            out = (result.stdout or "") + (result.stderr or "")
            code = result.exit_status if result.exit_status is not None else -1
            return out, int(code)
        finally:
            if close_after and conn is not None:
                conn.close()
                await conn.wait_closed()


class FrrVtyshSession(RouterClient):
    """Long-lived SSH + interactive vtysh PTY (configure, ``terminal monitor``, raw shell)."""

    def __init__(
        self,
        settings: Settings,
        ssh: SSHConfig | None = None,
    ) -> None:
        self._settings = settings
        self._ssh = ssh
        self._conn: asyncssh.SSHClientConnection | None = None
        self._proc: SSHClientProcess | None = None
        self._proc_cm: object | None = None
        self._io_lock = asyncio.Lock()
        self._ws_active = False

    def _backend(self) -> FrrVtyshSshBackend:
        return FrrVtyshSshBackend(self._settings, self._ssh)

    async def login(self) -> None:
        if self._conn is not None and self._proc is not None:
            return
        s = self._settings
        cfg = self._backend().effective_ssh_config()
        kw = connect_kwargs(
            cfg,
            s.dut_ssh_known_hosts,
            accept_unknown_host=not s.dut_ssh_known_hosts,
        )
        self._conn = await asyncssh.connect(**kw)
        assert self._conn is not None
        self._proc_cm = self._conn.create_process(
            "vtysh",
            term_type="xterm",
            stderr=STDOUT,
            encoding="utf-8",
        )
        self._proc = await self._proc_cm.__aenter__()
        await self._drain_banner()

    async def _drain_banner(self) -> None:
        await self._read_until_idle(max_total=5.0, idle=0.2)

    async def logout(self) -> None:
        self._ws_active = False
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

    async def get_shell(self) -> SSHClientProcess:
        if self._proc is None:
            raise RuntimeError("vtysh session not started; call login() first")
        return self._proc

    def attach_shell_websocket(self) -> None:
        """Mark session as owned by the shell WebSocket (REST show/configure blocked)."""
        self._ws_active = True

    def detach_shell_websocket(self) -> None:
        self._ws_active = False

    async def show(self, command: str) -> str:
        if self._ws_active:
            msg = "Close the shell WebSocket before using show on this session"
            raise RuntimeError(msg)
        async with self._io_lock:
            await self._write_line(command)
            return await self._read_until_idle()

    async def configure(self, commands: list[str]) -> str:
        if self._ws_active:
            msg = "Close the shell WebSocket before using configure on this session"
            raise RuntimeError(msg)
        if not commands:
            return ""
        async with self._io_lock:
            parts: list[str] = []
            await self._write_line("configure terminal")
            parts.append(await self._read_until_idle())
            for line in commands:
                await self._write_line(line)
                parts.append(await self._read_until_idle())
            await self._write_line("end")
            parts.append(await self._read_until_idle())
            return "".join(parts)

    async def _write_line(self, line: str) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise RuntimeError("vtysh process not available")
        raw = line if line.endswith("\n") else line + "\n"
        proc.stdin.write(raw)
        await proc.stdin.drain()

    async def _read_until_idle(self, max_total: float = 120.0, idle: float = 0.35) -> str:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return ""
        buf: list[str] = []
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max_total
        while loop.time() < deadline:
            try:
                chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=idle)
            except asyncio.TimeoutError:
                if buf:
                    break
                continue
            if not chunk:
                break
            buf.append(chunk if isinstance(chunk, str) else chunk.decode("utf-8", errors="replace"))
        return "".join(buf)


# Backward-compatible alias for code expecting the old name
FrrVtyshSshClient = FrrVtyshSession
