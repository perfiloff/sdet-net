"""SSH access to FRR and vtysh command execution."""

from __future__ import annotations

import asyncssh

from controller.core.settings import Settings, settings as default_settings
from controller.models.ssh import SSHConfig
from controller.services.ssh.frr import FrrVtyshSshBackend, FrrVtyshSshClient, FrrVtyshSession

# Re-export for callers that imported the old module path
__all__ = [
    "FrrVtyshSshClient",
    "FrrVtyshSession",
    "run_vtysh_commands",
    "check_dut_health",
]


async def run_vtysh_commands(
    commands: list[str],
    *,
    settings: Settings | None = None,
    ssh: SSHConfig | None = None,
    timeout: float | None = None,
    existing_conn: asyncssh.SSHClientConnection | None = None,
) -> tuple[str, int]:
    """Run one vtysh invocation with multiple -c clauses; return stdout and exit status."""
    s = settings or default_settings
    backend = FrrVtyshSshBackend(s, ssh)
    return await backend.run_commands(commands, timeout=timeout, existing_conn=existing_conn)


async def check_dut_health(
    settings: Settings | None = None,
    *,
    timeout: float | None = None,
) -> tuple[bool, bool, str]:
    """Return (ssh_reachable, vtysh_ok, message)."""
    s = settings or default_settings
    t = timeout if timeout is not None else min(s.dut_command_timeout, 15.0)
    try:
        out, code = await run_vtysh_commands(
            ["show version"],
            settings=s,
            ssh=s.primary_dut_ssh,
            timeout=t,
        )
        vtysh_ok = code == 0 and (
            "frr" in out.lower() or "version" in out.lower() or "FRRouting" in out
        )
        return True, vtysh_ok, (out[:2000] if out else "")
    except (OSError, asyncssh.Error) as exc:
        return False, False, str(exc)
