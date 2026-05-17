"""Per-device session handle for a test run."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from controller.models.schemas import MonitorConfig
from controller.models.ssh import SSHConfig
from controller.services.ssh.device_monitor import DeviceMonitorSession
from controller.services.ssh.frr import FrrVtyshSession

if TYPE_CHECKING:
    from controller.services.test_runner.monitor_capture import MonitorLogCapture


@dataclass
class DeviceHandle:
    alias: str
    ssh: SSHConfig
    session_kind: str
    monitor_config: MonitorConfig | None = None
    control: FrrVtyshSession | None = None
    monitor: DeviceMonitorSession | None = None
    capture: MonitorLogCapture | None = None
    default_configure_applied: bool = False
