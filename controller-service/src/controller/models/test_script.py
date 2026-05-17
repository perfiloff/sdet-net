"""Test script schema and run result models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from controller.models.schemas import MonitorConfig

ConfigType = Literal["configure", "send"]
RunStatus = Literal["pending", "running", "passed", "failed", "cancelled"]
ActionStatus = Literal["ok", "failed", "skipped"]


class ConfigurationFile(BaseModel):
    """Named command list referenced from script steps (e.g. ``172.20.0.3.yaml``)."""

    type: ConfigType = "configure"
    commands: list[str] = Field(..., min_length=1)

    @field_validator("commands", mode="before")
    @classmethod
    def _normalize_commands(cls, v: object) -> list[str]:
        if isinstance(v, str):
            lines = v.splitlines()
        else:
            lines = list(v)  # type: ignore[arg-type]
        out = [str(line).strip() for line in lines if str(line).strip()]
        if not out:
            raise ValueError("commands must contain at least one non-empty line")
        return out


class DeviceSpec(BaseModel):
    """SSH target and session type for a logical device alias."""

    ref: str | None = Field(default=None, description="Match ``dut_devices`` entry by host")
    host: str | None = None
    port: int = 22
    username: str | None = None
    password: str | None = None
    private_key: str | None = None
    session: Literal["control", "monitor"] = "control"
    monitor: MonitorConfig | None = None
    default_configure: str | None = Field(
        default=None,
        description="Config filename applied once after first connect",
    )

    @model_validator(mode="after")
    def _monitor_when_needed(self) -> DeviceSpec:
        if self.session == "monitor" and self.monitor is None:
            self.monitor = MonitorConfig()
        if self.session == "control" and self.monitor is not None:
            raise ValueError("monitor block is only allowed when session is monitor")
        if not self.ref and not self.host:
            raise ValueError("device must specify ref or host")
        if self.ref and self.host:
            raise ValueError("use either ref or host, not both")
        return self


class SleepAction(BaseModel):
    sleep: float = Field(..., gt=0)


class WaitUntilAction(BaseModel):
    wait_until: dict[str, Any]

    @property
    def device(self) -> str:
        return str(self.wait_until["device"])

    @property
    def pattern(self) -> str:
        return str(self.wait_until["pattern"])

    @property
    def timeout(self) -> float:
        return float(self.wait_until.get("timeout", 30))


class ReconnectAction(BaseModel):
    reconnect: dict[str, Any]

    @property
    def device(self) -> str:
        return str(self.reconnect["device"])

    @property
    def timeout(self) -> float:
        return float(self.reconnect.get("timeout", 60))

    @property
    def force(self) -> bool:
        return bool(self.reconnect.get("force", False))


class DeviceConfigureAction(BaseModel):
    device: str
    configure: str = Field(..., description="Configuration filename")


class DeviceSendAction(BaseModel):
    device: str
    send: str = Field(..., description="Configuration filename (type send)")


class DeviceShowAction(BaseModel):
    device: str
    show: str


class ScriptStep(BaseModel):
    """One step: parallel connect then sequential actions."""

    name: str | None = None
    parallel_connect: list[str] = Field(..., min_length=1)
    actions: list[dict[str, Any]] = Field(default_factory=list)


class TestScript(BaseModel):
    name: str = "test"
    config_dir: str | None = None
    output_dir: str | None = None
    continue_on_error: bool = False
    configurations: dict[str, ConfigurationFile] = Field(default_factory=dict)
    devices: dict[str, DeviceSpec]
    steps: list[dict[str, Any]]

    @field_validator("configurations", mode="before")
    @classmethod
    def _coerce_configurations(cls, v: object) -> dict[str, ConfigurationFile]:
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("configurations must be a mapping")
        out: dict[str, ConfigurationFile] = {}
        for key, raw in v.items():
            name = _normalize_config_name(str(key))
            if isinstance(raw, ConfigurationFile):
                out[name] = raw
            else:
                out[name] = ConfigurationFile.model_validate(raw)
        return out


def _normalize_config_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise ValueError("configuration filename must not be empty")
    if not (name.endswith(".yaml") or name.endswith(".yml")):
        name = f"{name}.yaml"
    return name


class ActionResult(BaseModel):
    type: str
    device: str | None = None
    config_file: str | None = None
    commands: list[str] = Field(default_factory=list)
    output: str = ""
    status: ActionStatus = "ok"
    error: str | None = None
    duration_ms: int = 0


class StepResult(BaseModel):
    name: str | None = None
    status: ActionStatus = "ok"
    actions: list[ActionResult] = Field(default_factory=list)
    error: str | None = None


class TestRunResult(BaseModel):
    run_id: str
    script_name: str
    status: RunStatus = "pending"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    current_step: str | None = None
    current_action: str | None = None
    steps: list[StepResult] = Field(default_factory=list)
    error: str | None = None
    output_dir: str = ""


class TestRunListItem(BaseModel):
    run_id: str
    script_name: str
    status: RunStatus = "pending"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    current_step: str | None = None
    current_action: str | None = None


class TestRunListResponse(BaseModel):
    runs: list[TestRunListItem] = Field(default_factory=list)
