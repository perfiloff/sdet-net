from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from controller.models.ssh import SSHConfig

SessionKind = Literal["control", "monitor"]


class DutHostRead(BaseModel):
    """DUT entry as stored under ``dut_devices`` in config (secrets are flags only)."""

    index: int = Field(..., ge=0)
    host: str
    port: int = Field(..., ge=1, le=65535)
    username: str
    has_password: bool = Field(
        default=False,
        description="Whether a password is configured (value is never returned)",
    )
    has_private_key: bool = Field(
        default=False,
        description="Whether a private_key is configured (value is never returned)",
    )


class DutHostListResponse(BaseModel):
    hosts: list[DutHostRead]
    config_path: str = Field(description="YAML file that was read")


class DutHostCreate(BaseModel):
    host: str = Field(..., min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(..., min_length=1)
    password: str | None = None
    private_key: str | None = None


class DutHostUpdate(BaseModel):
    host: str | None = Field(default=None, min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, min_length=1)
    password: str | None = Field(
        default=None,
        description="New password (write-only). Omit to leave unchanged unless clear_password is true.",
    )
    private_key: str | None = Field(
        default=None,
        description="New private key PEM/path content (write-only). Omit unless changing.",
    )
    clear_password: bool = Field(
        default=False,
        description="If true, remove stored password",
    )
    clear_private_key: bool = Field(
        default=False,
        description="If true, remove stored private_key",
    )


class DutHealthResponse(BaseModel):
    ssh_reachable: bool
    vtysh_ok: bool
    message: str = ""


class MonitorConfig(BaseModel):
    """How to collect logs on the device for ``kind=monitor`` sessions."""

    mode: Literal["terminal_monitor", "tail"] = Field(
        default="terminal_monitor",
        description="Run interactive vtysh and ``terminal monitor``, or ``tail -f`` on a file.",
    )
    tail_path: str | None = Field(
        default=None,
        description="File path on the device when mode is ``tail``.",
    )

    @model_validator(mode="after")
    def _tail_path_when_tail(self) -> MonitorConfig:
        if self.mode == "tail":
            if not (self.tail_path and self.tail_path.strip()):
                raise ValueError("tail_path is required when mode is tail")
        elif self.tail_path is not None and self.tail_path.strip():
            raise ValueError("tail_path is only used when mode is tail")
        return self


class VtyshSessionCreateRequest(BaseModel):
    """Optional DUT SSH override; defaults from service settings when omitted."""

    kind: SessionKind = Field(
        default="control",
        description="control: interactive vtysh (show/configure/shell); monitor: SSH log stream only.",
    )
    ssh: SSHConfig | None = None
    monitor: MonitorConfig | None = Field(
        default=None,
        description="Required when kind is monitor.",
    )

    @model_validator(mode="after")
    def _kind_monitor_consistency(self) -> VtyshSessionCreateRequest:
        if self.kind == "monitor":
            if self.monitor is None:
                raise ValueError("monitor is required when kind is monitor")
        elif self.monitor is not None:
            raise ValueError("monitor is only allowed when kind is monitor")
        return self


class VtyshSessionCreated(BaseModel):
    session_id: str


class VtyshSessionItem(BaseModel):
    session_id: str
    host: str
    port: int
    endpoint: str = Field(description="host:port for this session")
    kind: SessionKind = Field(description="control: vtysh CLI; monitor: device log stream over SSH")
    bootstrap: bool = False


class VtyshSessionListResponse(BaseModel):
    sessions: list[VtyshSessionItem]


class VtyshSessionShowRequest(BaseModel):
    command: str = Field(..., min_length=1)


class VtyshSessionShowResponse(BaseModel):
    output: str


class VtyshSessionConfigureRequest(BaseModel):
    commands: list[str] = Field(..., min_length=1)
