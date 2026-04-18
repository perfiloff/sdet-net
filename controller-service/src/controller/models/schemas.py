from pydantic import BaseModel, Field

from controller.models.ssh import SSHConfig


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


class VtyshSessionCreateRequest(BaseModel):
    """Optional DUT SSH override; defaults from service settings when omitted."""

    ssh: SSHConfig | None = None


class VtyshSessionCreated(BaseModel):
    session_id: str


class VtyshSessionItem(BaseModel):
    session_id: str
    host: str
    port: int
    endpoint: str = Field(description="host:port for this session")
    bootstrap: bool = False


class VtyshSessionListResponse(BaseModel):
    sessions: list[VtyshSessionItem]


class VtyshSessionShowRequest(BaseModel):
    command: str = Field(..., min_length=1)


class VtyshSessionShowResponse(BaseModel):
    output: str


class VtyshSessionConfigureRequest(BaseModel):
    commands: list[str] = Field(..., min_length=1)
