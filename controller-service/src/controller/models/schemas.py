from pydantic import BaseModel, Field

from controller.models.ssh import SSHConfig


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
