from pydantic import BaseModel


class SSHConfig(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str | None = None
    private_key: str | None = None