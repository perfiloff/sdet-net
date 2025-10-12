from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    project_name: str = Field("movies", alias="PROJECT_NAME")
    debug: bool = Field(False, alias="DEBUG")


class BGP_Settings(BaseSettings):
    as_number: int = Field(65001, alias="AS_NUMBER")
    router_id: str = Field("2.2.2.2", alias="ROUTER_ID")
    hold_time: int = Field(180, alias="HOLD_TIME")
    bgp_version: int = Field(4, alias="BGP_VERSION")
    remote_host: str = Field("frr", alias="REMOTE_HOST")
    remote_port: int = Field(179, alias="REMOTE_PORT")

    def __str__(self):
        return f"BGP_Settings(as_number={self.as_number}, router_id={self.router_id}, hold_time={self.hold_time}, bgp_version={self.bgp_version}, remote_host={self.remote_host}, remote_port={self.remote_port})"


settings = Settings()
bgp_settings = BGP_Settings()
