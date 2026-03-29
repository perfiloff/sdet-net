from pydantic import BaseModel, ConfigDict, Field
from tester_service.models.bgp_capabilities import BGPCapabilityModel


class BGPConfigUpdate(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    as_number: int | None = None
    router_id: str | None = None
    hold_time: int | None = None
    bgp_version: int | None = None
    remote_host: str | None = None
    remote_port: int | None = None
    capabilities: list[BGPCapabilityModel] | None = None


class BGPRouteInjection(BaseModel):
    """Model for injecting BGP routes"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    prefix: str
    next_hop: str | None = None
    as_path: list[int] = Field(default_factory=list)
    origin: int = 0  # 0=IGP, 1=EGP, 2=incomplete
    local_pref: int | None = None
    med: int | None = None
