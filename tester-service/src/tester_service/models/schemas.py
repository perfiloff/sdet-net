from datetime import datetime
from typing import List
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator
from scapy.base_classes import Net
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



class BGPRoute(BaseModel):
    """Model for BGP routes in the routing table"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    prefix: Net = Field(..., description="BGP prefix")
    next_hop: Net = Field(..., description="BGP next hop")
    as_path: list[int] = Field(default_factory=list, description="BGP AS path")
    origin: int = 0  # 0=IGP, 1=EGP, 2=incomplete
    local_pref: int | None = None
    med: int | None = None
    route_type: str  # "advertised" or "learned"
    timestamp: datetime
    source: str | None = None  # For learned routes, the source neighbor IP

    @field_validator("prefix", "next_hop", mode="before")
    def parse_net(cls, v):
        if isinstance(v, Net):
            return v
        return Net(v)

    @field_serializer("prefix", "next_hop")
    def serialize_net(self, v):
        value = f"{v}/{v.mask}" if v.mask != 32  else str(v)
        return value


class BGPRouteInjectionBatch(BaseModel):
    """Model for injecting multiple BGP routes in a single request"""
    routes: list[BGPRouteInjection] = Field(..., description="List of routes to inject")


class BGPWithdrawRequest(BaseModel):
    """Model for withdrawing multiple BGP routes"""

    prefixes: List[str] = Field(..., description="List of prefixes to withdraw, e.g., ['192.168.1.0/24', '10.0.0.0/8']")
