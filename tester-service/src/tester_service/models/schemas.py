from pydantic import BaseModel, ConfigDict
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
