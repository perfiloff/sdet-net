from enum import IntEnum
from pydantic import BaseModel


class BGPCapabilityCode(IntEnum):
    MP_BGP = 1
    ROUTE_REFRESH = 2
    ORF = 3
    GRACEFUL_RESTART = 64
    FOUR_OCTET_AS = 65


class BGPCapabilityModel(BaseModel):
    code: BGPCapabilityCode
    value: dict | None = None
