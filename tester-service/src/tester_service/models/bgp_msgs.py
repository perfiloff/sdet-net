from collections import defaultdict
import struct
from pydantic import BaseModel, ConfigDict, Field
from typing import ClassVar, List, Optional, Dict, Any
from datetime import datetime

from scapy.packet import Raw
from tester_service.core.settings import bgp_settings
from scapy.contrib.bgp import BGPOpen, BGPUpdate, BGPNotification, BGPHeader, BGPOptParam
from tester_service.models.bgp_settings import BGPConfig

class BGPMessage(BaseModel):
    """BGP message information"""
    bgp_type: ClassVar[int | None] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)
    timestamp: datetime
    direction: str  # "sent" or "received"
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def header(self) -> BGPHeader:
        return BGPHeader(type=self.bgp_type)

    @property
    def message(self):
        return self.header/self.payload

    def show(self, *args, **kwargs):
        try:
            return self.message.show(*args, **kwargs)
        except Exception:
            return f"BGPMessage(type={self.bgp_type}, direction={self.direction})"

    def to_bytes(self) -> bytes:
        return bytes(self.message)
        


class BGPOpenMessage(BGPMessage):
    """
    BGP OPEN message format
    Marker (16 bytes) + Length (2 bytes) + Type (1 byte) + Version (1 byte) + AS (2 bytes)
    + Hold Time (2 bytes) + BGP Identifier (4 bytes) + Optional Parameters Length (1 byte)
    """
    bgp_type: ClassVar[int] = 1

    version: int
    my_as: int
    hold_time: int
    bgp_id: str
    opt_params: list[BGPOptParam] = Field(default_factory=list)

    @property
    def payload(self) -> BGPOpen:
        return BGPOpen(
            version=self.version,
            my_as=self.my_as,
            hold_time=self.hold_time,
            bgp_id=self.bgp_id,
            opt_params=self.opt_params
            )


class BGPKeepaliveMessage(BGPMessage):
    """BGP KEEPALIVE message information"""
    bgp_type: ClassVar[int] = 4

    @property
    def payload(self) -> bytes:
        return Raw(b"")


class BGPUpdateMessage(BGPMessage):
    """BGP UPDATE message information"""
    bgp_type: ClassVar[int] = 2

    withdrawn_routes: list = Field(default_factory=list)
    path_attr: list = Field(default_factory=list)
    nlri: list = Field(default_factory=list)

    @property
    def payload(self):
        return BGPUpdate(
            withdrawn_routes=self.withdrawn_routes,
            path_attr=self.path_attr,
            nlri=self.nlri,
        )


class BGPNotificationMessage(BGPMessage):
    """BGP NOTIFICATION message information"""
    bgp_type: ClassVar[int] = 3

    error_code: int
    error_subcode: int
    data: str
    
    @property
    def payload(self) -> bytes:
        return BGPNotification(
            error_code=self.error_code,
            error_subcode=self.error_subcode,
            data=self.data,
        )


class BGPUnknownMessage(BGPMessage):
    """BGP UNKNOWN message information"""

    raw_data: bytes

    


class BGPStats(BaseModel):
    """BGP statistics"""

    total_messages_sent: int
    total_messages_received: int
    open_messages: int
    keepalive_messages: int
    update_messages: int
    notification_messages: int
    connection_uptime: Optional[str] = None
    

def scapy_decode_bgp(data):
    """Decode raw bytes into a Scapy BGP object."""
    try:
        pkt = BGPHeader(data)
        return pkt
    except Exception as e:
        raise ValueError(f"Failed to decode BGP with scapy: {e}")

def build_model_from_scapy(pkt, direction: str):
    msg_type = pkt.type

    if msg_type == 1:   # OPEN
        bgp = pkt[BGPOpen]
        return BGPOpenMessage(
            timestamp=datetime.now(),
            direction=direction,
            version=bgp.version,
            my_as=bgp.my_as,
            hold_time=bgp.hold_time,
            bgp_id=bgp.bgp_id,
            opt_params=list[BGPOptParam](bgp.opt_params)
        )

    elif msg_type == 4:  # KEEPALIVE
        return BGPKeepaliveMessage(
            timestamp=datetime.now(),
            direction=direction,
        )

    elif msg_type == 2:  # UPDATE
        bgp = pkt[BGPUpdate]
        return BGPUpdateMessage(
            timestamp=datetime.now(),
            direction=direction,
            withdrawn_routes=list(bgp.withdrawn_routes or []),
            path_attr=list(bgp.path_attr or []),
            nlri=list(bgp.nlri or []),
        )

    elif msg_type == 3:  # NOTIFICATION
        bgp = pkt[BGPNotification]
        return BGPNotificationMessage(
            timestamp=datetime.now(),
            direction=direction,
            error_code=bgp.error_code,
            error_subcode=bgp.error_subcode,
            data=bgp.data
        )

    else:
        return BGPUnknownMessage(
            timestamp=datetime.now(),
            direction=direction,
            raw_data=bytes(pkt),
            details="Unknown BGP message type"
        )