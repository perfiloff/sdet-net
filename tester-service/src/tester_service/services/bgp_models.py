from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from tester_service.core.settings import bgp_settings


class BGPConfig(BaseModel):
    """BGP connection configuration"""

    as_number: int = bgp_settings.as_number
    router_id: str = bgp_settings.router_id
    hold_time: int = bgp_settings.hold_time
    bgp_version: int = bgp_settings.bgp_version
    remote_host: str = bgp_settings.remote_host
    remote_port: int = bgp_settings.remote_port


class BGPConnectionStatus(BaseModel):
    """BGP connection status"""

    connected: bool
    config: BGPConfig
    last_activity: Optional[datetime] = None
    messages_sent: int = 0
    messages_received: int = 0
    connection_start_time: Optional[datetime] = None


class BGPCapability(BaseModel):
    """BGP capability"""

    code: int
    length: int
    value: bytes

    def human_readable(self) -> str:
        code_map = {
            1: self._parse_multiprotocol,
            2: lambda: "Route Refresh Capability",
            3: lambda: "Outbound Route Filtering",
            4: lambda: "Multiple Routes to a Destination (deprecated)",
            5: lambda: "Extended Next Hop Encoding",
            64: self._parse_graceful_restart,
            65: self._parse_four_octet_asn,
            67: "Add-path Capability",
            70: "Enhanced Route Refresh",
        }
        handler = code_map.get(self.code)
        if handler is None:
            return f"Unknown capability (code={self.code}, value={self.value.hex()})"
        if callable(handler):
            return handler()
        return handler

    def _parse_multiprotocol(self) -> str:
        """Capability 1 — Multiprotocol Extensions"""
        if self.length < 4:
            return "Multiprotocol Extensions (invalid length)"
        afi = int.from_bytes(self.value[0:2], "big")
        safi = self.value[3]
        afi_name = {
            1: "IPv4",
            2: "IPv6",
            25: "L2VPN",
        }.get(afi, f"Unknown AFI {afi}")
        return f"Multiprotocol Extensions ({afi_name}, SAFI={safi})"

    def _parse_four_octet_asn(self) -> str:
        """Capability 65 — Four-octet ASN"""
        if self.length != 4:
            return "Four-octet ASN (invalid length)"
        asn = int.from_bytes(self.value, "big")
        return f"Four-octet ASN (AS={asn})"

    def _parse_graceful_restart(self) -> str:
        """Capability 64 — Graceful Restart"""
        if self.length < 2:
            return "Graceful Restart (invalid length)"
        restart_time = (self.value[0] & 0x0F) * 2
        return f"Graceful Restart (Restart Time={restart_time}s)"

    def __str__(self):
        return self.human_readable()


class BGPMessage(BaseModel):
    """BGP message information"""

    length: int
    timestamp: datetime
    direction: str  # "sent" or "received"
    message_type: str
    details: Dict[str, Any] = Field(default_factory=dict)

    def __str__(self):
        return (
            f"BGPMessage("
            f"timestamp={self.timestamp}, "
            f"direction={self.direction}, "
            f"type={self.message_type}, "
            f"details={self.human_details()})"
        )

    def human_details(self) -> Dict[str, Any]:
        return self.details


class BGPOpenMessage(BGPMessage):
    """BGP OPEN message information"""

    version: int
    as_number: int
    hold_time: int
    router_id: str
    capabilities: List[BGPCapability] = []

    def human_details(self) -> Dict[str, Any]:
        caps_readable = [cap.human_readable() for cap in self.capabilities]
        return {
            **self.details,
            "version": self.version,
            "as_number": self.as_number,
            "hold_time": self.hold_time,
            "router_id": self.router_id,
            "capabilities": caps_readable,
        }


class BGPKeepaliveMessage(BGPMessage):
    """BGP KEEPALIVE message"""

    def human_details(self) -> Dict[str, Any]:
        return {"info": "KEEPALIVE — no data fields"}


class BGPUpdateMessage(BGPMessage):
    """BGP UPDATE message"""

    withdrawn_routes: List[str] = []
    path_attributes: Dict[str, Any] = {}
    nlri: List[str] = []

    def human_details(self) -> Dict[str, Any]:
        return {
            "withdrawn_routes": self.withdrawn_routes,
            "path_attributes": self.path_attributes,
            "nlri": self.nlri,
        }


class BGPNotificationMessage(BGPMessage):
    """BGP NOTIFICATION message"""

    error_code: int
    error_subcode: int
    data: bytes = b""

    def human_details(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "error_subcode": self.error_subcode,
            "data": self.data.hex(),
        }


class BGPUnknownMessage(BGPMessage):
    """BGP UNKNOWN message"""

    raw_data: bytes

    def human_details(self) -> Dict[str, Any]:
        return {"raw_data": self.raw_data.hex()}


class BGPStats(BaseModel):
    """BGP statistics"""

    total_messages_sent: int
    total_messages_received: int
    open_messages: int
    keepalive_messages: int
    update_messages: int
    notification_messages: int
    connection_uptime: Optional[str] = None
