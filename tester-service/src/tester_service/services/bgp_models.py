from pydantic import BaseModel
from typing import Optional, Dict, Any
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


class BGPMessage(BaseModel):
    """BGP message information"""

    timestamp: datetime
    direction: str  # "sent" or "received"
    message_type: str
    details: Dict[str, Any]

    def __str__(self):
        return f"BGPMessage(timestamp={self.timestamp}, direction={self.direction}, message_type={self.message_type}, details={self.details})"


class BGPStats(BaseModel):
    """BGP statistics"""

    total_messages_sent: int
    total_messages_received: int
    open_messages: int
    keepalive_messages: int
    update_messages: int
    notification_messages: int
    connection_uptime: Optional[str] = None
