from enum import Enum
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from copy import deepcopy

from tester_service.core.settings import bgp_settings
from tester_service.models.bgp_capabilities import BGPCapabilityModel


class BGPFSMState(str, Enum):
    """RFC 4271 BGP Finite State Machine states."""

    IDLE = "Idle"
    CONNECT = "Connect"
    ACTIVE = "Active"
    OPENSENT = "OpenSent"
    OPENCONFIRM = "OpenConfirm"
    ESTABLISHED = "Established"


class BGPConfig(BaseModel):
    """BGP connection configuration"""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    as_number: int = bgp_settings.as_number
    router_id: str = bgp_settings.router_id
    hold_time: int = bgp_settings.hold_time
    bgp_version: int = bgp_settings.bgp_version
    remote_host: str = bgp_settings.remote_host
    remote_port: int = bgp_settings.remote_port
    capabilities: list[BGPCapabilityModel] = Field(default_factory=lambda: deepcopy(bgp_settings.capabilities))


class BGPConnectionStatus(BaseModel):
    """BGP connection status"""


    connected: bool = False
    state: BGPFSMState = BGPFSMState.IDLE
    config: BGPConfig
    last_activity: Optional[datetime] = None
    messages_sent: int = 0
    messages_received: int = 0
    connection_start_time: Optional[datetime] = None


class BGPStats(BaseModel):
    """BGP statistics"""

    total_messages_sent: int
    total_messages_received: int
    open_messages: int
    keepalive_messages: int
    update_messages: int
    notification_messages: int
    connection_uptime: Optional[str] = None