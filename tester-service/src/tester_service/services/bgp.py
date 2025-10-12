import asyncio
from functools import lru_cache
import struct
from datetime import datetime
from typing import Optional, Dict, Any, List
from tester_service.services.bgp_models import (
    BGPConfig,
    BGPConnectionStatus,
    BGPMessage, 
    BGPStats,
    BGPCapability,
    BGPOpenMessage,
    BGPKeepaliveMessage,
    BGPUpdateMessage,
    BGPNotificationMessage,
    BGPUnknownMessage,
)


class BGPManager:
    def __init__(self):
        self.connection_status = BGPConnectionStatus(connected=False, config=BGPConfig())
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connection_task: Optional[asyncio.Task] = None
        self.keepalive_task: Optional[asyncio.Task] = None
        self.message_log: List[BGPMessage] = []
        self.stats = BGPStats(
            total_messages_sent=0,
            total_messages_received=0,
            open_messages=0,
            keepalive_messages=0,
            update_messages=0,
            notification_messages=0,
        )
        print(f"BGPManager initialized with config: {self.connection_status.config}")

    def __str__(self):
        return self.connection_status.config.__str__()

    def ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP address to bytes"""
        return bytes(map(int, ip.split(".")))

    def build_open_message(self) -> bytes:
        """
        Build BGP OPEN message.
        BGP OPEN message format
        Marker (16 bytes) + Length (2 bytes) + Type (1 byte) + Version (1 byte) + AS (2 bytes)
        + Hold Time (2 bytes) + BGP Identifier (4 bytes) + Optional Parameters Length (1 byte)
        """
        marker = b"\xff" * 16
        msg_type = 1  # OPEN
        version = self.connection_status.config.bgp_version
        my_as = self.connection_status.config.as_number
        hold_time = self.connection_status.config.hold_time
        bgp_id = self.ip_to_bytes(self.connection_status.config.router_id)
        opt_len = 0

        payload = struct.pack("!BHH4sB", version, my_as, hold_time, bgp_id, opt_len)
        length = 19 + len(payload)
        header = marker + struct.pack("!HB", length, msg_type)

        return header + payload

    def build_keepalive_message(self) -> bytes:
        """Build BGP KEEPALIVE message"""
        marker = b"\xff" * 16
        length = 19
        msg_type = 4  # KEEPALIVE
        return marker + struct.pack("!HB", length, msg_type)

    def decode_open_message(self, data: bytes, direction: str) -> Dict[str, Any]:
        """Decode BGP OPEN message"""
        if len(data) < 29:
            raise ValueError("Too short for BGP OPEN")

        marker = data[:16]
        if marker != b"\xff" * 16:
            raise ValueError("Bad marker")

        length, msg_type = struct.unpack("!HB", data[16:19])
        if msg_type != 1:
            raise ValueError("Not an OPEN message")

        version, my_as, hold_time, bgp_id, opt_len = struct.unpack("!BHH4sB", data[19:29])
        bgp_id_str = ".".join(map(str, bgp_id))
        opts = data[29 : 29 + opt_len] if opt_len > 0 else b""
        if opts:
            capabilities = self.parse_optional_params(opt_bytes=opts)

        return BGPOpenMessage(
            timestamp=datetime.now(),
            direction=direction,
            length=length,
            message_type=msg_type,
            version=version,
            as_number=my_as,
            hold_time=hold_time,
            router_id=bgp_id_str,
            capabilities=capabilities if opts else None,
        )

    def decode_keepalive_message(self, data: bytes, direction) -> Dict[str, Any]:
        """Decode BGP KEEPALIVE message"""
        msg_dict = dict(
            length=len(data),
            timestamp=datetime.now(),
            direction=direction,
            message_type="KEEPALIVE",
            raw_data=data
            )
        
        if len(data) < 19:
            return BGPUnknownMessage(**msg_dict, details={"note": "Message too short for BGP"})
        
        marker, length, msg_type = struct.unpack("!16sHB", data[:19])

        if marker != b"\xff" * 16:
            return BGPUnknownMessage(**msg_dict, details={"note": "Invalid marker"})

        if length != 19:
            return BGPUnknownMessage(**msg_dict, details={"note": f"KEEPALIVE should be 19 bytes, got {length}"})


        if msg_type != 4:
            return BGPUnknownMessage(**msg_dict, details={"note": f"Not a KEEPALIVE (type {msg_type})"})
            
        return BGPKeepaliveMessage(
            length=len(data),
            timestamp=datetime.now(),
            direction=direction,
            message_type="KEEPALIVE",
            details={"info": "KEEPALIVE received"},
        )

    def decode_update_message(self, data: bytes, direction: str):
        return BGPUpdateMessage(
                length=len(data),
                timestamp=datetime.now(),
                direction=direction,
                message_type="UPDATE",
                details={"raw": data},
                withdrawn_routes=[],
                path_attributes={},
                nlri=[],
            )

    def parse_bgp_message(self, data: bytes, direction: str = "received") -> Dict[str, Any]:
        """Parse BGP message and return details"""
        unknown_message = dict(
            length=len(data),
            timestamp=datetime.now(),
            direction=direction,
            message_type="UNKNOWN",
            raw_data=data,
        )
        if direction == "sent":
            return {}
        if len(data) < 19:
            return BGPUnknownMessage(**unknown_message, details={"error": "Too short BGP message"})

        marker = data[:16]
        length, msg_type = struct.unpack("!HB", data[16:19])
        payload = data[19:length]

        if marker != b"\xff" * 16:
            return BGPUnknownMessage(**unknown_message, details={"error": "Invalid marker"})

        # message_info = {"length": length, "type": msg_type, "payload_hex": payload.hex()}

        if msg_type == 1:  # OPEN
            try:
                return self.decode_open_message(data, direction=direction)
            except Exception as e:
                print(unknown_message)
                return BGPUnknownMessage(**unknown_message, details={"error": f"Failed to decode OPEN: {e}"})

        elif msg_type == 4:  # KEEPALIVE
            try:
                return self.decode_keepalive_message(data, direction=direction)
            except Exception as e:
                print(unknown_message)
                return BGPUnknownMessage(**unknown_message, details=f"Failed to decode KEEPALIVE: {e}")

        elif msg_type == 2:  # UPDATE
            return self.decode_update_message(data, direction=direction)

        elif msg_type == 3:  # NOTIFICATION
            try:
                error_code, error_subcode = struct.unpack("!BB", payload[:2])
                data_field = payload[2:]
                return BGPNotificationMessage(
                    length=len(data),
                    timestamp=datetime.now(),
                    direction=direction,
                    message_type="NOTIFICATION",
                    details={},
                    error_code=error_code,
                    error_subcode=error_subcode,
                    data=data_field,
                )
            except Exception as e:
                return BGPUnknownMessage(**unknown_message, details=f"Failed to decode NOTIFICATION: {e}")

        else:
            return BGPUnknownMessage(**unknown_message, details=f"UNKNOWN_{msg_type}")


    def parse_optional_params(self, opt_bytes: bytes):
        i = 0
        capabilities = []
        while i < len(opt_bytes):
            if i + 2 > len(opt_bytes):
                print("[!] Truncated optional param header")
                break
            param_type, param_len = struct.unpack("!BB", opt_bytes[i:i+2])
            param_value = opt_bytes[i+2:i+2+param_len]
            i += 2 + param_len

            print(f"Optional Param: type={param_type}, length={param_len}")

            # Capability
            if param_type == 2:
                j = 0
                while j < len(param_value):
                    if j + 2 > len(param_value):
                        print("[!] Truncated capability header")
                        break
                    cap_code, cap_len = struct.unpack("!BB", param_value[j:j+2])
                    cap_value = param_value[j+2:j+2+cap_len]
                    j += 2 + cap_len
                    cap = BGPCapability(
                        code=cap_code,
                        length=cap_len,
                        value=cap_value,
                    )
                    capabilities.append(cap)
        return capabilities


    def log_message(self, msg):
        """Log BGP message"""
        if msg == {}:
            return

        self.message_log.append(msg)
        print(f"Logged message: {msg}")
        # Keep only last 1000 messages
        if len(self.message_log) > 1000:
            self.message_log = self.message_log[-1000:]

        # Update stats
        if msg.direction == "sent":
            self.stats.total_messages_sent += 1
        else:
            self.stats.total_messages_received += 1

        if msg.message_type == "OPEN":
            self.stats.open_messages += 1
        elif msg.message_type == "KEEPALIVE":
            self.stats.keepalive_messages += 1
        elif msg.message_type == "UPDATE":
            self.stats.update_messages += 1
        elif msg.message_type == "NOTIFICATION":
            self.stats.notification_messages += 1

    async def send_keepalives(self):
        """Send periodic keepalive messages"""
        interval = self.connection_status.config.hold_time // 3
        while self.connection_status.connected and self.writer:
            try:
                await asyncio.sleep(interval)
                if self.writer and not self.writer.is_closing():
                    msg = self.build_keepalive_message()
                    self.writer.write(msg)
                    await self.writer.drain()
                    sent = self.parse_bgp_message(msg, direction="sent")
                    self.log_message(sent)
                    # self.log_message("sent", "KEEPALIVE", {"message": "Periodic keepalive sent"})
            except Exception as e:
                print(f"Error sending keepalive: {e}")
                break

    async def start_connection(self):
        """Start BGP connection"""
        if self.connection_status.connected:
            raise Exception("BGP connection already active")

        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.connection_status.config.remote_host, self.connection_status.config.remote_port
            )

            self.connection_status.connected = True
            self.connection_status.connection_start_time = datetime.now()
            self.connection_status.last_activity = datetime.now()

            # Send OPEN message
            open_msg = self.build_open_message()
            self.writer.write(open_msg)
            await self.writer.drain()
            sent = self.parse_bgp_message(open_msg, direction="sent")
            self.log_message(sent)

            # Start keepalive task
            self.keepalive_task = asyncio.create_task(self.send_keepalives())

            # Start message reading task
            self.connection_task = asyncio.create_task(self.read_messages())

            return {"status": "connected", "message": "BGP connection established"}

        except Exception as e:
            self.connection_status.connected = False
            raise Exception(f"Failed to establish BGP connection: {e}")

    async def read_messages(self):
        """Read and process BGP messages"""
        try:
            while self.connection_status.connected and self.reader:
                data = await self.reader.read(4096)
                if not data:
                    print(f"{datetime.now()}Connection closed")
                    break

                self.connection_status.last_activity = datetime.now()
                self.connection_status.messages_received += 1

                msg = self.parse_bgp_message(data, direction="received")
                self.log_message(msg)

        except Exception as e:
            print(f"Error reading messages: {e}")
        finally:
            await self.stop_connection()

    async def stop_connection(self):
        """Stop BGP connection"""
        self.connection_status.connected = False

        if self.keepalive_task:
            self.keepalive_task.cancel()
            self.keepalive_task = None

        if self.connection_task:
            self.connection_task.cancel()
            self.connection_task = None

        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self.writer = None

        self.reader = None

    def update_config(self, new_config: BGPConfig):
        """Update BGP configuration"""
        if self.connection_status.connected:
            raise Exception("Cannot update config while connected. Stop connection first.")

        self.connection_status.config = new_config
        return {"status": "updated", "config": new_config.dict()}

    def get_connection_status(self) -> BGPConnectionStatus:
        """Get current connection status"""
        if self.connection_status.connected and self.connection_status.connection_start_time:
            uptime = datetime.now() - self.connection_status.connection_start_time
            self.connection_status.connection_start_time = datetime.now() - uptime

        return self.connection_status

    def get_stats(self) -> BGPStats:
        """Get BGP statistics"""
        if self.connection_status.connected and self.connection_status.connection_start_time:
            uptime = datetime.now() - self.connection_status.connection_start_time
            self.stats.connection_uptime = str(uptime)

        return self.stats

    def get_message_log(self, limit: int = 100) -> List[BGPMessage]:
        """Get recent message log"""
        return self.message_log[-limit:] if self.message_log else []


@lru_cache()
def get_bgp_manager() -> BGPManager:
    return BGPManager()
