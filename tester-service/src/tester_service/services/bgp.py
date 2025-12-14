import asyncio
from functools import lru_cache
import struct
from datetime import datetime
from typing import Optional, Dict, Any, List
from tester_service.models.bgp_msgs import (
    BGPMessage, 
    BGPStats,
    BGPOpenMessage,
    BGPKeepaliveMessage,
    BGPUpdateMessage,
    BGPNotificationMessage,
    BGPUnknownMessage,
    scapy_decode_bgp,
    build_model_from_scapy
)
from tester_service.models.bgp_settings import BGPConfig, BGPConnectionStatus, BGPStats


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

    def build_open_message(self):
        """
        Build BGP OPEN message.
        """
        bgp_msg = BGPOpenMessage(
            timestamp=datetime.now(),
            direction="sent",
            version=self.connection_status.config.bgp_version, 
            my_as=self.connection_status.config.as_number, 
            hold_time=self.connection_status.config.hold_time, 
            bgp_id=self.connection_status.config.router_id,
            opt_params=[]
            )
        return bgp_msg.to_bytes()

    def build_keepalive_message(self) -> bytes:
        """Build BGP KEEPALIVE message"""
        bgp_msg = BGPKeepaliveMessage(
            timestamp=datetime.now(),
            direction="sent",
        )
        return bgp_msg.to_bytes()


    def parse_bgp_message(self, data: bytes, direction: str = "received") -> Dict[str, Any]:
        """Parse BGP message and return details"""

        try:
            scapy_pkt = scapy_decode_bgp(data)
        except Exception as e:
            return BGPUnknownMessage(
                timestamp=datetime.now(),
                direction=direction,
                raw_data=data,
                details={"error": str(e)},
            )

        try:
            model = build_model_from_scapy(scapy_pkt, direction)
            return model
        except Exception as e:
            return BGPUnknownMessage(
                timestamp=datetime.now(),
                direction=direction,
                raw_data=data,
                details={"error": f"Failed to build model: {e}"},
            )


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

        if msg.bgp_type == 1:
            self.stats.open_messages += 1
        elif msg.bgp_type == 4:
            self.stats.keepalive_messages += 1
        elif msg.bgp_type == 2:
            self.stats.update_messages += 1
        elif msg.bgp_type == 3:
            self.stats.notification_messages += 1
        print(f"\n({msg.direction})MSG STRUCTURE:\n{msg.show(dump=True)}")

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
                print(f"Keepalive failed: {e}")
                await self.stop_connection()
                return

    async def _connect_once(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.connection_status.config.remote_host,
            self.connection_status.config.remote_port
        )

        self.connection_status.connected = True
        self.connection_status.connection_start_time = datetime.now()

        open_msg = self.build_open_message()
        self.writer.write(open_msg)
        await self.writer.drain()

        self.keepalive_task = asyncio.create_task(self.send_keepalives())
        self.connection_task = asyncio.create_task(self.read_messages())

    async def start_connection(self):
        while True:
            try:
                await self._connect_once()
                await self.connection_task
            except Exception as e:
                print(f"Connection error: {e}")
            finally:
                await self.stop_connection()
                await asyncio.sleep(5)

    
    # async def start_connection(self):
    #     """Start BGP connection"""
    #     if self.connection_status.connected:
    #         raise Exception("BGP connection already active")

    #     while True:
    #         try:
    #             self.reader, self.writer = await asyncio.open_connection(
    #                 self.connection_status.config.remote_host, self.connection_status.config.remote_port
    #             )

    #             self.connection_status.connected = True
    #             self.connection_status.connection_start_time = datetime.now()
    #             self.connection_status.last_activity = datetime.now()

    #             # Send OPEN message
    #             open_msg = self.build_open_message()
    #             self.writer.write(open_msg)
    #             await self.writer.drain()
    #             sent = self.parse_bgp_message(open_msg, direction="sent")
    #             self.log_message(sent)

    #             # Start keepalive task
    #             self.keepalive_task = asyncio.create_task(self.send_keepalives())

    #             # Start message reading task
    #             self.connection_task = asyncio.create_task(self.read_messages())

    #             return {"status": "connected", "message": "BGP connection established"}

    #         except Exception as e:
    #             self.connection_status.connected = False
    #             print(f"Failed to establish BGP connection: {e}")
    #             await asyncio.sleep(10)


    async def read_messages(self):
        """Read and process BGP messages"""
        try:
            while self.connection_status.connected and self.reader:
                data = await self.reader.read(4096)
                if not data:
                    print("Peer closed TCP session")
                    return

                self.connection_status.last_activity = datetime.now()
                self.connection_status.messages_received += 1

                revceived = self.parse_bgp_message(data, direction="received")
                self.log_message(revceived)

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
            try:
                if self.writer.is_closing():
                    await self.writer.wait_closed()
                else:
                    print("Socket was not opened.")
            except asyncio.exceptions.CancelledError:
                print("Socket is not ready")
                await asyncio.sleep(5)

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
