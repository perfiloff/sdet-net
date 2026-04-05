import asyncio
from functools import lru_cache
from datetime import datetime
from typing import Optional, Dict, Any, List

from pydantic import BaseModel
from scapy.base_classes import Net
from tester_service.models.bgp_msgs import (
    BGPMessage, 
    BGPStats,
    BGPOpenMessage,
    BGPKeepaliveMessage,
    BGPUpdateMessage,
    BGPUnknownMessage,
    scapy_decode_bgp,
    build_model_from_scapy
)
from tester_service.models.bgp_settings import BGPConfig, BGPConnectionStatus
from tester_service.models.bgp_capabilities import BGPCapabilityCode, BGPCapabilityModel
from tester_service.models.schemas import BGPConfigUpdate, BGPRoute, BGPRouteInjection, BGPRouteInjectionBatch, BGPWithdrawRequest
from scapy.contrib.bgp import (
    BGPPAAS4BytesPath,
    BGPCapFourBytesASN,
    BGPCapGeneric,
    BGPCapGracefulRestart,
    BGPCapMultiprotocol,
    BGPCapORF,
    BGPCapORFBlock,
    BGPPAASPath,
    BGPPALocalPref,
    BGPPAMultiExitDisc,
    BGPPANextHop,
    BGPPAOrigin,
    BGPNLRI_IPv4,
    BGPOptParam,
    BGPPathAttr,
    bgp_module_conf,
)

class BGPManager:
    def __init__(self):
        self.connection_status = BGPConnectionStatus(connected=False, config=BGPConfig())
        self._sync_as_path_asn_width()
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
        # Routing table state
        self.routing_table: List[BGPRoute] = []
        print(f"BGPManager initialized with config: {self.connection_status.config}")

    def __str__(self):
        return self.connection_status.config.__str__()

    def ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP address to bytes"""
        return bytes(map(int, ip.split(".")))

    def _sync_as_path_asn_width(self):
        """Use 4-byte AS_PATH encoding when Four-Octet-AS capability is enabled."""
        has_four_octet = any(
            int(cap.code) == int(BGPCapabilityCode.FOUR_OCTET_AS)
            for cap in self.connection_status.config.capabilities
        )
        bgp_module_conf.use_2_bytes_asn = not has_four_octet

    def _capability_data_to_bytes(self, value: Any) -> bytes:
        """Normalize arbitrary capability payload data to bytes for generic capabilities."""
        if value is None:
            return b""

        if isinstance(value, bytes):
            return value

        if isinstance(value, str):
            return bytes.fromhex(value)

        if isinstance(value, list):
            return bytes(value)

        if isinstance(value, dict):
            if not value:
                return b""
            if "hex" in value and isinstance(value["hex"], str):
                return bytes.fromhex(value["hex"])
            if "data" in value:
                return self._capability_data_to_bytes(value["data"])

        raise ValueError(f"Unsupported capability payload format: {type(value).__name__}")

    def _to_cidr(self, prefix: Any) -> str:
        """Normalize route prefix objects to CIDR string form."""
        if isinstance(prefix, str):
            return prefix

        if isinstance(prefix, Net):
            return f"{prefix}/{prefix.mask}" if prefix.mask != 32 else str(prefix)

        if hasattr(prefix, "prefix"):
            return self._to_cidr(prefix.prefix)

        return str(prefix)

    def _extract_update_attrs(self, path_attrs: list[Any]) -> dict[str, Any]:
        """Extract key routing attributes from Scapy BGP path attributes."""
        attrs: dict[str, Any] = {
            "origin": 0,
            "as_path": [],
            "next_hop": None,
            "local_pref": None,
            "med": None,
        }

        for path_attr in path_attrs or []:
            attr = getattr(path_attr, "attribute", None)
            type_code = getattr(path_attr, "type_code", None)

            if type_code == 1 and hasattr(attr, "origin"):
                attrs["origin"] = int(attr.origin)
            elif type_code in (2, 17) and hasattr(attr, "segments"):
                as_path: list[int] = []
                for segment in attr.segments:
                    as_path.extend(int(asn) for asn in getattr(segment, "segment_value", []))
                attrs["as_path"] = as_path
            elif type_code == 3 and hasattr(attr, "next_hop"):
                attrs["next_hop"] = str(attr.next_hop)
            elif type_code == 5 and hasattr(attr, "local_pref"):
                attrs["local_pref"] = int(attr.local_pref)
            elif type_code == 4 and hasattr(attr, "med"):
                attrs["med"] = int(attr.med)

        return attrs

    def _update_learned_routes(self, msg: BGPUpdateMessage):
        """Apply received UPDATE NLRIs/withdrawals to learned routes table state."""
        source = self.connection_status.config.remote_host

        withdrawn_prefixes = {
            self._to_cidr(withdrawn)
            for withdrawn in (msg.withdrawn_routes or [])
        }
        if withdrawn_prefixes:
            self.routing_table = [
                route
                for route in self.routing_table
                if not (
                    route.route_type == "learned"
                    and self._to_cidr(route.prefix) in withdrawn_prefixes
                )
            ]

        attrs = self._extract_update_attrs(msg.path_attr or [])
        next_hop = attrs["next_hop"] or "0.0.0.0"

        for nlri in msg.nlri or []:
            prefix = self._to_cidr(nlri)

            # Replace any older learned route for the same prefix.
            self.routing_table = [
                route
                for route in self.routing_table
                if not (route.route_type == "learned" and self._to_cidr(route.prefix) == prefix)
            ]

            self.routing_table.append(
                BGPRoute(
                    prefix=prefix,
                    next_hop=next_hop,
                    as_path=attrs["as_path"],
                    origin=attrs["origin"],
                    local_pref=attrs["local_pref"],
                    med=attrs["med"],
                    route_type="learned",
                    timestamp=datetime.now(),
                    source=source,
                )
            )

    def _build_open_opt_params(self, capabilities: list[BGPCapabilityModel]) -> list[BGPOptParam]:
        """Build OPEN optional parameters from configured BGP capabilities."""
        opt_params: list[BGPOptParam] = []

        for capability in capabilities:
            cap_code = int(capability.code)
            cap_value = capability.value or {}

            if cap_code == BGPCapabilityCode.MP_BGP:
                param_value = BGPCapMultiprotocol(
                    afi=int(cap_value.get("afi", 1)),
                    reserved=int(cap_value.get("reserved", 0)),
                    safi=int(cap_value.get("safi", 1)),
                )
            elif cap_code == BGPCapabilityCode.FOUR_OCTET_AS:
                param_value = BGPCapFourBytesASN(asn=int(cap_value.get("asn", self.connection_status.config.as_number)))
            elif cap_code == BGPCapabilityCode.GRACEFUL_RESTART:
                param_value = BGPCapGracefulRestart(
                    restart_flags=int(cap_value.get("restart_flags", 0)),
                    restart_time=int(cap_value.get("restart_time", 0)),
                )
            elif cap_code == BGPCapabilityCode.ORF:
                orf_blocks = cap_value.get("orf")
                if not orf_blocks:
                    # RFC 5291 minimum ORF payload is one block with zero entries.
                    orf_blocks = [{"afi": 1, "reserved": 0, "safi": 1, "entries": []}]

                blocks = []
                for block in orf_blocks:
                    tuples = [
                        BGPCapORFBlock.ORFTuple(
                            orf_type=int(entry.get("orf_type", 64)),
                            send_receive=int(entry.get("send_receive", 3)),
                        )
                        for entry in block.get("entries", [])
                    ]
                    blocks.append(
                        BGPCapORFBlock(
                            afi=int(block.get("afi", 1)),
                            reserved=int(block.get("reserved", 0)),
                            safi=int(block.get("safi", 1)),
                            entries=tuples,
                        )
                    )

                param_value = BGPCapORF(orf=blocks)
            else:
                # Use generic packet for capabilities not mapped to a specific Scapy helper.
                param_value = BGPCapGeneric(
                    code=cap_code,
                    cap_data=self._capability_data_to_bytes(cap_value),
                )

            opt_params.append(BGPOptParam(param_type=2, param_value=param_value))

        return opt_params

    def build_open_message(self):
        """
        Build BGP OPEN message.
        """
        opt_params = self._build_open_opt_params(self.connection_status.config.capabilities)

        bgp_msg = BGPOpenMessage(
            timestamp=datetime.now(),
            direction="sent",
            version=self.connection_status.config.bgp_version, 
            my_as=self.connection_status.config.as_number, 
            hold_time=self.connection_status.config.hold_time, 
            bgp_id=self.connection_status.config.router_id,
            opt_params=opt_params,
            )
        return bgp_msg.to_bytes()

    def build_keepalive_message(self) -> bytes:
        """Build BGP KEEPALIVE message"""
        bgp_msg = BGPKeepaliveMessage(
            timestamp=datetime.now(),
            direction="sent",
        )
        return bgp_msg.to_bytes()

    def build_update_message(self, route_injection: dict) -> bytes:
        """Build BGP UPDATE message for route injection"""
        self._sync_as_path_asn_width()

        # Build path attributes
        path_attrs = []

        # Origin
        print(f"Origin: {route_injection}")
        origin_attr = BGPPathAttr(
            type_flags="Transitive",
            type_code=1,
            attribute=BGPPAOrigin(origin=int(route_injection.origin)),
        )
        path_attrs.append(origin_attr)

        # AS Path
        if bgp_module_conf.use_2_bytes_asn:
            segments=[
                BGPPAASPath.ASPathSegment(
                    segment_type=2,  # AS_SEQUENCE
                    segment_value=[int(asn) for asn in route_injection.as_path],
                )
            ]
            if route_injection.as_path:
                as_path_payload = BGPPAASPath(segments=segments)
            else:
                as_path_payload = BGPPAASPath()    
        else:
            segments=[
                    BGPPAAS4BytesPath.ASPathSegment(
                        segment_type=2,  # AS_SEQUENCE
                        segment_value=[int(asn) for asn in route_injection.as_path],
                    )
                ]
            if route_injection.as_path:
                as_path_payload = BGPPAAS4BytesPath(segments=segments)
            else:
                as_path_payload = BGPPAASPath()


        as_path_attr = BGPPathAttr(
            type_flags="Transitive",
            type_code=2,
            attribute=as_path_payload,
        )
        path_attrs.append(as_path_attr)

        # Next Hop
        next_hop = route_injection.next_hop or self.connection_status.config.router_id
        next_hop_attr = BGPPathAttr(
            type_flags="Transitive",
            type_code=3,
            attribute=BGPPANextHop(next_hop=next_hop),
        )
        path_attrs.append(next_hop_attr)

        # Local Preference (optional)
        if route_injection.local_pref is not None:
            local_pref_attr = BGPPathAttr(
                type_flags="Transitive",
                type_code=5,
                attribute=BGPPALocalPref(local_pref=int(route_injection.local_pref)),
            )
            path_attrs.append(local_pref_attr)

        # MED (optional)
        if route_injection.med is not None:
            med_attr = BGPPathAttr(
                type_flags="Optional",
                type_code=4,
                attribute=BGPPAMultiExitDisc(med=int(route_injection.med)),
            )
            path_attrs.append(med_attr)

        # NLRI
        nlri = [BGPNLRI_IPv4(prefix=route_injection.prefix)]

        bgp_msg = BGPUpdateMessage(
            timestamp=datetime.now(),
            direction="sent",
            withdrawn_routes=[],
            path_attr=path_attrs,
            nlri=nlri
        )
        print(f"BGP UPDATE message: {bgp_msg.show(dump=True)}")
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

    def _same_route_attrs(self, left: BGPRouteInjection, right: BGPRouteInjection) -> bool:
        """Return True when two routes share the exact same path attributes."""
        left_next_hop = left.next_hop or self.connection_status.config.router_id
        right_next_hop = right.next_hop or self.connection_status.config.router_id

        return (
            left.origin == right.origin
            and left.as_path == right.as_path
            and left_next_hop == right_next_hop
            and left.local_pref == right.local_pref
            and left.med == right.med
        )

    def _build_grouped_update_message(self, routes: list[BGPRouteInjection]) -> bytes:
        """Build one UPDATE message with shared path attributes and all route NLRIs."""
        ref = routes[0]  # all routes in the group share the same attrs

        path_attrs = []

        path_attrs.append(BGPPathAttr(
            type_flags="Transitive",
            type_code=1,
            attribute=BGPPAOrigin(origin=int(ref.origin)),
        ))

        if bgp_module_conf.use_2_bytes_asn:
            as_path_payload = (
                BGPPAASPath(segments=[BGPPAASPath.ASPathSegment(segment_type=2, segment_value=[int(a) for a in ref.as_path])])
                if ref.as_path else BGPPAASPath()
            )
        else:
            as_path_payload = (
                BGPPAAS4BytesPath(segments=[BGPPAAS4BytesPath.ASPathSegment(segment_type=2, segment_value=[int(a) for a in ref.as_path])])
                if ref.as_path else BGPPAASPath()
            )

        path_attrs.append(BGPPathAttr(
            type_flags="Transitive",
            type_code=2,
            attribute=as_path_payload,
        ))

        next_hop = ref.next_hop or self.connection_status.config.router_id
        path_attrs.append(BGPPathAttr(
            type_flags="Transitive",
            type_code=3,
            attribute=BGPPANextHop(next_hop=next_hop),
        ))

        if ref.local_pref is not None:
            path_attrs.append(BGPPathAttr(
                type_flags="Transitive",
                type_code=5,
                attribute=BGPPALocalPref(local_pref=int(ref.local_pref)),
            ))

        if ref.med is not None:
            path_attrs.append(BGPPathAttr(
                type_flags="Optional",
                type_code=4,
                attribute=BGPPAMultiExitDisc(med=int(ref.med)),
            ))

        nlri = [BGPNLRI_IPv4(prefix=r.prefix) for r in routes]

        bgp_msg = BGPUpdateMessage(
            timestamp=datetime.now(),
            direction="sent",
            withdrawn_routes=[],
            path_attr=path_attrs,
            nlri=nlri,
        )
        return bgp_msg.to_bytes()

    def _split_group_by_message_size(self, routes: list[BGPRouteInjection], max_size: int = 4096) -> list[list[BGPRouteInjection]]:
        """Split a route group so each resulting UPDATE message is <= max_size bytes."""
        if not routes:
            return []

        chunks: list[list[BGPRouteInjection]] = []
        current: list[BGPRouteInjection] = []

        for route in routes:
            candidate = current + [route]
            if len(self._build_grouped_update_message(candidate)) <= max_size:
                current = candidate
                continue

            if not current:
                raise Exception(
                    f"Route {route.prefix} exceeds max BGP UPDATE size {max_size} bytes by itself"
                )

            chunks.append(current)
            current = [route]

            if len(self._build_grouped_update_message(current)) > max_size:
                raise Exception(
                    f"Route {route.prefix} exceeds max BGP UPDATE size {max_size} bytes by itself"
                )

        if current:
            chunks.append(current)

        return chunks

    def log_message(self, msg: BaseModel):
        """Log BGP message"""

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
                if self.connection_status.connected:
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

                received = self.parse_bgp_message(data, direction="received")
                if getattr(received, "bgp_type", None) == 2:
                    self._update_learned_routes(received)
                self.log_message(received)

        except Exception as e:
            print(f"Error reading messages: {e}")
        finally:
            if self.connection_status.connected:
                await self.stop_connection()

    async def stop_connection(self):
        """Stop BGP connection"""
        if not self.connection_status.connected:
            print("The connection is already down.")
            return
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

    async def update_config(self, new_config: BGPConfigUpdate, reconnect: bool):
        """Update BGP configuration"""
        if self.connection_status.connected and reconnect:
            await self.stop_connection()
        for key, value in new_config.model_dump().items():
            if value is not None:
                setattr(self.connection_status.config, key, value)
        self._sync_as_path_asn_width()
        if not self.connection_status.connected:
            await self.start_connection()

        return True
        

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

    async def inject_route(self, route_injection: BGPRouteInjection):
        """Inject and advertise a BGP route"""
        if not self.connection_status.connected:
            raise Exception("BGP connection not active")

        if not self.writer:
            raise Exception("No active BGP connection")

        try:
            # Build and send UPDATE message
            update_msg = self.build_update_message(route_injection)
            self.writer.write(update_msg)
            await self.writer.drain()

            # Log the sent message
            sent = self.parse_bgp_message(update_msg, direction="sent")
            self.log_message(sent)
            print(f"Route injected: {route_injection}, {Net(route_injection.prefix)}")

            # Add route to local routing table
            route = BGPRoute(
                prefix=Net(route_injection.prefix),
                next_hop=Net(route_injection.next_hop or self.connection_status.config.router_id),
                as_path=route_injection.as_path,
                origin=route_injection.origin,
                local_pref=route_injection.local_pref,
                med=route_injection.med,
                route_type="advertised",
                timestamp=datetime.now(),
                source=None
            )

            # Remove any existing route with the same prefix
            self.routing_table = [r for r in self.routing_table if r.prefix != route_injection.prefix]

            # Add the new route
            self.routing_table.append(route)

            return {"status": "success", "message": f"Route {route_injection.prefix} injected and advertised"}

        except Exception as e:
            raise Exception(f"Failed to inject route: {e}")

    async def inject_routes(self, batch: BGPRouteInjectionBatch) -> dict:
        """Inject multiple BGP routes grouped by shared path attributes.

        Routes that share the same origin, as_path, next_hop, local_pref, and med
        are packed into a single UPDATE message with multiple NLRI prefixes instead
        of sending one UPDATE per route.
        """
        if not self.connection_status.connected:
            raise Exception("BGP connection not active")
        if not self.writer:
            raise Exception("No active BGP connection")

        self._sync_as_path_asn_width()

        # Collect all routes then group by exact attribute equality.
        groups: list[list[BGPRouteInjection]] = []
        for route in batch.routes:
            added = False
            for group in groups:
                if self._same_route_attrs(route, group[0]):
                    group.append(route)
                    added = True
                    break
            if not added:
                groups.append([route])

        results = []
        injected = 0
        failed = 0

        updates_sent = 0

        for group_routes in groups:
            try:
                for chunk_routes in self._split_group_by_message_size(group_routes, max_size=4096):
                    update_msg = self._build_grouped_update_message(chunk_routes)
                    self.writer.write(update_msg)
                    await self.writer.drain()

                    sent = self.parse_bgp_message(update_msg, direction="sent")
                    self.log_message(sent)
                    updates_sent += 1

                    now = datetime.now()
                    next_hop = chunk_routes[0].next_hop or self.connection_status.config.router_id
                    for route in chunk_routes:
                        self.routing_table = [
                            r for r in self.routing_table
                            if not (self._to_cidr(r.prefix) == route.prefix and r.route_type == "advertised")
                        ]
                        self.routing_table.append(BGPRoute(
                            prefix=route.prefix,
                            next_hop=next_hop,
                            as_path=route.as_path,
                            origin=route.origin,
                            local_pref=route.local_pref,
                            med=route.med,
                            route_type="advertised",
                            timestamp=now,
                            source=None,
                        ))
                        results.append({"prefix": route.prefix, "status": "success"})
                        injected += 1

            except Exception as e:
                for route in group_routes:
                    results.append({"prefix": route.prefix, "status": "failed", "error": str(e)})
                failed += len(group_routes)

        return {
            "injected": injected,
            "failed": failed,
            "groups": len(groups),
            "updates_sent": updates_sent,
            "max_update_size": 4096,
            "results": results,
        }

    def get_routing_table(self, route_type: str | None = None) -> List[BGPRoute]:
        """Get the routing table, optionally filtered by route type"""
        if route_type:
            return [route for route in self.routing_table if route.route_type == route_type]
        return self.routing_table.copy()

    async def withdraw_routes(self, request: BGPWithdrawRequest):
        """Withdraw multiple routes by their prefixes"""
        if not self.connection_status.connected:
            raise Exception("BGP connection not active")

        if not self.writer:
            raise Exception("No active BGP connection")

        withdrawn_routes = []
        removed_count = 0

        # Validate and collect routes to withdraw
        for prefix in request.prefixes:
            # Check if route exists in our advertised routes
            route_exists = any(
                route.prefix == prefix and route.route_type == "advertised"
                for route in self.routing_table
            )

            if route_exists:
                withdrawn_routes.append(BGPNLRI_IPv4(prefix=prefix))
                removed_count += 1
            else:
                print(f"Warning: Route {prefix} not found in advertised routes")

        if not withdrawn_routes:
            return {"status": "warning", "message": "No valid routes to withdraw", "withdrawn_count": 0}

        try:
            # Build UPDATE message with all withdrawn routes
            bgp_msg = BGPUpdateMessage(
                timestamp=datetime.now(),
                direction="sent",
                withdrawn_routes=withdrawn_routes,
                path_attr=[],
                nlri=[]
            )

            update_msg = bgp_msg.to_bytes()
            self.writer.write(update_msg)
            await self.writer.drain()

            # Log the sent message
            sent = self.parse_bgp_message(update_msg, direction="sent")
            self.log_message(sent)

            # Remove withdrawn routes from routing table
            self.routing_table = [
                route for route in self.routing_table
                if not (route.prefix in request.prefixes and route.route_type == "advertised")
            ]

            return {
                "status": "success",
                "message": f"Successfully withdrew {removed_count} routes",
                "withdrawn_count": removed_count,
                "withdrawn_prefixes": request.prefixes
            }

        except Exception as e:
            raise Exception(f"Failed to withdraw routes: {e}")



@lru_cache()
def get_bgp_manager() -> BGPManager:
    return BGPManager()
