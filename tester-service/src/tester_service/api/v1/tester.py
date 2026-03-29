import logging
import asyncio
from typing import Any, List
from fastapi import APIRouter, Query
from starlette.requests import Request
from starlette.responses import Response
from tester_service.models.bgp_settings import BGPConnectionStatus
from tester_service.services.bgp import BGPManager, get_bgp_manager
from tester_service.models.schemas import BGPConfigUpdate, BGPRouteInjection, BGPWithdrawRequest
from fastapi import Depends


logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/ping")
async def ping(request: Request):
    return Response(content="pong", status_code=200)


@router.get("/status", response_model=BGPConnectionStatus)
async def get_status(bgp_manager: BGPManager = Depends(get_bgp_manager)):
    """Get BGP connection status"""
    print(bgp_manager)
    return bgp_manager.get_connection_status()


@router.patch("/bgp/config")
async def update_bgp_config(
    update: BGPConfigUpdate,
    reconnect: bool = Query(False),
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    result = await bgp_manager.update_config(update, reconnect=reconnect)

    if reconnect and bgp_manager.connection_status.connected:
        await bgp_manager.stop_connection()
        asyncio.create_task(bgp_manager.start_connection())

    return result


@router.get("/bgp/config")
async def get_bgp_config(
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    return bgp_manager.connection_status.config


@router.post("/bgp/routes/inject")
async def inject_bgp_route(
    route: BGPRouteInjection,
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    """Inject and advertise a BGP route to the neighbor"""
    result = await bgp_manager.inject_route(route)
    return result


@router.delete("/bgp/routes")
async def withdraw_bgp_routes(
    request: BGPWithdrawRequest,
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    """Withdraw a BGP route by prefix"""
    result = await bgp_manager.withdraw_routes(request)
    return result



@router.get("/bgp/routes")
async def get_bgp_routes(
    route_type: str | None = None,
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    """Get the BGP routing table, optionally filtered by route type"""
    routes = bgp_manager.get_routing_table(route_type)
    print(f"Routes: {routes}")
    return {"routes": routes, "count": len(routes)}
