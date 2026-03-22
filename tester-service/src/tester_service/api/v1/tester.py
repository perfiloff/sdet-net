import logging
import asyncio
from fastapi import APIRouter, Query
from starlette.requests import Request
from starlette.responses import Response
from tester_service.models.bgp_settings import BGPConnectionStatus
from tester_service.services.bgp import BGPManager, get_bgp_manager
from tester_service.models.schemas import BGPConfigUpdate
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
