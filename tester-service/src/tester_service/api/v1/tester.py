import logging

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import Response
from tester_service.services.bgp_models import BGPConnectionStatus
from tester_service.services.bgp import BGPManager, get_bgp_manager
from fastapi import Depends


logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
async def ping(request: Request):
    return Response(content="pong", status_code=200)


@router.get("/status", response_model=BGPConnectionStatus)
async def get_status(bgp_manager: BGPManager = Depends(get_bgp_manager)):
    """Get BGP connection status"""
    return bgp_manager.get_connection_status()
