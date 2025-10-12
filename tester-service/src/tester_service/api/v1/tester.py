import logging

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
async def ping(request: Request):
    return Response(content="pong", status_code=200)
