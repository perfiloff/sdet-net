import asyncio
import logging

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from starlette.requests import Request
from starlette.responses import Response

from tester_service.core.config_loader import (
    load_bgp_config_from_yaml,
    resolve_bgp_config_path,
    write_bgp_config_yaml,
)
from tester_service.models.bgp_settings import BGPConfig, BGPConnectionStatus, BGPFSMState
from tester_service.models.schemas import (
    BGPConfigUpdate,
    BGPRouteInjectionBatch,
    BGPYamlUploadResponse,
    BGPWithdrawRequest,
)
from tester_service.services.bgp import BGPManager, get_bgp_manager


logger = logging.getLogger(__name__)

router = APIRouter()


async def _apply_loaded_bgp_settings(
    bgp_manager: BGPManager,
    loaded,
    reconnect: bool,
) -> BGPConfig:
    update = BGPConfigUpdate(
        as_number=loaded.as_number,
        router_id=loaded.router_id,
        hold_time=loaded.hold_time,
        bgp_version=loaded.bgp_version,
        remote_host=loaded.remote_host,
        remote_port=loaded.remote_port,
        capabilities=list(loaded.capabilities),
    )
    await bgp_manager.update_config(update, reconnect=reconnect)

    if reconnect and bgp_manager.connection_status.state != BGPFSMState.IDLE:
        await bgp_manager.stop_connection()
        asyncio.create_task(bgp_manager.start_connection())

    return bgp_manager.connection_status.config


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

    if reconnect and bgp_manager.connection_status.state != BGPFSMState.IDLE:
        await bgp_manager.stop_connection()
        asyncio.create_task(bgp_manager.start_connection())

    return result


@router.get("/bgp/config/yaml-path")
async def get_bgp_config_yaml_path() -> dict[str, str]:
    """Return the path where uploaded YAML is stored on this host."""
    path = resolve_bgp_config_path()
    return {"path": str(path)}


@router.post("/bgp/config/upload-yaml", response_model=BGPYamlUploadResponse)
async def upload_bgp_config_yaml(
    file: UploadFile = File(..., description="BGP YAML with a top-level ``bgp:`` section"),
    reconnect: bool = Query(False, description="Reconnect BGP after applying uploaded config"),
    apply: bool = Query(True, description="Load written file into the running BGP manager"),
    path: str | None = Query(
        None,
        description="Target path on the tester host; default from BGP_CONFIG_FILE or /opt/config/bgp_config.yaml",
    ),
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    """Upload a local YAML file, overwrite the on-disk config, and optionally apply it."""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="YAML file must be UTF-8 text") from exc

    try:
        written = write_bgp_config_yaml(text, path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write config: {exc}") from exc

    applied_config = None
    if apply:
        try:
            loaded = load_bgp_config_from_yaml(str(written))
            applied_config = await _apply_loaded_bgp_settings(bgp_manager, loaded, reconnect)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return BGPYamlUploadResponse(
        path=str(written),
        applied=apply,
        config=applied_config.model_dump() if applied_config is not None else None,
    )


@router.post("/bgp/config/load-from-yaml")
async def load_bgp_config_from_yaml_endpoint(
    path: str | None = Query(
        None,
        description="YAML path on the server; omit to use default search (e.g. config/bgp_config.yaml)",
    ),
    reconnect: bool = Query(
        False,
        description="Apply settings and restart BGP connection if not idle",
    ),
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    """Load ``bgp:`` block from YAML on disk and apply (file must already exist on the tester)."""
    try:
        loaded = load_bgp_config_from_yaml(path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return await _apply_loaded_bgp_settings(bgp_manager, loaded, reconnect)


@router.get("/bgp/config")
async def get_bgp_config(
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    return bgp_manager.connection_status.config


@router.post("/bgp/routes/inject")
async def inject_bgp_routes(
    batch: BGPRouteInjectionBatch,
    bgp_manager: BGPManager = Depends(get_bgp_manager),
):
    """Inject and advertise one or more BGP routes to the neighbor"""
    result = await bgp_manager.inject_routes(batch)
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
