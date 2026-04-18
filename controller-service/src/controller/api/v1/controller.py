import asyncio
import contextlib
import logging
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import PlainTextResponse
from starlette.responses import Response

from controller.core.settings import Settings
from controller.core.state import AppContainer
from controller.models.schemas import (
    DutHealthResponse,
    VtyshSessionConfigureRequest,
    VtyshSessionCreated,
    VtyshSessionCreateRequest,
    VtyshSessionItem,
    VtyshSessionListResponse,
    VtyshSessionShowRequest,
    VtyshSessionShowResponse,
)
from controller.services.log_stream import (
    LogSource,
    lines_from_bytes,
    snapshot_logs,
    stream_merged_logs,
)
from controller.services.ssh.frr import FrrVtyshSession
from controller.services.ssh.session_store import VtyshSessionStore
from controller.services.vtysh_ssh import check_dut_health

logger = logging.getLogger(__name__)

router = APIRouter()


def get_container(request: Request) -> AppContainer:
    return request.app.state.container


ContainerDep = Annotated[AppContainer, Depends(get_container)]


def get_settings(container: ContainerDep) -> Settings:
    return container.settings


def get_session_store(container: ContainerDep) -> VtyshSessionStore:
    return container.vtysh_session_store


def _get_vtysh_session(
    session_id: str,
    store: VtyshSessionStore = Depends(get_session_store),
) -> FrrVtyshSession:
    sess = store.get(session_id)
    if sess is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vtysh session not found")
    return sess


VtyshSessionDep = Annotated[FrrVtyshSession, Depends(_get_vtysh_session)]


@router.get("/ping")
async def ping() -> Response:
    return Response(content="pong", status_code=200)


@router.websocket("/stream/logs")
async def logs_websocket(
    websocket: WebSocket,
    s: Settings = Depends(get_settings),
) -> None:
    """Stream newline-delimited log lines; query `sources=all|frr|tester`."""
    await websocket.accept()
    src_key = websocket.query_params.get("sources", "all").strip().lower()
    if src_key in ("frr", "tester", "all"):
        source: LogSource = src_key  # type: ignore[assignment]
    elif "frr" in src_key and "tester" in src_key:
        source = "all"
    else:
        source = "all"

    try:
        async for line in lines_from_bytes(stream_merged_logs(s, source, tail=0)):
            await websocket.send_text(line)
            await asyncio.sleep(0)  # yield for cancellation
    except WebSocketDisconnect:
        logger.info("logs websocket client disconnected")
    except Exception as exc:  # noqa: BLE001
        logger.exception("logs websocket error: %s", exc)
        try:
            await websocket.close(code=1011)
        except Exception:  # noqa: BLE001
            pass


@router.get("/logs/{source}", response_class=PlainTextResponse)
async def get_logs(
    source: Literal["frr", "tester", "all"],
    tail: int = Query(default=500, ge=1, le=50_000),
    s: Settings = Depends(get_settings),
) -> str:
    """Return the last *tail* log lines from container stdout/stderr (via Docker)."""
    if source == "all":
        parts = []
        for name in [s.container_frr, s.container_tester]:
            parts.append(f"=== {name} ===\n")
            parts.append(await snapshot_logs(s, name, tail=tail))
        return "".join(parts)
    return await snapshot_logs(s, source, tail=tail)


@router.get("/dut/vtysh/sessions", response_model=VtyshSessionListResponse)
async def dut_vtysh_sessions_list(container: ContainerDep) -> VtyshSessionListResponse:
    """List open vtysh sessions with ``host:port``; ``bootstrap`` marks sessions created from config at startup."""
    store = container.vtysh_session_store
    return VtyshSessionListResponse(
        sessions=[
            VtyshSessionItem(
                session_id=rec.session_id,
                host=rec.host,
                port=rec.port,
                endpoint=rec.endpoint,
                bootstrap=rec.bootstrap,
            )
            for rec in store.list_records()
        ],
    )


@router.post("/dut/vtysh/sessions", response_model=VtyshSessionCreated)
async def dut_vtysh_session_create(
    s: Settings = Depends(get_settings),
    store: VtyshSessionStore = Depends(get_session_store),
    body: VtyshSessionCreateRequest = Body(default_factory=VtyshSessionCreateRequest),
) -> VtyshSessionCreated:
    """Open SSH + interactive vtysh (PTY); use WebSocket shell or configure/show until DELETE."""
    session_id = await store.create(s, body.ssh)
    return VtyshSessionCreated(session_id=session_id)


@router.delete("/dut/vtysh/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def dut_vtysh_session_delete(
    session_id: str,
    store: VtyshSessionStore = Depends(get_session_store),
) -> None:
    """Close vtysh and SSH for this session id (idempotent if already gone)."""
    await store.delete(session_id)


@router.post("/dut/vtysh/sessions/{session_id}/show", response_model=VtyshSessionShowResponse)
async def dut_vtysh_session_show(
    body: VtyshSessionShowRequest,
    session: VtyshSessionDep,
) -> VtyshSessionShowResponse:
    """Run an exec-mode command on the open PTY (not ``vtysh -c``)."""
    try:
        out = await session.show(body.command)
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return VtyshSessionShowResponse(output=out)


@router.post("/dut/vtysh/sessions/{session_id}/configure", response_model=VtyshSessionShowResponse)
async def dut_vtysh_session_configure(
    body: VtyshSessionConfigureRequest,
    session: VtyshSessionDep,
) -> VtyshSessionShowResponse:
    """``configure terminal`` then the given lines, then ``end``."""
    try:
        out = await session.configure(body.commands)
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return VtyshSessionShowResponse(output=out)


@router.websocket("/dut/vtysh/sessions/{session_id}/shell")
async def dut_vtysh_session_shell(
    websocket: WebSocket,
    session_id: str,
    store: VtyshSessionStore = Depends(get_session_store),
) -> None:
    """Bidirectional vtysh PTY (e.g. ``terminal monitor``). Close WebSocket before REST show/configure."""
    session = store.get(session_id)
    if session is None:
        await websocket.close(code=1008, reason="vtysh session not found")
        return
    await websocket.accept()
    session.attach_shell_websocket()
    proc = await session.get_shell()
    stdout, stdin = proc.stdout, proc.stdin
    if stdout is None or stdin is None:
        session.detach_shell_websocket()
        await websocket.close(code=1011)
        return

    async def pump_out() -> None:
        try:
            while True:
                chunk = await stdout.read(65536)
                if not chunk:
                    break
                try:
                    if isinstance(chunk, str):
                        await websocket.send_text(chunk)
                    else:
                        await websocket.send_bytes(chunk)
                except (WebSocketDisconnect, RuntimeError):
                    break
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("vtysh shell pump_out: %s", exc)

    out_task = asyncio.create_task(pump_out())
    try:
        while True:
            msg = await websocket.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            if msg.get("type") != "websocket.receive":
                continue
            text = msg.get("text")
            raw = msg.get("bytes")
            if text is not None:
                stdin.write(text)
                await stdin.drain()
            elif raw is not None:
                stdin.write(raw.decode("utf-8", errors="replace"))
                await stdin.drain()
    except WebSocketDisconnect:
        logger.info("vtysh shell websocket disconnected session_id=%s", session_id)
    finally:
        out_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await out_task
        session.detach_shell_websocket()


@router.get("/dut/health", response_model=DutHealthResponse)
async def dut_health(
    s: Settings = Depends(get_settings),
) -> DutHealthResponse:
    """Check SSH to DUT and `vtysh -c 'show version'`."""
    ssh_ok, vtysh_ok, msg = await check_dut_health(settings=s)
    return DutHealthResponse(
        ssh_reachable=ssh_ok,
        vtysh_ok=vtysh_ok,
        message=msg,
    )
