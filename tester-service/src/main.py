import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from tester_service.api.v1.tester import router
from tester_service.core.settings import settings
from tester_service.services.bgp import get_bgp_manager


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    mgr = get_bgp_manager()
    app.state.bgp_manager = mgr

    # Store reference to the connection task so we can cancel it during shutdown
    connection_task = asyncio.create_task(mgr.start_connection())

    yield

    # Cancel the connection task first, then stop the connection
    if not connection_task.done():
        connection_task.cancel()
        try:
            await connection_task
        except asyncio.CancelledError:
            pass

    await mgr.stop_connection()


app = FastAPI(
    title=settings.project_name,
    description="Testing service",
    summary="Async test API",
    version="0.0.1",
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    lifespan=app_lifespan,
)


_origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(router, prefix="/api/v1", tags=["ping"])

_STATIC_DIR = Path(__file__).resolve().parent / "tester_service" / "static"
_STATIC_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/")
async def root() -> RedirectResponse:
    return RedirectResponse(url="/ui/", status_code=307)


app.mount(
    "/ui",
    StaticFiles(directory=str(_STATIC_DIR), html=True),
    name="ui",
)


if __name__ == "__main__":
    logging.info("Running FastAPI service...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
