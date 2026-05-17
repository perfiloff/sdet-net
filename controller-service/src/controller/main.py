import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from controller.api.v1.config_hosts import router as config_hosts_router
from controller.api.v1.controller import router
from controller.api.v1.test_runs import router as test_runs_router
from controller.core.settings import settings
from controller.core.state import AppContainer


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    container = AppContainer(settings)
    app.state.container = container
    for target in container.settings.dut_ssh_targets:
        sid = await container.vtysh_session_store.create(
            container.settings,
            ssh=target,
            bootstrap=True,
            kind="control",
        )
        container.bootstrap_session_ids.add(sid)
        container.logger.info(
            "Bootstrap vtysh session %s for %s:%s",
            sid,
            target.host,
            target.port,
        )
    yield
    await container.shutdown()


app = FastAPI(
    title=settings.project_name,
    description="Controller service",
    summary="Async controller API",
    version="0.0.1",
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    lifespan=app_lifespan,
)


app.include_router(router, prefix="/api/v1", tags=["controller"])
app.include_router(config_hosts_router, prefix="/api/v1", tags=["config"])
app.include_router(test_runs_router, prefix="/api/v1")

_STATIC_DIR = Path(__file__).resolve().parent / "static"
# Bind mounts may omit `static/`; Starlette requires the directory to exist.
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
