import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

# from tester_service.api.v1.tester import router as tester_router
from tester_service.api.v1.tester import router
from tester_service.core.settings import settings
from tester_service.services.bgp import get_bgp_manager


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    mgr = get_bgp_manager()
    await mgr.start_connection()
    yield
    await mgr.stop_connection()


app = FastAPI(
    title=settings.project_name,
    description="Testing service",
    summary="Async test API",
    version="0.0.1",
    lifespan=app_lifespan,
)


app.include_router(router, prefix="/api/v1", tags=["ping"])


if __name__ == "__main__":
    logging.info("Running FastAPI service...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
