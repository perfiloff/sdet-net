import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
# from tester_service.api.v1.tester import router as tester_router
from tester_service.api.v1.tester import ping as ping_router
from tester_service.core.settings import settings


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    # redis.redis = Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)
    # logging.info("Инициализация Redis - DONE")
    yield
    # await redis.redis.close()
    # logging.info("Закрытие подключения к Redis...")


app = FastAPI(
    title=settings.project_name,
    description="Testing service",
    summary="Async test API",
    version="0.0.1",
    lifespan=app_lifespan,
)

 
# app.include_router(tester_router, prefix="/api/v1/tester", tags=["tester"])
app.include_router(ping_router, prefix="/api/v1/ping", tags=["ping"])


if __name__ == "__main__":
    logging.info("Running FastAPI service...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
