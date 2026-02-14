"""
©AngelaMos | 2026
factory.py
"""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.core.redis_manager import redis_manager


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage application startup and shutdown lifecycle
    """
    app.state.startup_time = time.monotonic()
    app.state.pipeline_running = False

    await redis_manager.connect()

    yield

    await redis_manager.disconnect()


def create_app() -> FastAPI:
    """
    Build and configure the AngelusVigil FastAPI application
    """
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.startup_time = time.monotonic()
    app.state.pipeline_running = False

    from app.api.health import router as health_router

    app.include_router(health_router)

    return app
    
