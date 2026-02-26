import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.api.router import api_router
from backend.app.core.logging import setup_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("dragonflAI API starting")
    yield


app = FastAPI(
    title="dragonflAI",
    description="AI-assisted bug bounty hunting platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(api_router)
