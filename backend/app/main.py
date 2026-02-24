from fastapi import FastAPI

from app.api.router import router
from app.core.logging import configure_logging

configure_logging()

app = FastAPI(title="dragonflAI", version="0.1.0")
app.include_router(router)
