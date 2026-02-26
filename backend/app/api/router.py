from fastapi import APIRouter

from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.programs import router as programs_router
from backend.app.api.routes.runs import router as runs_router
from backend.app.api.routes.targets import router as targets_router

api_router = APIRouter()

api_router.include_router(health_router, tags=["health"])
api_router.include_router(programs_router, prefix="/programs", tags=["programs"])
api_router.include_router(targets_router, prefix="/targets", tags=["targets"])
api_router.include_router(runs_router, prefix="/runs", tags=["runs"])
