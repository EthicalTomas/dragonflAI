from fastapi import APIRouter

from backend.app.api.routes.assets import router as assets_router
from backend.app.api.routes.detection import detection_router
from backend.app.api.routes.endpoints import router as endpoints_router
from backend.app.api.routes.findings import router as findings_router
from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.programs import router as programs_router
from backend.app.api.routes.runs import router as runs_router
from backend.app.api.routes.targets import router as targets_router

api_router = APIRouter()

api_router.include_router(health_router, tags=["health"])
api_router.include_router(programs_router, prefix="/programs", tags=["programs"])
api_router.include_router(targets_router, prefix="/targets", tags=["targets"])
api_router.include_router(runs_router, prefix="/runs", tags=["runs"])
api_router.include_router(findings_router, prefix="/findings", tags=["findings"])
api_router.include_router(assets_router, prefix="/assets", tags=["assets"])
api_router.include_router(endpoints_router, prefix="/endpoints", tags=["endpoints"])
api_router.include_router(detection_router, prefix="/detection", tags=["detection"])
