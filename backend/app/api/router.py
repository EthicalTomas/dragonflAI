from fastapi import APIRouter

from app.api.routes import health, programs, targets, runs

router = APIRouter()
router.include_router(health.router, tags=["health"])
router.include_router(programs.router, prefix="/programs", tags=["programs"])
router.include_router(targets.router, prefix="/targets", tags=["targets"])
router.include_router(runs.router, prefix="/runs", tags=["runs"])
