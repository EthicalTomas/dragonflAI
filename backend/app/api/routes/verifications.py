"""API routes for verification management."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from redis import Redis
from rq import Queue
from rq.job import Retry
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models import Finding, Run, Target
from backend.app.models.verification import Verification, VerificationStatus
from backend.app.schemas.verification import VerificationCreate, VerificationOut

logger = logging.getLogger(__name__)

router = APIRouter()

_VALID_METHODS = {"http_replay", "dns_recheck", "screenshot"}


@router.post("", response_model=VerificationOut, status_code=201)
def create_verification(body: VerificationCreate, db: Session = Depends(get_db)):
    """Queue a new verification for a finding or target."""
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")

    if body.run_id is not None and not db.get(Run, body.run_id):
        raise HTTPException(status_code=404, detail="Run not found")

    if body.finding_id is not None and not db.get(Finding, body.finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")

    if body.method not in _VALID_METHODS:
        raise HTTPException(
            status_code=400,
            detail=f"method must be one of: {', '.join(sorted(_VALID_METHODS))}",
        )

    verification = Verification(
        target_id=body.target_id,
        run_id=body.run_id,
        finding_id=body.finding_id,
        status=VerificationStatus.QUEUED,
        method=body.method,
        log_text="",
    )
    db.add(verification)
    db.commit()
    db.refresh(verification)

    redis_conn = Redis.from_url(settings.redis_url)
    q = Queue("verifications", connection=redis_conn)
    q.enqueue(
        "worker.jobs.execute_verification.execute_verification",
        verification.id,
        job_timeout=settings.job_timeout_seconds,
        retry=Retry(max=3, interval=[10, 30, 60]),
    )

    logger.info(
        "Queued verification id=%d method=%s target_id=%d",
        verification.id,
        verification.method,
        verification.target_id,
    )
    return verification


@router.get("", response_model=list[VerificationOut])
def list_verifications(
    target_id: int | None = None,
    run_id: int | None = None,
    finding_id: int | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """List verification records, optionally filtered."""
    query = db.query(Verification)
    if target_id is not None:
        query = query.filter(Verification.target_id == target_id)
    if run_id is not None:
        query = query.filter(Verification.run_id == run_id)
    if finding_id is not None:
        query = query.filter(Verification.finding_id == finding_id)
    if status is not None:
        query = query.filter(Verification.status == status)
    return query.order_by(Verification.id.desc()).all()


@router.get("/{verification_id}", response_model=VerificationOut)
def get_verification(verification_id: int, db: Session = Depends(get_db)):
    """Retrieve a single verification by ID."""
    verification = db.get(Verification, verification_id)
    if not verification:
        raise HTTPException(status_code=404, detail="Verification not found")
    return verification
