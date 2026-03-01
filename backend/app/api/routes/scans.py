import json

from fastapi import APIRouter, Depends, HTTPException
from redis import Redis
from rq import Queue
from rq.job import Retry
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models import Scan, Target
from backend.app.schemas.scan import ScanCreate, ScanOut

router = APIRouter()


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(body: ScanCreate, db: Session = Depends(get_db)):
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    scan = Scan(
        target_id=body.target_id,
        run_id=body.run_id,
        scanner=body.scanner,
        status="queued",
        config_json=json.dumps(body.config),
        log_text="",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    redis_conn = Redis.from_url(settings.redis_url)
    q = Queue("scans", connection=redis_conn)
    q.enqueue(
        "worker.jobs.execute_scan.execute_scan",
        scan.id,
        job_timeout=settings.job_timeout_seconds,
        retry=Retry(max=3, interval=[10, 30, 60]),
    )
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(target_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(Scan)
    if target_id is not None:
        query = query.filter(Scan.target_id == target_id)
    return query.order_by(Scan.id.desc()).all()


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
