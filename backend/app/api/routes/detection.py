"""
Detection API routes.

All detection operations are READ-ONLY on external systems — analysis is performed
on data already stored in the database.  Auto-generated findings are always created
as drafts and require manual review before submission.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.detection.heuristics import HeuristicEngine
from backend.app.detection.orchestrator import DetectionOrchestrator
from backend.app.detection.patterns import PatternMatcher
from backend.app.models import Asset, Endpoint, Target

logger = logging.getLogger(__name__)

router = APIRouter()

_VALID_CONFIDENCE = {"low", "medium", "high"}


class _RunRequest(BaseModel):
    target_id: int
    run_id: int | None = None


class _AutoFindingsRequest(BaseModel):
    target_id: int
    min_confidence: str = "medium"


# ---------------------------------------------------------------------------
# POST /run
# ---------------------------------------------------------------------------


@router.post("/run")
def run_detection(body: _RunRequest, db: Session = Depends(get_db)):
    """Run detection on all stored endpoints and assets for a target.

    Detection is read-only on external systems; only database records are analyzed.
    Flags interesting endpoints/assets and returns the full detection report.
    """
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")

    orchestrator = DetectionOrchestrator(db)
    report = orchestrator.run_detection(body.target_id, body.run_id)
    db.commit()
    logger.info(
        "run_detection: target_id=%d run_id=%s signals=%d",
        body.target_id,
        body.run_id,
        report["signals_found"],
    )
    return report


# ---------------------------------------------------------------------------
# POST /auto-findings
# ---------------------------------------------------------------------------


@router.post("/auto-findings")
def auto_findings(body: _AutoFindingsRequest, db: Session = Depends(get_db)):
    """Auto-generate DRAFT findings from detection signals.

    All findings are created as drafts and require manual review before submission.
    """
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")

    if body.min_confidence not in _VALID_CONFIDENCE:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid min_confidence. Must be one of: "
                f"{', '.join(sorted(_VALID_CONFIDENCE))}"
            ),
        )

    orchestrator = DetectionOrchestrator(db)
    report = orchestrator.run_detection(body.target_id)
    signals = report["signals"]
    count, finding_ids = orchestrator.auto_create_findings(
        body.target_id, signals, body.min_confidence
    )
    db.commit()
    logger.info(
        "auto-findings: target_id=%d min_confidence=%s findings_created=%d",
        body.target_id,
        body.min_confidence,
        count,
    )
    return {
        "findings_created": count,
        "finding_ids": finding_ids,
        "note": "All findings are created as drafts and require manual review before submission.",
    }


# ---------------------------------------------------------------------------
# GET /signals/{target_id}
# ---------------------------------------------------------------------------


@router.get("/signals/{target_id}")
def get_signals(target_id: int, db: Session = Depends(get_db)):
    """Get detection signals for a target, grouped by vulnerability type.

    Runs detection using only stored database data — no external network calls.
    No database state is modified by this endpoint.
    """
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found")

    orchestrator = DetectionOrchestrator(db)
    report = orchestrator.run_detection(target_id)
    # Roll back any in-memory flag updates — this endpoint is read-only
    db.rollback()
    signals = report["signals"]

    grouped: dict[str, list[dict]] = defaultdict(list)
    for sig in signals:
        grouped[sig.get("vuln_type", "unknown")].append(sig)

    return {"target_id": target_id, "signals_by_vuln_type": dict(grouped)}


# ---------------------------------------------------------------------------
# POST /analyze-endpoint/{endpoint_id}
# ---------------------------------------------------------------------------


@router.post("/analyze-endpoint/{endpoint_id}")
def analyze_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    """Analyze a single endpoint and return its detection signals."""
    endpoint = db.get(Endpoint, endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    engine = HeuristicEngine(PatternMatcher())
    signals = engine.analyze_endpoint(endpoint)
    if endpoint.response_headers_json:
        signals.extend(engine.analyze_headers(endpoint))

    return {"endpoint_id": endpoint_id, "signals": signals}


# ---------------------------------------------------------------------------
# POST /analyze-asset/{asset_id}
# ---------------------------------------------------------------------------


@router.post("/analyze-asset/{asset_id}")
def analyze_asset(asset_id: int, db: Session = Depends(get_db)):
    """Analyze a single asset and return its detection signals."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    engine = HeuristicEngine(PatternMatcher())
    signals = engine.analyze_asset(asset)

    return {"asset_id": asset_id, "signals": signals}
