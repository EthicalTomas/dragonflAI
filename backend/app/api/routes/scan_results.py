import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models import Finding, ScanResult
from backend.app.schemas.scan import ScanResultOut

logger = logging.getLogger(__name__)

router = APIRouter()

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "unknown": "informational",
}


@router.get("", response_model=list[ScanResultOut])
def list_scan_results(
    scan_id: int | None = None,
    target_id: int | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(ScanResult)
    if scan_id is not None:
        query = query.filter(ScanResult.scan_id == scan_id)
    if target_id is not None:
        query = query.filter(ScanResult.target_id == target_id)
    if severity is not None:
        query = query.filter(ScanResult.severity == severity)
    return query.order_by(ScanResult.id.desc()).all()


@router.get("/{result_id}", response_model=ScanResultOut)
def get_scan_result(result_id: int, db: Session = Depends(get_db)):
    result = db.get(ScanResult, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return result


@router.post("/{result_id}/promote", response_model=dict, status_code=201)
def promote_scan_result(result_id: int, db: Session = Depends(get_db)):
    """Promote a ScanResult to a Finding for manual review and reporting."""
    result = db.get(ScanResult, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")

    severity = _SEVERITY_MAP.get(result.severity.lower(), "informational")
    title = result.title if len(result.title) >= 5 else f"[{result.tool}] {result.title}"
    if len(title) > 200:
        title = title[:200]

    template_info = f"Template: {result.template_id}. " if result.template_id else ""
    url_info = f"URL: {result.matched_url}. " if result.matched_url else ""
    description = (
        f"Automatically promoted from scanner result. "
        f"{template_info}"
        f"{url_info}"
        f"Tool: {result.tool}. Severity: {severity}. "
        f"⚠️ Requires manual verification before submission."
    )

    steps_to_reproduce = (
        f"1. Review scanner evidence in scan result #{result_id}.\n"
        f"2. Manually verify the finding at {result.matched_url or 'the target URL'}.\n"
        f"3. Document reproduction steps after verification."
    )

    impact = (
        f"To be assessed — see scanner result #{result_id} for initial evidence."
    )

    try:
        evidence = json.loads(result.evidence_json or "{}")
        evidence_notes = json.dumps(evidence, indent=2) if evidence else ""
    except (json.JSONDecodeError, TypeError):
        evidence_notes = result.evidence_json or ""

    notes = (
        f"Promoted from ScanResult #{result_id} (scan #{result.scan_id}). "
        f"⚠️ Scanner results require manual verification before submission.\n"
        + (f"\nEvidence:\n{evidence_notes}" if evidence_notes else "")
    )

    finding = Finding(
        target_id=result.target_id,
        run_id=result.run_id,
        title=title,
        vulnerability_type=result.template_id or result.tool or "Other",
        severity=severity,
        url=result.matched_url,
        description=description,
        steps_to_reproduce=steps_to_reproduce,
        impact=impact,
        notes=notes,
        evidence_paths_json="[]",
        references_json="[]",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    logger.info(
        "Promoted scan_result id=%s to finding id=%s", result_id, finding.id
    )
    return {"finding_id": finding.id, "scan_result_id": result_id}
