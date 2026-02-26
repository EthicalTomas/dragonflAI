import datetime
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models import Finding, Target
from backend.app.schemas.finding import FindingCreate, FindingOut, FindingSummary, FindingUpdate

findings_router = APIRouter()


def _to_out(finding: Finding) -> FindingOut:
    return FindingOut(
        id=finding.id,
        target_id=finding.target_id,
        run_id=finding.run_id,
        title=finding.title,
        vulnerability_type=finding.vulnerability_type,
        severity=finding.severity,
        status=finding.status,
        url=finding.url,
        parameter=finding.parameter,
        description=finding.description,
        steps_to_reproduce=finding.steps_to_reproduce,
        impact=finding.impact,
        remediation=finding.remediation,
        evidence_paths=json.loads(finding.evidence_paths_json or "[]"),
        request_response=finding.request_response,
        cvss_score=finding.cvss_score,
        cvss_vector=finding.cvss_vector,
        references=json.loads(finding.references_json or "[]"),
        notes=finding.notes,
        report_markdown=finding.report_markdown,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@findings_router.post("", response_model=FindingOut, status_code=201)
def create_finding(body: FindingCreate, db: Session = Depends(get_db)):
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    finding = Finding(
        target_id=body.target_id,
        run_id=body.run_id,
        title=body.title,
        vulnerability_type=body.vulnerability_type,
        severity=body.severity,
        url=body.url,
        parameter=body.parameter,
        description=body.description,
        steps_to_reproduce=body.steps_to_reproduce,
        impact=body.impact,
        remediation=body.remediation,
        evidence_paths_json=json.dumps(body.evidence_paths),
        request_response=body.request_response,
        cvss_score=body.cvss_score,
        cvss_vector=body.cvss_vector,
        references_json=json.dumps(body.references),
        notes=body.notes,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return _to_out(finding)


@findings_router.get("", response_model=list[FindingSummary])
def list_findings(target_id: int | None = None, run_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(Finding)
    if target_id is not None:
        query = query.filter(Finding.target_id == target_id)
    if run_id is not None:
        query = query.filter(Finding.run_id == run_id)
    return query.order_by(Finding.id.desc()).all()


@findings_router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_out(finding)


@findings_router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, body: FindingUpdate, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = body.model_dump(exclude_unset=True)
    if "evidence_paths" in data:
        finding.evidence_paths_json = json.dumps(data.pop("evidence_paths"))
    if "references" in data:
        finding.references_json = json.dumps(data.pop("references"))
    for key, value in data.items():
        setattr(finding, key, value)
    finding.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(finding)
    return _to_out(finding)
