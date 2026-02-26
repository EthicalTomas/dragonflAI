import datetime
import json
import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import case

from backend.app.db.session import get_db
from backend.app.models import Finding, Run, Target
from backend.app.reports.cvss import calculate_cvss_score, cvss_to_severity
from backend.app.reports.generator import ReportGenerator
from backend.app.llm.null_provider import NullLLMProvider
from backend.app.schemas.finding import FindingCreate, FindingOut, FindingSummary, FindingUpdate

logger = logging.getLogger(__name__)

router = APIRouter()


class _BatchReportRequest(BaseModel):
    finding_ids: list[int]
    template: str = "summary"

_SEVERITY_ORDER = case(
    (Finding.severity == "critical", 0),
    (Finding.severity == "high", 1),
    (Finding.severity == "medium", 2),
    (Finding.severity == "low", 3),
    else_=4,
)

_VALID_TEMPLATES = {"full", "summary", "platform"}
_VALID_FORMATS = {"markdown", "txt"}
_FORMAT_EXT = {"markdown": "md", "txt": "txt"}


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


@router.post("", response_model=FindingOut, status_code=201)
def create_finding(body: FindingCreate, db: Session = Depends(get_db)):
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    if body.run_id is not None and not db.get(Run, body.run_id):
        raise HTTPException(status_code=404, detail="Run not found")

    cvss_score = body.cvss_score
    cvss_vector = body.cvss_vector
    severity = body.severity

    if cvss_vector is not None and cvss_score is None:
        try:
            cvss_score = calculate_cvss_score(cvss_vector)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid CVSS vector: {exc}") from exc

    if cvss_score is not None:
        severity = cvss_to_severity(cvss_score)

    finding = Finding(
        target_id=body.target_id,
        run_id=body.run_id,
        title=body.title,
        vulnerability_type=body.vulnerability_type,
        severity=severity,
        url=body.url,
        parameter=body.parameter,
        description=body.description,
        steps_to_reproduce=body.steps_to_reproduce,
        impact=body.impact,
        remediation=body.remediation,
        evidence_paths_json=json.dumps(body.evidence_paths),
        request_response=body.request_response,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        references_json=json.dumps(body.references),
        notes=body.notes,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    logger.info("Created finding id=%s target_id=%s", finding.id, finding.target_id)
    return _to_out(finding)


@router.get("", response_model=list[FindingSummary])
def list_findings(
    target_id: int | None = None,
    run_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Finding)
    if target_id is not None:
        query = query.filter(Finding.target_id == target_id)
    if run_id is not None:
        query = query.filter(Finding.run_id == run_id)
    if severity is not None:
        query = query.filter(Finding.severity == severity)
    if status is not None:
        query = query.filter(Finding.status == status)
    findings = query.order_by(_SEVERITY_ORDER, Finding.created_at.desc()).all()
    return findings


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_out(finding)


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, body: FindingUpdate, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = body.model_dump(exclude_none=True)

    if "evidence_paths" in update_data:
        update_data["evidence_paths_json"] = json.dumps(update_data.pop("evidence_paths"))
    if "references" in update_data:
        update_data["references_json"] = json.dumps(update_data.pop("references"))

    cvss_score = update_data.get("cvss_score", finding.cvss_score)

    if "cvss_vector" in update_data:
        try:
            cvss_score = calculate_cvss_score(update_data["cvss_vector"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid CVSS vector: {exc}") from exc
        update_data["cvss_score"] = cvss_score

    if cvss_score is not None:
        update_data["severity"] = cvss_to_severity(cvss_score)

    update_data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    for field, value in update_data.items():
        setattr(finding, field, value)

    db.commit()
    db.refresh(finding)
    logger.info("Updated finding id=%s", finding.id)
    return _to_out(finding)


@router.post("/{finding_id}/generate-report")
def generate_report(
    finding_id: int,
    template: str = Query(default="full"),
    db: Session = Depends(get_db),
):
    if template not in _VALID_TEMPLATES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid template. Must be one of: {', '.join(sorted(_VALID_TEMPLATES))}",
        )
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    generator = ReportGenerator(NullLLMProvider())
    report_markdown = generator.generate_report(finding, template_name=template)

    finding.report_markdown = report_markdown
    db.commit()
    logger.info("Generated report for finding id=%s template=%s", finding.id, template)
    return {"finding_id": finding.id, "template": template, "report_markdown": report_markdown}


@router.get("/{finding_id}/export")
def export_report(
    finding_id: int,
    format: str = Query(default="markdown"),
    db: Session = Depends(get_db),
):
    if format not in _VALID_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format. Must be one of: {', '.join(sorted(_VALID_FORMATS))}",
        )
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not finding.report_markdown:
        raise HTTPException(status_code=400, detail="Generate a report first.")

    ext = _FORMAT_EXT[format]
    output_path = f"artifacts/{finding.target_id}/reports/{finding_id}.{ext}"
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    generator = ReportGenerator(NullLLMProvider())
    final_path = generator.export_report(finding.report_markdown, output_path, format=format)
    logger.info("Exported report for finding id=%s format=%s path=%s", finding.id, format, final_path)

    media_type = "text/markdown" if format == "markdown" else "text/plain"
    return FileResponse(path=final_path, media_type=media_type, filename=os.path.basename(final_path))


@router.post("/batch-report")
def batch_report(body: _BatchReportRequest, db: Session = Depends(get_db)):
    finding_ids = body.finding_ids
    template = body.template

    if not finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids must not be empty")

    if template not in _VALID_TEMPLATES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid template. Must be one of: {', '.join(sorted(_VALID_TEMPL## Task
Write the file `ui/pages/8_Reports.py` for the dragonflAI project.

## Requirements
- Streamlit page dedicated to viewing and exporting generated reports.

**Section 1: Single Report Viewer**
- Number input for finding ID.
- "Load Report" button.
- If the finding has a `report_markdown`:
  - Display it as rendered Markdown using `st.markdown()`.
  - Show a "View Raw Markdown" toggle that shows the raw text in a code block.
  - Download buttons: Markdown (.md), Plain Text (.txt).
- If no report exists, show a warning: "No report generated yet. Go to the Findings page to generate one."

**Section 2: Batch Report Dashboard**
- Fetch all findings with `GET /findings`.
- Show summary statistics:
  - Total findings by severity (use `st.metric()` widgets in columns).
  - Total findings by status.
- "Generate Full Assessment Report" button:
  - Sends all finding IDs to `POST /findings/batch-report`.
  - Displays the combined report.
  - Download button for the combined report.

**Section 3: Report History**
- List all findings that have `report_markdown` not empty.
- Display as a table: ID, Title, Severity, Template used, Generated date.
- Click to view any report.

## Reminders
- Use `st.columns()` for the severity metrics dashboard.
- Use `st.tabs()` to separate the three sections.
- Wrap API calls in try/except.
- For downloads, use `st.download_button(data=report_bytes, file_name=..., mime=...)`.
- No print statements.
- Output ONLY the file content, no explanation.ATES))}",
        )

    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
    found_ids = {f.id for f in findings}
    missing = [fid for fid in finding_ids if fid not in found_ids]
    if missing:
        raise HTTPException(status_code=404, detail=f"Findings not found: {missing}")

    generator = ReportGenerator(NullLLMProvider())
    report_markdown = generator.generate_batch_report(findings, template_name=template)
    logger.info("Generated batch report for %d findings", len(findings))
    return {"report_markdown": report_markdown}

