import json
import logging

from sqlalchemy.orm import Session

from backend.app.models import Finding, Run

logger = logging.getLogger(__name__)


class RunDiffer:
    @staticmethod
    def get_previous_run(db: Session, run: Run) -> Run | None:
        return (
            db.query(Run)
            .filter(Run.target_id == run.target_id, Run.id < run.id)
            .order_by(Run.id.desc())
            .first()
        )

    @staticmethod
    def diff_full(db: Session, run_a: Run, run_b: Run) -> dict:
        findings_a = db.query(Finding).filter(Finding.run_id == run_a.id).all()
        findings_b = db.query(Finding).filter(Finding.run_id == run_b.id).all()

        def _key(f: Finding) -> tuple:
            return (f.title, f.url, f.parameter)

        map_a = {_key(f): f for f in findings_a}
        map_b = {_key(f): f for f in findings_b}

        def _serialize(f: Finding) -> dict:
            return {
                "id": f.id,
                "target_id": f.target_id,
                "run_id": f.run_id,
                "title": f.title,
                "vulnerability_type": f.vulnerability_type,
                "severity": f.severity,
                "status": f.status,
                "url": f.url,
                "parameter": f.parameter,
                "description": f.description,
                "steps_to_reproduce": f.steps_to_reproduce,
                "impact": f.impact,
                "remediation": f.remediation,
                "evidence_paths": json.loads(f.evidence_paths_json or "[]"),
                "request_response": f.request_response,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "references": json.loads(f.references_json or "[]"),
                "notes": f.notes,
                "created_at": f.created_at,
                "updated_at": f.updated_at,
            }

        new_findings = [_serialize(f) for k, f in map_b.items() if k not in map_a]
        resolved_findings = [_serialize(f) for k, f in map_a.items() if k not in map_b]
        persisted_findings = [_serialize(f) for k, f in map_b.items() if k in map_a]

        logger.info(
            "diff_full run_a=%s run_b=%s new=%d resolved=%d persisted=%d",
            run_a.id,
            run_b.id,
            len(new_findings),
            len(resolved_findings),
            len(persisted_findings),
        )

        return {
            "run_a_id": run_a.id,
            "run_b_id": run_b.id,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "persisted_findings": persisted_findings,
        }
