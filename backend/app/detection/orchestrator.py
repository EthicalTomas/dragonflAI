"""
Detection Orchestrator — drives the heuristic engine over stored endpoint and asset data.

No network calls are made; all analysis is performed on data already in the database.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy.orm import Session

from backend.app.detection.heuristics import HeuristicEngine
from backend.app.detection.patterns import PatternMatcher
from backend.app.models import Asset, Endpoint, Finding, FindingStatus

logger = logging.getLogger(__name__)

_CONFIDENCE_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}
_MAX_INTERESTING_REASONS = 3
_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}


class DetectionOrchestrator:
    """Orchestrates heuristic detection over stored endpoints and assets."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self._engine = HeuristicEngine(PatternMatcher())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_detection(self, target_id: int, run_id: int | None = None) -> dict:
        """Analyze all endpoints and assets for *target_id* and return a report dict.

        Flags interesting endpoints in the database when signals are found.
        No external network calls are made — analysis is read-only on stored data.
        """
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == target_id).all()
        assets = self.db.query(Asset).filter(Asset.target_id == target_id).all()

        signals = self._engine.analyze_batch(endpoints, assets)

        # Collect reasons per endpoint/asset so we can update the is_interesting flag
        ep_reasons: dict[int, list[str]] = defaultdict(list)
        asset_reasons: dict[int, list[str]] = defaultdict(list)
        for sig in signals:
            if "endpoint_id" in sig:
                ep_reasons[sig["endpoint_id"]].append(sig["detail"])
            if "asset_id" in sig:
                asset_reasons[sig["asset_id"]].append(sig["detail"])

        for ep in endpoints:
            if ep.id in ep_reasons:
                ep.is_interesting = True
                ep.interesting_reason = "; ".join(ep_reasons[ep.id][:_MAX_INTERESTING_REASONS])

        logger.info(
            "Detection run: target_id=%d run_id=%s endpoints=%d assets=%d signals=%d",
            target_id,
            run_id,
            len(endpoints),
            len(assets),
            len(signals),
        )

        return {
            "target_id": target_id,
            "run_id": run_id,
            "endpoints_analyzed": len(endpoints),
            "assets_analyzed": len(assets),
            "signals_found": len(signals),
            "endpoints_flagged": len(ep_reasons),
            "assets_flagged": len(asset_reasons),
            "signals": signals,
        }

    def auto_create_findings(
        self,
        target_id: int,
        signals: list[dict],
        min_confidence: str,
    ) -> tuple[int, list[int]]:
        """Create draft findings from *signals* that meet *min_confidence*.

        All findings are created with status=draft. Returns (count, list_of_ids).
        """
        min_rank = _CONFIDENCE_RANK.get(min_confidence, 1)

        # Build a lookup so we can attach endpoint URLs to findings
        endpoint_ids = {sig["endpoint_id"] for sig in signals if "endpoint_id" in sig}
        endpoint_id_to_url: dict[int, str] = {}
        if endpoint_ids:
            rows = (
                self.db.query(Endpoint.id, Endpoint.url)
                .filter(Endpoint.id.in_(endpoint_ids))
                .all()
            )
            endpoint_id_to_url = {row.id: row.url for row in rows}

        finding_ids: list[int] = []
        for sig in signals:
            if _CONFIDENCE_RANK.get(sig.get("confidence", "low"), 0) < min_rank:
                continue

            vuln_type = sig.get("vuln_type", "unknown")
            detail = sig.get("detail", "")
            severity = _SEVERITY_MAP.get(sig.get("severity_hint", "low"), "low")
            url = endpoint_id_to_url.get(sig.get("endpoint_id")) if "endpoint_id" in sig else None

            finding = Finding(
                target_id=target_id,
                title=f"[Auto] {vuln_type.replace('_', ' ').title()}: {detail[:120]}",
                vulnerability_type=vuln_type,
                severity=severity,
                status=FindingStatus.DRAFT,
                url=url,
                description=detail,
                steps_to_reproduce=(
                    "Auto-generated from detection signal. Manual verification required."
                ),
                impact=(
                    f"Potential {vuln_type.replace('_', ' ')} vulnerability "
                    "detected by automated analysis."
                ),
            )
            self.db.add(finding)
            self.db.flush()
            finding_ids.append(finding.id)

        logger.info(
            "auto_create_findings: target_id=%d min_confidence=%s created=%d",
            target_id,
            min_confidence,
            len(finding_ids),
        )
        return len(finding_ids), finding_ids
