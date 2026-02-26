import json
import logging
from collections import defaultdict

from sqlalchemy.orm import Session

from backend.app.detection.heuristics import HeuristicEngine
from backend.app.detection.patterns import PatternMatcher
from backend.app.models.asset import Asset
from backend.app.models.endpoint import Endpoint
from backend.app.models.finding import Finding

logger = logging.getLogger(__name__)

_IMPACT_MAP: dict[str, str] = {
    "rce": "Remote code execution could allow an attacker to fully compromise the server.",
    "ssti": "Server-side template injection may lead to remote code execution.",
    "sqli": "SQL injection could expose or corrupt database contents.",
    "lfi": "Local file inclusion may expose sensitive server files.",
    "ssrf": "Server-side request forgery could allow access to internal services.",
    "xss": "Cross-site scripting could allow session hijacking and data theft.",
    "open_redirect": "Open redirect can be used in phishing attacks.",
    "idor": "Insecure direct object reference may expose other users' data.",
    "admin_panel": "Exposed admin panel increases the attack surface significantly.",
    "no_https": "Lack of HTTPS exposes data in transit to interception.",
    "sensitive_path": "Sensitive path exposure may reveal internal functionality or data.",
    "tech_disclosure": "Technology disclosure aids attackers in targeting known vulnerabilities.",
    "debug_enabled": "Debug mode enabled in production can expose sensitive information.",
    "cors_wildcard": "Wildcard CORS policy may allow cross-origin data leakage.",
    "missing_security_header": (
        "Missing security headers reduce defense-in-depth and browser protections."
    ),
}


class DetectionOrchestrator:
    def __init__(self, db: Session) -> None:
        self.db = db
        self._pattern_matcher = PatternMatcher()
        self._heuristic_engine = HeuristicEngine()

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def run_detection(self, target_id: int, run_id: int | None = None) -> dict:
        """Run heuristic detection for *target_id*, optionally scoped to *run_id*.

        Does **not** commit — the caller is responsible for committing.
        """
        # Load assets
        asset_query = self.db.query(Asset).filter(Asset.target_id == target_id)
        if run_id is not None:
            asset_query = asset_query.filter(Asset.run_id == run_id)
        assets: list[Asset] = asset_query.all()

        # Load endpoints
        endpoint_query = self.db.query(Endpoint).filter(Endpoint.target_id == target_id)
        if run_id is not None:
            endpoint_query = endpoint_query.filter(Endpoint.run_id == run_id)
        endpoints: list[Endpoint] = endpoint_query.all()

        logger.info(
            "run_detection: target_id=%d run_id=%s → %d endpoints, %d assets",
            target_id,
            run_id,
            len(endpoints),
            len(assets),
        )

        signals = self._heuristic_engine.analyze_batch(endpoints, assets)

        # Build id → object maps for O(1) lookup
        endpoint_map: dict[int, Endpoint] = {ep.id: ep for ep in endpoints}
        asset_map: dict[int, Asset] = {a.id: a for a in assets}

        flagged_endpoint_ids: set[int] = set()
        flagged_asset_ids: set[int] = set()

        for signal in signals:
            ep_id = signal.get("endpoint_id")
            if ep_id is not None and ep_id in endpoint_map:
                ep = endpoint_map[ep_id]
                detail = signal.get("detail", "")
                if not ep.is_interesting:
                    ep.is_interesting = True
                    ep.interesting_reason = detail
                else:
                    # Append to existing reason — do not overwrite
                    if ep.interesting_reason:
                        ep.interesting_reason = ep.interesting_reason + "; " + detail
                    else:
                        ep.interesting_reason = detail
                flagged_endpoint_ids.add(ep_id)

            asset_id = signal.get("asset_id")
            if asset_id is not None and asset_id in asset_map:
                asset = asset_map[asset_id]
                tag = signal.get("tag")
                if tag:
                    try:
                        tags: list = json.loads(asset.tags_json or "[]")
                    except (json.JSONDecodeError, TypeError):
                        tags = []
                    if tag not in tags:
                        tags.append(tag)
                        asset.tags_json = json.dumps(tags)
                    flagged_asset_ids.add(asset_id)

        # Aggregate report metrics
        signals_by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        signals_by_vuln_type: dict[str, int] = defaultdict(int)
        high_confidence_signals: list[dict] = []

        for signal in signals:
            conf = signal.get("confidence", "low")
            if conf in signals_by_confidence:
                signals_by_confidence[conf] += 1
            vuln_type = signal.get("vuln_type", "unknown")
            signals_by_vuln_type[vuln_type] += 1
            if conf == "high":
                high_confidence_signals.append(signal)

        return {
            "target_id": target_id,
            "run_id": run_id,
            "total_signals": len(signals),
            "signals_by_confidence": signals_by_confidence,
            "signals_by_vuln_type": dict(signals_by_vuln_type),
            "high_confidence_signals": high_confidence_signals,
            "all_signals": signals,
            "endpoints_flagged": len(flagged_endpoint_ids),
            "assets_flagged": len(flagged_asset_ids),
        }

    def run_detection_on_endpoint(self, endpoint_id: int) -> list[dict]:
        """Run heuristic analysis on a single endpoint and return its signals."""
        endpoint: Endpoint | None = self.db.get(Endpoint, endpoint_id)
        if endpoint is None:
            logger.warning(
                "run_detection_on_endpoint: endpoint_id=%d not found", endpoint_id
            )
            return []
        return self._heuristic_engine.analyze_batch([endpoint], [])

    def run_detection_on_asset(self, asset_id: int) -> list[dict]:
        """Run heuristic analysis on a single asset and return its signals."""
        asset: Asset | None = self.db.get(Asset, asset_id)
        if asset is None:
            logger.warning(
                "run_detection_on_asset: asset_id=%d not found", asset_id
            )
            return []
        return self._heuristic_engine.analyze_batch([], [asset])

    def auto_create_findings(
        self,
        target_id: int,
        signals: list[dict],
        min_confidence: str = "medium",
    ) -> list[Finding]:
        """Create draft ``Finding`` objects for signals at or above *min_confidence*.

        Does **not** commit — the caller is responsible for committing.

        .. warning::
            All created findings have ``status="draft"``.  They are **NOT**
            confirmed vulnerabilities.  The user **MUST** review and verify
            each one manually before submission.
        """
        if min_confidence == "high":
            allowed_confidences = {"high"}
        else:
            allowed_confidences = {"high", "medium"}

        findings: list[Finding] = []

        for signal in signals:
            if signal.get("confidence") not in allowed_confidences:
                continue

            vuln_type: str = signal.get("vuln_type", "unknown")
            detail: str = signal.get("detail", "")
            severity: str = signal.get("severity_hint", "medium")
            url: str | None = signal.get("url")
            param: str | None = signal.get("param")

            title = (
                f"[Auto-detected] {detail}"
                if detail
                else f"[Auto-detected] {vuln_type.upper()} finding"
            )

            description = (
                f"{detail}\n\n"
                "⚠️ This finding was auto-generated by heuristic detection. "
                "Manual verification is required before submission."
            )

            impact = _IMPACT_MAP.get(
                vuln_type,
                "This vulnerability may impact the security of the application.",
            )

            if url:
                steps = (
                    f"1. Navigate to {url}\n"
                    f"2. Observe {detail}\n"
                    "3. [Manual verification required]"
                )
            else:
                steps = (
                    "1. Locate the affected resource\n"
                    f"2. Observe {detail}\n"
                    "3. [Manual verification required]"
                )

            finding = Finding(
                target_id=target_id,
                title=title,
                vulnerability_type=vuln_type,
                severity=severity,
                status="draft",
                url=url,
                parameter=param,
                description=description,
                steps_to_reproduce=steps,
                impact=impact,
            )
            self.db.add(finding)
            findings.append(finding)
            logger.debug(
                "auto_create_findings: draft finding '%s' (vuln_type=%s, confidence=%s)",
                title,
                vuln_type,
                signal.get("confidence"),
            )

        logger.info(
            "auto_create_findings: target_id=%d → %d draft findings created",
            target_id,
            len(findings),
        )
        return findings
