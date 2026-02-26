import json
import logging

from backend.app.detection.patterns import PatternMatcher
from backend.app.models.asset import Asset
from backend.app.models.endpoint import Endpoint

logger = logging.getLogger(__name__)

# Map vuln_type / issue to a confidence level.
_VULN_CONFIDENCE: dict[str, str] = {
    "rce": "high",
    "ssti": "high",
    "sqli": "high",
    "lfi": "high",
    "ssrf": "high",
    "xss": "medium",
    "open_redirect": "medium",
    "idor": "medium",
    "admin_panel": "medium",
    "sensitive_path": "medium",
    "tech_disclosure": "low",
    "debug_enabled": "low",
    "cors_wildcard": "low",
    "missing_security_header": "low",
}

_ADMIN_PATTERNS: list[str] = [
    "admin",
    "panel",
    "console",
    "dashboard",
    "manage",
    "portal",
    "backoffice",
    "internal",
    "staff",
]


class HeuristicEngine:
    def __init__(self) -> None:
        self._matcher = PatternMatcher()

    # ------------------------------------------------------------------
    # per-object analysis
    # ------------------------------------------------------------------

    def analyze_endpoint(self, endpoint: Endpoint) -> list[dict]:
        signals: list[dict] = []

        # 1. Analyze query / body parameters
        try:
            params: list[dict] = json.loads(endpoint.params_json or "[]")
        except (json.JSONDecodeError, TypeError):
            params = []

        for match in self._matcher.match_params(params):
            vuln_type = match["vuln_type"]
            param_name = match["param"]
            severity = match["severity_hint"]
            confidence = _VULN_CONFIDENCE.get(vuln_type, "low")
            signals.append(
                {
                    "endpoint_id": endpoint.id,
                    "asset_id": None,
                    "confidence": confidence,
                    "vuln_type": vuln_type,
                    "severity_hint": severity,
                    "detail": (
                        f"Parameter '{param_name}' may be vulnerable to {vuln_type.upper()}"
                    ),
                    "url": endpoint.url,
                    "param": param_name,
                    "tag": None,
                }
            )

        # 2. Analyze URL path
        if endpoint.path:
            for match in self._matcher.match_path(endpoint.path):
                signals.append(
                    {
                        "endpoint_id": endpoint.id,
                        "asset_id": None,
                        "confidence": "medium",
                        "vuln_type": "sensitive_path",
                        "severity_hint": "medium",
                        "detail": match["reason"],
                        "url": endpoint.url,
                        "param": None,
                        "tag": None,
                    }
                )

        # 3. Analyze response headers
        if endpoint.response_headers_json:
            try:
                response_headers: dict = json.loads(endpoint.response_headers_json)
            except (json.JSONDecodeError, TypeError):
                response_headers = {}

            if isinstance(response_headers, dict) and response_headers:
                for header_match in self._matcher.check_headers(response_headers):
                    issue = header_match["issue"]
                    header = header_match["header"]
                    if header_match["type"] == "present_bad":
                        detail = f"Response header '{header}' reveals {issue}"
                    else:
                        detail = f"Missing security header: '{header}'"
                    signals.append(
                        {
                            "endpoint_id": endpoint.id,
                            "asset_id": None,
                            "confidence": "low",
                            "vuln_type": issue,
                            "severity_hint": "low",
                            "detail": detail,
                            "url": endpoint.url,
                            "param": None,
                            "tag": None,
                        }
                    )

        return signals

    def analyze_asset(self, asset: Asset) -> list[dict]:
        signals: list[dict] = []

        value_lower = (asset.value or "").lower()

        # 1. Admin-panel detection via hostname patterns
        if any(pattern in value_lower for pattern in _ADMIN_PATTERNS):
            signals.append(
                {
                    "endpoint_id": None,
                    "asset_id": asset.id,
                    "confidence": "medium",
                    "vuln_type": "admin_panel",
                    "severity_hint": "medium",
                    "detail": f"Asset '{asset.value}' appears to expose an admin panel",
                    "url": None,
                    "param": None,
                    "tag": "admin-panel",
                }
            )

        # 2. No-HTTPS detection: port 80 open but not 443
        if asset.ports_json:
            try:
                ports: list = json.loads(asset.ports_json)
            except (json.JSONDecodeError, TypeError):
                ports = []

            port_numbers: set[int] = set()
            for entry in ports:
                if isinstance(entry, dict):
                    try:
                        port_numbers.add(int(entry.get("port", 0)))
                    except (ValueError, TypeError):
                        pass
                elif isinstance(entry, int):
                    port_numbers.add(entry)

            if 80 in port_numbers and 443 not in port_numbers:
                signals.append(
                    {
                        "endpoint_id": None,
                        "asset_id": asset.id,
                        "confidence": "medium",
                        "vuln_type": "no_https",
                        "severity_hint": "medium",
                        "detail": (
                            f"Asset '{asset.value}' serves HTTP (port 80) but not HTTPS (port 443)"
                        ),
                        "url": None,
                        "param": None,
                        "tag": "no-https",
                    }
                )

        return signals

    # ------------------------------------------------------------------
    # batch analysis
    # ------------------------------------------------------------------

    def analyze_batch(
        self,
        endpoints: list[Endpoint],
        assets: list[Asset],
    ) -> list[dict]:
        signals: list[dict] = []

        for endpoint in endpoints:
            try:
                signals.extend(self.analyze_endpoint(endpoint))
            except Exception:
                logger.exception("Error analyzing endpoint id=%s", endpoint.id)

        for asset in assets:
            try:
                signals.extend(self.analyze_asset(asset))
            except Exception:
                logger.exception("Error analyzing asset id=%s", asset.id)

        logger.info(
            "analyze_batch: %d endpoints, %d assets → %d signals",
            len(endpoints),
            len(assets),
            len(signals),
        )
        return signals
