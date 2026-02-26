"""
Heuristic engine for flagging interesting and potentially vulnerable targets.

Analyzes endpoints and assets using pattern matching and rule-based checks.
No network requests are made — analysis is performed purely on stored data.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.app.detection.patterns import PatternMatcher
    from backend.app.models.asset import Asset
    from backend.app.models.endpoint import Endpoint

logger = logging.getLogger(__name__)

_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_FILE_EXTENSIONS = {".pdf", ".xml", ".txt", ".log", ".php", ".jsp", ".asp"}
_SENSITIVE_KEYWORDS = {"token", "key", "secret", "password", "api_key", "apikey", "access_token"}
_ADMIN_KEYWORDS = {"admin", "dashboard", "panel", "login", "manager"}
_NON_STANDARD_PORTS = {8080, 8443, 9090, 3000, 5000}
_TECH_CHECKS = [
    {"name": "WordPress", "match_key": "wordpress", "hint": "check /wp-admin endpoint"},
    {"name": "Apache Tomcat", "match_key": "apache tomcat", "hint": "check /manager endpoint"},
    {"name": "Jenkins", "match_key": "jenkins", "hint": "check /script endpoint"},
    {"name": "Spring Boot", "match_key": "spring boot", "hint": "check /actuator endpoint"},
]


def _load_json(value: str | None, fallback):
    """Safely parse a JSON string field, returning *fallback* on failure."""
    if value is None:
        return fallback
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        logger.debug("Failed to parse JSON field: %r", value)
        return fallback


class HeuristicEngine:
    """Analyzes endpoints and assets to flag interesting/potentially vulnerable targets."""

    def __init__(self, pattern_matcher: PatternMatcher) -> None:
        self._pm = pattern_matcher

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_endpoint(self, endpoint: Endpoint) -> list[dict]:
        """Run all heuristic checks on a single endpoint and return signals."""
        signals: list[dict] = []
        signals.extend(self._check_params(endpoint))
        signals.extend(self._check_path(endpoint))
        signals.extend(self._check_numeric_ids(endpoint))
        signals.extend(self._check_file_extension_in_params(endpoint))
        signals.extend(self._check_url_in_params(endpoint))
        signals.extend(self._check_sensitive_data_in_url(endpoint))
        signals.extend(self._check_http_method(endpoint))
        return signals

    def analyze_asset(self, asset: Asset) -> list[dict]:
        """Run heuristic checks on an asset and return signals."""
        signals: list[dict] = []
        signals.extend(self._check_missing_https(asset))
        signals.extend(self._check_non_standard_ports(asset))
        signals.extend(self._check_admin_panel(asset))
        signals.extend(self._check_tech_stack(asset))
        signals.extend(self._check_asset_status_code(asset))
        return signals

    def analyze_headers(self, endpoint: Endpoint) -> list[dict]:
        """Check response headers for missing security headers and dangerous values."""
        signals: list[dict] = []
        headers = _load_json(endpoint.response_headers_json, None)
        if not headers:
            return signals
        try:
            raw_signals = self._pm.check_headers(headers)
        except Exception:
            logger.debug("PatternMatcher.check_headers() raised an exception", exc_info=True)
            return signals
        for raw in raw_signals or []:
            signals.append(self._enrich(raw, endpoint_id=endpoint.id))
        return signals

    def analyze_batch(
        self,
        endpoints: list[Endpoint],
        assets: list[Asset],
    ) -> list[dict]:
        """Run all checks on all endpoints and assets, deduplicate, and sort results."""
        signals: list[dict] = []

        for ep in endpoints:
            signals.extend(self.analyze_endpoint(ep))
            if ep.response_headers_json:
                signals.extend(self.analyze_headers(ep))

        for asset in assets:
            signals.extend(self.analyze_asset(asset))

        signals = _deduplicate(signals)
        signals.sort(key=lambda s: (
            _CONFIDENCE_ORDER.get(s.get("confidence", "low"), 99),
            _SEVERITY_ORDER.get(s.get("severity_hint", "info"), 99),
        ))
        return signals

    # ------------------------------------------------------------------
    # Endpoint heuristics
    # ------------------------------------------------------------------

    def _check_params(self, endpoint: Endpoint) -> list[dict]:
        """Check each parameter name via PatternMatcher.match_params()."""
        signals: list[dict] = []
        params = _load_json(endpoint.params_json, [])
        if not params:
            return signals
        try:
            raw_signals = self._pm.match_params(params)
        except Exception:
            logger.debug("PatternMatcher.match_params() raised an exception", exc_info=True)
            return signals
        for raw in raw_signals or []:
            signals.append(self._enrich(raw, endpoint_id=endpoint.id))
        return signals

    def _check_path(self, endpoint: Endpoint) -> list[dict]:
        """Check the endpoint path via PatternMatcher.match_path()."""
        signals: list[dict] = []
        path = endpoint.path
        if not path:
            return signals
        try:
            raw_signals = self._pm.match_path(path)
        except Exception:
            logger.debug("PatternMatcher.match_path() raised an exception", exc_info=True)
            return signals
        for raw in raw_signals or []:
            signals.append(self._enrich(raw, endpoint_id=endpoint.id))
        return signals

    def _check_numeric_ids(self, endpoint: Endpoint) -> list[dict]:
        """Flag parameters with purely numeric values as potential IDOR."""
        signals: list[dict] = []
        params = _load_json(endpoint.params_json, [])
        for param in params:
            name = param.get("name", "") if isinstance(param, dict) else ""
            value = str(param.get("value", "")) if isinstance(param, dict) else ""
            if value.isdigit():
                # Multi-digit IDs are more likely to be database row IDs (higher IDOR signal);
                # single-digit values may just be flags or boolean-like parameters.
                confidence = "medium" if len(value) > 1 else "low"
                signals.append(self._enrich(
                    {
                        "type": "numeric_id_param",
                        "detail": (
                            f"Parameter '{name}' has a numeric value — "
                            "suggests potential IDOR vulnerability"
                        ),
                        "vuln_type": "idor",
                        "severity_hint": "medium",
                        "confidence": confidence,
                    },
                    endpoint_id=endpoint.id,
                ))
        return signals

    def _check_file_extension_in_params(self, endpoint: Endpoint) -> list[dict]:
        """Flag parameters containing file extensions as potential LFI."""
        signals: list[dict] = []
        params = _load_json(endpoint.params_json, [])
        for param in params:
            if not isinstance(param, dict):
                continue
            name = param.get("name", "")
            value = str(param.get("value", ""))
            for ext in _FILE_EXTENSIONS:
                if ext in value.lower():
                    signals.append(self._enrich(
                        {
                            "type": "file_extension_in_param",
                            "detail": (
                                f"Parameter '{name}' value contains a file extension ('{ext}') — "
                                "suggests potential LFI vulnerability"
                            ),
                            "vuln_type": "lfi",
                            "severity_hint": "high",
                            "confidence": "medium",
                        },
                        endpoint_id=endpoint.id,
                    ))
                    break
        return signals

    def _check_url_in_params(self, endpoint: Endpoint) -> list[dict]:
        """Flag parameters whose values look like URLs as potential SSRF or open redirect."""
        signals: list[dict] = []
        params = _load_json(endpoint.params_json, [])
        for param in params:
            if not isinstance(param, dict):
                continue
            name = param.get("name", "")
            value = str(param.get("value", ""))
            if value.startswith(("http://", "https://", "//")):
                signals.append(self._enrich(
                    {
                        "type": "url_in_param",
                        "detail": (
                            f"Parameter '{name}' value looks like a URL — "
                            "suggests potential SSRF or open redirect vulnerability"
                        ),
                        "vuln_type": "ssrf_or_open_redirect",
                        "severity_hint": "high",
                        "confidence": "high",
                    },
                    endpoint_id=endpoint.id,
                ))
        return signals

    def _check_sensitive_data_in_url(self, endpoint: Endpoint) -> list[dict]:
        """Flag sensitive keywords appearing in the URL path or query string."""
        signals: list[dict] = []
        url_lower = (endpoint.url or "").lower()
        path_lower = (endpoint.path or "").lower()
        for keyword in _SENSITIVE_KEYWORDS:
            if keyword in path_lower or keyword in url_lower:
                signals.append(self._enrich(
                    {
                        "type": "sensitive_keyword_in_url",
                        "detail": (
                            f"URL may contain sensitive data (keyword: '{keyword}') — "
                            "suggests potential information disclosure"
                        ),
                        "vuln_type": "information_disclosure",
                        "severity_hint": "high",
                        "confidence": "high",
                    },
                    endpoint_id=endpoint.id,
                ))
                break  # one signal per endpoint is enough
        return signals

    def _check_http_method(self, endpoint: Endpoint) -> list[dict]:
        """Flag write operations (PUT, DELETE) for authorization review."""
        signals: list[dict] = []
        method = (endpoint.method or "").upper()
        if method in {"PUT", "DELETE"}:
            signals.append(self._enrich(
                {
                    "type": "write_method",
                    "detail": (
                        f"Endpoint uses {method} method — "
                        "write operation, may be missing authorization checks"
                    ),
                    "vuln_type": "broken_access_control",
                    "severity_hint": "medium",
                    "confidence": "low",
                },
                endpoint_id=endpoint.id,
            ))
        return signals

    # ------------------------------------------------------------------
    # Asset heuristics
    # ------------------------------------------------------------------

    def _check_missing_https(self, asset: Asset) -> list[dict]:
        """Flag assets that have HTTP (port 80) but not HTTPS (port 443)."""
        ports = set(_load_json(asset.ports_json, []))
        if 80 in ports and 443 not in ports:
            return [self._enrich(
                {
                    "type": "missing_https",
                    "detail": "Asset has port 80 open but not port 443 — no HTTPS detected",
                    "vuln_type": "insecure_transport",
                    "severity_hint": "medium",
                    "confidence": "medium",
                },
                asset_id=asset.id,
            )]
        return []

    def _check_non_standard_ports(self, asset: Asset) -> list[dict]:
        """Flag non-standard service ports for investigation."""
        signals: list[dict] = []
        ports = set(_load_json(asset.ports_json, []))
        for port in _NON_STANDARD_PORTS:
            if port in ports:
                signals.append(self._enrich(
                    {
                        "type": "non_standard_port",
                        "detail": (
                            f"Non-standard service port {port} is open — "
                            "may be a development or admin service, investigate"
                        ),
                        "vuln_type": "attack_surface",
                        "severity_hint": "low",
                        "confidence": "medium",
                    },
                    asset_id=asset.id,
                ))
        return signals

    def _check_admin_panel(self, asset: Asset) -> list[dict]:
        """Flag titles that suggest an admin panel."""
        title = (asset.title or "").lower()
        for keyword in _ADMIN_KEYWORDS:
            if keyword in title:
                return [self._enrich(
                    {
                        "type": "admin_panel",
                        "detail": (
                            f"Page title contains '{keyword}' — "
                            "suggests potential admin panel"
                        ),
                        "vuln_type": "sensitive_exposure",
                        "severity_hint": "high",
                        "confidence": "high",
                    },
                    asset_id=asset.id,
                )]
        return []

    def _check_tech_stack(self, asset: Asset) -> list[dict]:
        """Flag known frameworks/versions that warrant further investigation."""
        signals: list[dict] = []
        techs = _load_json(asset.tech_json, [])
        if not techs:
            return signals
        # Check each tech entry individually to avoid false positives from joining
        tech_strings = [str(t).lower() for t in techs]
        for check in _TECH_CHECKS:
            match_key = check["match_key"]
            if any(match_key in entry for entry in tech_strings):
                signals.append(self._enrich(
                    {
                        "type": "known_technology",
                        "detail": (
                            f"{check['name']} detected — {check['hint']}, "
                            "may expose sensitive functionality"
                        ),
                        "vuln_type": "known_technology_risk",
                        "severity_hint": "medium",
                        "confidence": "medium",
                    },
                    asset_id=asset.id,
                ))
        return signals

    def _check_asset_status_code(self, asset: Asset) -> list[dict]:
        """Flag 401/403 responses as potentially bypassable access restrictions."""
        if asset.status_code in {401, 403}:
            return [self._enrich(
                {
                    "type": "access_restricted",
                    "detail": (
                        f"Asset returns HTTP {asset.status_code} — "
                        "access restricted, may be bypassable"
                    ),
                    "vuln_type": "broken_access_control",
                    "severity_hint": "low",
                    "confidence": "low",
                },
                asset_id=asset.id,
            )]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _enrich(signal: dict, *, endpoint_id: int | None = None, asset_id: int | None = None) -> dict:
        """Ensure required fields are present and attach a reference ID."""
        result = {
            "type": signal.get("type", "unknown"),
            "detail": signal.get("detail", ""),
            "vuln_type": signal.get("vuln_type", "unknown"),
            "severity_hint": signal.get("severity_hint", "info"),
            "confidence": signal.get("confidence", "low"),
        }
        if endpoint_id is not None:
            result["endpoint_id"] = endpoint_id
        if asset_id is not None:
            result["asset_id"] = asset_id
        return result


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _deduplicate(signals: list[dict]) -> list[dict]:
    """Remove duplicate signals based on (type, vuln_type, endpoint_id, asset_id)."""
    seen: set[tuple] = set()
    unique: list[dict] = []
    for sig in signals:
        key = (
            sig.get("type"),
            sig.get("vuln_type"),
            sig.get("endpoint_id"),
            sig.get("asset_id"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(sig)
    return unique
