"""Vulnerability-type-aware verification router.

Routes verification to the appropriate strategy based on the finding's
``vulnerability_type``, Nuclei template tags, or title heuristics (in that
priority order).  Each strategy applies finding-specific proof logic and
defaults to ``inconclusive`` when proof is weak.
"""

from __future__ import annotations

import logging
import re
import socket
import time
import urllib.parse
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from backend.app.verify.base import VerificationResult
from backend.app.verify.http_replay import _MAX_BODY_BYTES, _redact_headers

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Canary (unresolvable) domain used as open-redirect payload
_REDIRECT_CANARY = "dragonflai-verify.invalid"

# Common parameter names used in open-redirect vulnerabilities
_REDIRECT_PARAMS = (
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnTo",
    "return_url",
    "next",
    "url",
    "goto",
    "dest",
    "destination",
    "redir",
    "target",
    "link",
)

# Known subdomain-takeover fingerprints: (provider_name, body_substring)
_TAKEOVER_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("GitHub Pages", "There isn't a GitHub Pages site here"),
    ("Heroku", "No such app"),
    ("Shopify", "Sorry, this shop is currently unavailable"),
    ("Fastly", "Fastly error: unknown domain"),
    ("Pantheon", "The gods are wise"),
    ("AWS S3", "NoSuchBucket"),
    ("Cargo", "If you're moving your domain away from Cargo"),
    ("Tumblr", "There's nothing here"),
    ("WP Engine", "The site you were looking for couldn't be found"),
    ("Surge", "project not found"),
    ("Bitbucket", "Repository not found"),
    ("UserVoice", "This UserVoice subdomain is currently available"),
    ("Ghost", "The thing you were looking for is no longer here"),
    ("Zendesk", "Help Center Closed"),
    ("Desk", "Please try again or try Desk.com free for 14 days"),
    ("Acquia", "Web Site Not Found"),
    ("ReadMe", "Project doesnt exist"),
    ("Feedpress", "The feed has not been found"),
)

# Regex patterns that indicate an admin/sensitive panel in response body
_ADMIN_PATTERNS: tuple[str, ...] = (
    r"<title>[^<]*(admin|dashboard|control\s+panel|management console|administrator)[^<]*</title>",
    r"(admin\s+panel|administration|administrator login|dashboard overview|control center)",
)

# Harmless marker used for XSS reflection probing
_XSS_MARKER = "dragonflai-xss-probe-7f3a9b"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _classify(
    vulnerability_type: str | None,
    title: str | None,
    tags: list[str] | None,
) -> str:
    """Classify a finding into a verification strategy name.

    Returns one of: ``open_redirect``, ``reflected_xss``, ``sensitive_file``,
    ``takeover``, or ``generic``.

    Priority: vulnerability_type > tags > title.
    """
    vtype = (vulnerability_type or "").lower()
    ttags = [t.lower() for t in (tags or [])]
    ttitle = (title or "").lower()

    # Phase 1: vulnerability_type (highest priority – explicit classification)
    if vtype:
        if "redirect" in vtype or "open-redirect" in vtype:
            return "open_redirect"
        if "xss" in vtype or "cross-site scripting" in vtype:
            return "reflected_xss"
        if "takeover" in vtype or "subdomain" in vtype:
            return "takeover"
        if any(k in vtype for k in ("exposure", "disclosure", "admin", "panel", "sensitive")):
            return "sensitive_file"
        # vtype present but unrecognised; fall through for richer tag/title signal

    # Phase 2: Nuclei template tags
    if "open-redirect" in ttags or "open_redirect" in ttags:
        return "open_redirect"
    if "xss" in ttags:
        return "reflected_xss"
    if "takeover" in ttags or "subdomain-takeover" in ttags:
        return "takeover"
    if any(k in ttags for k in ("exposure", "admin", "panel", "disclosure")):
        return "sensitive_file"

    # Phase 3: title heuristics (last resort)
    if "open redirect" in ttitle or "redirect" in ttitle:
        return "open_redirect"
    if "xss" in ttitle or "cross-site scripting" in ttitle or "reflected" in ttitle:
        return "reflected_xss"
    if "takeover" in ttitle or "subdomain takeover" in ttitle:
        return "takeover"
    if any(k in ttitle for k in ("admin", "panel", "exposed", "login page", "sensitive", "disclosure")):
        return "sensitive_file"

    return "generic"


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


class VulnRouter:
    """Route HTTP verification to a per-vulnerability-type strategy.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds (default 10).
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(
        self,
        url: str,
        vulnerability_type: str | None = None,
        title: str | None = None,
        tags: list[str] | None = None,
    ) -> VerificationResult:
        """Select and execute the right verification strategy.

        Parameters
        ----------
        url:
            Full URL of the finding being verified.
        vulnerability_type:
            Canonical vulnerability type (e.g. ``"Open Redirect"``).
        title:
            Finding title used as a secondary classification signal.
        tags:
            Nuclei template tags or other metadata tags.

        Returns
        -------
        VerificationResult
            Conservative verdict: ``confirmed`` only when strong evidence is
            collected, ``inconclusive`` when proof is weak or ambiguous.
        """
        category = _classify(vulnerability_type, title, tags)
        logger.info(
            "VulnRouter: url=%r category=%r (vuln_type=%r title=%r tags=%r)",
            url,
            category,
            vulnerability_type,
            title,
            tags,
        )

        dispatch = {
            "open_redirect": self._verify_open_redirect,
            "reflected_xss": self._verify_reflected_xss,
            "sensitive_file": self._verify_sensitive_file,
            "takeover": self._verify_takeover,
            "generic": self._verify_generic,
        }
        return dispatch[category](url)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get(
        self,
        url: str,
        *,
        follow_redirects: bool = False,
        extra_params: dict[str, str] | None = None,
    ) -> tuple[httpx.Response | None, float, str | None]:
        """Issue a GET request and return ``(response, elapsed_s, error)``."""
        if extra_params:
            parsed = urlparse(url)
            existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            existing.update({k: [v] for k, v in extra_params.items()})
            new_query = urllib.parse.urlencode(existing, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))

        t0 = time.monotonic()
        try:
            with httpx.Client(follow_redirects=follow_redirects, timeout=self.timeout) as client:
                resp = client.get(url)
            return resp, time.monotonic() - t0, None
        except httpx.TransportError as exc:
            return None, time.monotonic() - t0, str(exc)
        except Exception as exc:
            return None, time.monotonic() - t0, str(exc)

    @staticmethod
    def _resolve_ips(host: str) -> list[str]:
        """Resolve *host* to IP addresses; return empty list on failure."""
        try:
            infos = socket.getaddrinfo(host, None)
            return list({info[4][0] for info in infos})
        except Exception:
            return []

    @staticmethod
    def _body_from(response: httpx.Response) -> tuple[str, bool]:
        """Return ``(body_text, body_truncated)`` for *response*."""
        raw = response.content[:_MAX_BODY_BYTES]
        text = raw.decode("utf-8", errors="replace")
        truncated = len(response.content) > _MAX_BODY_BYTES
        return text, truncated

    def _base_evidence(
        self,
        url: str,
        response: httpx.Response | None,
        elapsed: float,
        *,
        error: str | None = None,
        host: str | None = None,
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "schema_version": 1,
            "method": "GET",
            "final_url": url,
            "elapsed_s": round(elapsed, 3),
        }
        if host:
            evidence["resolved_ips"] = self._resolve_ips(host)
        if error:
            evidence["error"] = error
            return evidence
        if response is not None:
            body_text, body_truncated = self._body_from(response)
            evidence.update(
                {
                    "final_url": str(response.url),
                    "status_code": response.status_code,
                    "response_headers": _redact_headers(dict(response.headers)),
                    "body_snippet": body_text[:2000],
                    "body_truncated": body_truncated,
                }
            )
        return evidence

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    def _verify_open_redirect(self, url: str) -> VerificationResult:
        """Probe for open redirect by injecting an unresolvable canary URL.

        Confirmed only when the ``Location`` response header contains the
        canary domain.
        """
        canary = f"https://{_REDIRECT_CANARY}/"
        parsed = urlparse(url)
        host = parsed.hostname or url
        params_tried: list[str] = []

        for param in _REDIRECT_PARAMS:
            resp, elapsed, error = self._get(
                url,
                follow_redirects=False,
                extra_params={param: canary},
            )
            params_tried.append(param)

            if error or resp is None:
                continue

            location = resp.headers.get("location", "")
            if _REDIRECT_CANARY in location:
                evidence = self._base_evidence(url, resp, elapsed, host=host)
                evidence.update(
                    {
                        "probe_param": param,
                        "canary": canary,
                        "location_header": location,
                        "matched_param": param,
                        "params_tried": params_tried,
                    }
                )
                return VerificationResult(
                    status="confirmed",
                    evidence=evidence,
                    notes=(
                        f"Open redirect confirmed: Location header redirects to {_REDIRECT_CANARY!r} "
                        f"via parameter {param!r}."
                    ),
                )

        # No param triggered a canary redirect
        evidence: dict[str, Any] = {
            "schema_version": 1,
            "method": "GET",
            "final_url": url,
            "canary": canary,
            "params_tried": params_tried,
            "resolved_ips": self._resolve_ips(host),
        }
        return VerificationResult(
            status="inconclusive",
            evidence=evidence,
            notes=(
                "No open redirect confirmed: canary domain not found in Location header "
                f"for any of {len(params_tried)} tested parameters."
            ),
        )

    def _verify_reflected_xss(self, url: str) -> VerificationResult:
        """Probe for reflected XSS by injecting a harmless marker string.

        Confirmed only when the marker appears verbatim in the response body.
        """
        marker = _XSS_MARKER
        parsed = urlparse(url)
        host = parsed.hostname or url

        # Inject marker into common input parameters, preserving any existing query string
        existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        existing.update({"q": [marker], "search": [marker], "input": [marker]})
        probe_query = urllib.parse.urlencode(existing, doseq=True)
        probe_url = urlunparse(parsed._replace(query=probe_query))

        resp, elapsed, error = self._get(probe_url, follow_redirects=True)
        evidence = self._base_evidence(probe_url, resp, elapsed, error=error, host=host)
        evidence["marker"] = marker

        if error or resp is None:
            return VerificationResult(
                status="inconclusive",
                evidence=evidence,
                notes="Transport error during XSS marker probe; cannot confirm.",
            )

        body_text, _ = self._body_from(resp)
        if marker in body_text:
            evidence["marker_reflected"] = True
            return VerificationResult(
                status="confirmed",
                evidence=evidence,
                notes=f"Reflected XSS confirmed: marker {marker!r} found in response body.",
            )

        evidence["marker_reflected"] = False
        return VerificationResult(
            status="unconfirmed",
            evidence=evidence,
            notes=f"Marker {marker!r} not reflected in response body; XSS not confirmed.",
        )

    def _verify_sensitive_file(self, url: str) -> VerificationResult:
        """Verify exposed admin panel or sensitive file.

        Confirmed only when a stable marker (title or body keyword) is present
        in the response.  A bare HTTP 200 is not sufficient evidence.
        """
        parsed = urlparse(url)
        host = parsed.hostname or url

        resp, elapsed, error = self._get(url, follow_redirects=True)
        evidence = self._base_evidence(url, resp, elapsed, error=error, host=host)

        if error or resp is None:
            return VerificationResult(
                status="inconclusive",
                evidence=evidence,
                notes="Transport error; cannot confirm sensitive file exposure.",
            )

        if resp.status_code == 404 or resp.status_code >= 500:
            return VerificationResult(
                status="unconfirmed",
                evidence=evidence,
                notes=f"HTTP {resp.status_code}: resource not accessible; exposure not confirmed.",
            )

        if resp.status_code in (401, 403):
            return VerificationResult(
                status="inconclusive",
                evidence=evidence,
                notes=(
                    f"HTTP {resp.status_code}: resource requires authentication; "
                    "cannot confirm content without bypassing auth."
                ),
            )

        body_text, _ = self._body_from(resp)
        for pattern in _ADMIN_PATTERNS:
            m = re.search(pattern, body_text, re.IGNORECASE)
            if m:
                evidence["matched_pattern"] = pattern
                evidence["matched_text"] = m.group(0)[:200]
                return VerificationResult(
                    status="confirmed",
                    evidence=evidence,
                    notes="Exposed admin/sensitive panel confirmed: stable marker found in response body.",
                )

        # 200 but no stable marker
        return VerificationResult(
            status="inconclusive",
            evidence=evidence,
            notes=(
                f"HTTP {resp.status_code} received but no stable admin/sensitive-file "
                "marker matched; cannot confirm exposure without stronger evidence."
            ),
        )

    def _verify_takeover(self, url: str) -> VerificationResult:
        """Verify subdomain-takeover signals via DNS + HTTP fingerprint.

        Confirmed only when a known provider error-page fingerprint is present.
        """
        parsed = urlparse(url)
        host = parsed.hostname or url

        resolved_ips = self._resolve_ips(host)
        dns_nxdomain = len(resolved_ips) == 0

        evidence: dict[str, Any] = {
            "schema_version": 1,
            "method": "GET",
            "final_url": url,
            "host": host,
            "resolved_ips": resolved_ips,
            "dns_nxdomain": dns_nxdomain,
        }

        if dns_nxdomain:
            return VerificationResult(
                status="inconclusive",
                evidence=evidence,
                notes=(
                    "DNS NXDOMAIN: host does not resolve. "
                    "Possible takeover signal but HTTP fingerprint unavailable."
                ),
            )

        resp, elapsed, error = self._get(url, follow_redirects=True)
        evidence["elapsed_s"] = round(elapsed, 3)

        if error or resp is None:
            evidence["error"] = error or "no response"
            return VerificationResult(
                status="inconclusive",
                evidence=evidence,
                notes="DNS resolved but HTTP request failed; cannot fingerprint provider.",
            )

        body_text, body_truncated = self._body_from(resp)
        evidence.update(
            {
                "status_code": resp.status_code,
                "response_headers": _redact_headers(dict(resp.headers)),
                "body_snippet": body_text[:2000],
                "body_truncated": body_truncated,
            }
        )

        for provider, fingerprint in _TAKEOVER_FINGERPRINTS:
            if fingerprint.lower() in body_text.lower():
                evidence["matched_provider"] = provider
                evidence["matched_fingerprint"] = fingerprint
                return VerificationResult(
                    status="confirmed",
                    evidence=evidence,
                    notes=f"Subdomain takeover confirmed: {provider!r} fingerprint found in response.",
                )

        return VerificationResult(
            status="inconclusive",
            evidence=evidence,
            notes=(
                "DNS resolved and host is HTTP-reachable, but no known takeover "
                "fingerprint matched. Manual review recommended."
            ),
        )

    def _verify_generic(self, url: str) -> VerificationResult:
        """Generic fallback: always ``inconclusive`` without finding-specific proof.

        A plain HTTP response is not sufficient to confirm a vulnerability.
        """
        parsed = urlparse(url)
        host = parsed.hostname or url

        resp, elapsed, error = self._get(url, follow_redirects=True)
        evidence = self._base_evidence(url, resp, elapsed, error=error, host=host)

        if error or resp is None:
            return VerificationResult(
                status="inconclusive",
                evidence=evidence,
                notes="Transport error; cannot verify without vulnerability-specific proof logic.",
            )

        return VerificationResult(
            status="inconclusive",
            evidence=evidence,
            notes=(
                f"HTTP {resp.status_code} received. No vulnerability-specific proof logic "
                "available for this finding type; cannot confirm without markers or a "
                "per-type verification strategy."
            ),
        )
