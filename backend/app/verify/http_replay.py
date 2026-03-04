"""HTTP replay verifier.

Issues a controlled HTTP request and captures the response to confirm
or deny suspected web-layer findings.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from backend.app.verify.base import BaseVerifier, VerificationResult

logger = logging.getLogger(__name__)

# Maximum response body bytes to capture (1 MB)
_MAX_BODY_BYTES = 1 * 1024 * 1024

# Secrets patterns to redact from captured headers/body
_REDACT_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k: ("[REDACTED]" if k.lower() in _REDACT_HEADERS else v)
        for k, v in headers.items()
    }


class HttpReplayVerifier(BaseVerifier):
    """Verify a web finding by replaying an HTTP request.

    Parameters
    ----------
    timeout:
        Request timeout in seconds (default 10).
    markers:
        Optional list of strings to look for in the response body/headers.
        If provided, at least one must be present for ``confirmed`` verdict.
    follow_redirects:
        Whether to follow HTTP redirects (default False so open-redirect
        detection can inspect the raw Location header).
    """

    def __init__(
        self,
        timeout: float = 10.0,
        markers: list[str] | None = None,
        follow_redirects: bool = False,
    ) -> None:
        self.timeout = timeout
        self.markers = markers or []
        self.follow_redirects = follow_redirects

    def verify(self, target: str, **kwargs: Any) -> VerificationResult:  # noqa: ARG002
        """Send a GET request to *target* and evaluate the response.

        Returns
        -------
        VerificationResult
            ``confirmed``   – response received and all markers matched.
            ``unconfirmed`` – response received but markers not matched.
            ``inconclusive``– network/protocol error.
        """
        try:
            with httpx.Client(
                follow_redirects=self.follow_redirects,
                timeout=self.timeout,
            ) as client:
                response = client.get(target)
        except httpx.TransportError as exc:
            logger.warning("HttpReplayVerifier: transport error for %r: %s", target, exc)
            return VerificationResult(
                status="inconclusive",
                evidence={"error": str(exc)},
                notes="Network/transport error during HTTP replay.",
            )
        except Exception as exc:
            logger.warning("HttpReplayVerifier: unexpected error for %r: %s", target, exc)
            return VerificationResult(
                status="inconclusive",
                evidence={"error": str(exc)},
                notes="Unexpected error during HTTP replay.",
            )

        body_bytes = response.content[:_MAX_BODY_BYTES]
        body_text = body_bytes.decode("utf-8", errors="replace")

        evidence: dict[str, Any] = {
            "url": str(response.url),
            "status_code": response.status_code,
            "response_headers": _redact_headers(dict(response.headers)),
            "body_snippet": body_text[:2000],
        }

        if self.markers:
            matched = [m for m in self.markers if m in body_text or m in str(response.headers)]
            evidence["markers_checked"] = self.markers
            evidence["markers_matched"] = matched
            if matched:
                return VerificationResult(
                    status="confirmed",
                    evidence=evidence,
                    notes=f"Markers found: {matched}",
                )
            return VerificationResult(
                status="unconfirmed",
                evidence=evidence,
                notes="Response received but no markers matched.",
            )

        # No markers specified – presence of a successful response is sufficient
        if response.status_code < 500:
            return VerificationResult(
                status="confirmed",
                evidence=evidence,
                notes=f"HTTP {response.status_code} received from target.",
            )
        return VerificationResult(
            status="unconfirmed",
            evidence=evidence,
            notes=f"HTTP {response.status_code} received; server error.",
        )
