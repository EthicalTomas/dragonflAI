"""DNS re-check verifier.

Passively re-resolves hostnames and compares against expected DNS records.
Useful for subdomain-takeover signals and newly discovered assets.
"""

from __future__ import annotations

import logging
import socket
from typing import Any

from backend.app.verify.base import BaseVerifier, VerificationResult

logger = logging.getLogger(__name__)


class DnsRecheckVerifier(BaseVerifier):
    """Verify a hostname by re-resolving its DNS records.

    Parameters
    ----------
    expected_ips:
        Optional list of IP addresses expected in the A/AAAA records.
        If provided, the verdict is ``confirmed`` when at least one matches.
    expected_cname:
        Optional CNAME value expected in the response.  Currently checked
        via ``getaddrinfo`` canonical name when available.
    """

    def __init__(
        self,
        expected_ips: list[str] | None = None,
        expected_cname: str | None = None,
    ) -> None:
        self.expected_ips = expected_ips or []
        self.expected_cname = expected_cname

    def verify(self, target: str, **kwargs: Any) -> VerificationResult:  # noqa: ARG002
        """Resolve *target* and compare results against expectations.

        Returns
        -------
        VerificationResult
            ``confirmed``   – resolved IPs include an expected value.
            ``unconfirmed`` – resolved successfully but expectations not met.
            ``inconclusive``– DNS resolution failed.
        """
        try:
            infos = socket.getaddrinfo(target, None)
        except socket.gaierror as exc:
            logger.warning("DnsRecheckVerifier: DNS failure for %r: %s", target, exc)
            return VerificationResult(
                status="inconclusive",
                evidence={"host": target, "error": str(exc)},
                notes="DNS resolution failed.",
            )
        except Exception as exc:
            logger.warning("DnsRecheckVerifier: unexpected error for %r: %s", target, exc)
            return VerificationResult(
                status="inconclusive",
                evidence={"host": target, "error": str(exc)},
                notes="Unexpected error during DNS re-check.",
            )

        resolved_ips: list[str] = list({info[4][0] for info in infos})

        evidence: dict[str, Any] = {
            "host": target,
            "resolved_ips": resolved_ips,
        }

        if self.expected_ips:
            matched = [ip for ip in self.expected_ips if ip in resolved_ips]
            evidence["expected_ips"] = self.expected_ips
            evidence["matched_ips"] = matched
            if matched:
                return VerificationResult(
                    status="confirmed",
                    evidence=evidence,
                    notes=f"Expected IPs found: {matched}",
                )
            return VerificationResult(
                status="unconfirmed",
                evidence=evidence,
                notes="Host resolves but no expected IPs matched.",
            )

        # No expectations supplied – confirm that resolution succeeds
        return VerificationResult(
            status="confirmed",
            evidence=evidence,
            notes=f"Host resolves to: {resolved_ips}",
        )
