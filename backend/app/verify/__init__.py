"""Verification package: extensible second-technique proof steps."""

from backend.app.verify.base import BaseVerifier, VerificationResult
from backend.app.verify.http_replay import HttpReplayVerifier
from backend.app.verify.dns_recheck import DnsRecheckVerifier
from backend.app.verify.screenshot import ScreenshotVerifier

__all__ = [
    "BaseVerifier",
    "VerificationResult",
    "HttpReplayVerifier",
    "DnsRecheckVerifier",
    "ScreenshotVerifier",
]
