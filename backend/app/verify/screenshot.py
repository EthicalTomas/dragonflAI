"""Screenshot verifier (opt-in, active).

Uses Playwright (headless Chromium) to capture a screenshot and page title
for suspected exposed panels.  This verifier MUST be explicitly enabled via
configuration because it is heavier and more active than passive methods.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from backend.app.verify.base import BaseVerifier, VerificationResult

logger = logging.getLogger(__name__)

# Respect an opt-in environment variable so screenshots cannot be triggered
# accidentally.  Set VERIFY_SCREENSHOT_ENABLED=1 to enable.
_ENABLED_ENV_VAR = "VERIFY_SCREENSHOT_ENABLED"


def _is_enabled() -> bool:
    return os.environ.get(_ENABLED_ENV_VAR, "").strip() == "1"


class ScreenshotVerifier(BaseVerifier):
    """Capture a headless-browser screenshot of a URL.

    Parameters
    ----------
    output_dir:
        Directory in which to save the screenshot PNG.
    timeout_ms:
        Playwright navigation timeout in milliseconds (default 15 000).
    enabled:
        Override the environment-variable check.  ``None`` (default) reads
        ``VERIFY_SCREENSHOT_ENABLED`` from the environment.
    """

    def __init__(
        self,
        output_dir: str = "/tmp/dragonflai_screenshots",
        timeout_ms: int = 15_000,
        enabled: bool | None = None,
    ) -> None:
        self.output_dir = output_dir
        self.timeout_ms = timeout_ms
        self._enabled = enabled

    def _check_enabled(self) -> bool:
        if self._enabled is not None:
            return self._enabled
        return _is_enabled()

    def verify(self, target: str, **kwargs: Any) -> VerificationResult:  # noqa: ARG002
        """Navigate to *target* and capture a screenshot.

        Returns
        -------
        VerificationResult
            ``confirmed``   – screenshot captured successfully.
            ``inconclusive``– verifier disabled, Playwright unavailable, or
                              navigation failed.
        """
        if not self._check_enabled():
            return VerificationResult(
                status="inconclusive",
                evidence={"url": target},
                notes=(
                    f"Screenshot verifier is disabled. "
                    f"Set {_ENABLED_ENV_VAR}=1 to enable."
                ),
            )

        try:
            from playwright.sync_api import sync_playwright  # noqa: PLC0415
        except ImportError:
            logger.warning("ScreenshotVerifier: playwright is not installed")
            return VerificationResult(
                status="inconclusive",
                evidence={"url": target},
                notes="playwright Python package is not installed.",
            )

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        # Derive a safe filename from the target URL
        safe_name = "".join(c if c.isalnum() else "_" for c in target)[:80]
        screenshot_path = str(Path(self.output_dir) / f"{safe_name}.png")

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(target, timeout=self.timeout_ms)
                title = page.title()
                page.screenshot(path=screenshot_path, full_page=False)
                browser.close()
        except Exception as exc:
            logger.warning("ScreenshotVerifier: error for %r: %s", target, exc)
            return VerificationResult(
                status="inconclusive",
                evidence={"url": target, "error": str(exc)},
                notes="Navigation or screenshot capture failed.",
            )

        return VerificationResult(
            status="confirmed",
            evidence={
                "url": target,
                "title": title,
                "screenshot_path": screenshot_path,
            },
            notes=f"Screenshot captured. Page title: {title!r}",
        )
