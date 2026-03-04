"""Base interfaces for verification methods."""

from __future__ import annotations

import abc
import dataclasses
from typing import Any


@dataclasses.dataclass
class VerificationResult:
    """Outcome returned by every verifier."""

    # One of: confirmed, unconfirmed, inconclusive, failed
    status: str
    # Structured evidence suitable for JSON serialisation
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    # Free-text human-readable notes
    notes: str = ""


class BaseVerifier(abc.ABC):
    """Abstract base class for all verification methods."""

    @abc.abstractmethod
    def verify(self, target: str, **kwargs: Any) -> VerificationResult:
        """Run the verification and return a :class:`VerificationResult`.

        Parameters
        ----------
        target:
            The host, URL, or other identifier being verified.
        **kwargs:
            Method-specific parameters (e.g., ``expected_cname`` for DNS).

        Returns
        -------
        VerificationResult
        """
