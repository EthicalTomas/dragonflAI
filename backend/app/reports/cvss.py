import logging
import math

logger = logging.getLogger(__name__)

_AV_VALUES: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_VALUES: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_VALUES_UNCHANGED: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_VALUES_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_VALUES: dict[str, float] = {"N": 0.85, "R": 0.62}
_IMPACT_VALUES: dict[str, float] = {"N": 0.0, "L": 0.22, "H": 0.56}

_VALID_METRICS: dict[str, set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    return math.ceil(value * 10) / 10


def _parse_vector(vector: str) -> dict[str, str]:
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError(f"Invalid CVSS vector prefix; expected 'CVSS:3.1/': {vector!r}")

    parts = vector[len("CVSS:3.1/"):].split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Malformed metric component {part!r} in vector {vector!r}")
        key, _, val = part.partition(":")
        if key in metrics:
            raise ValueError(f"Duplicate metric {key!r} in vector {vector!r}")
        metrics[key] = val

    for metric in _REQUIRED_METRICS:
        if metric not in metrics:
            raise ValueError(f"Missing required metric {metric!r} in vector {vector!r}")
        if metrics[metric] not in _VALID_METRICS[metric]:
            raise ValueError(
                f"Invalid value {metrics[metric]!r} for metric {metric!r} in vector {vector!r}"
            )

    return metrics


def calculate_cvss_score(vector: str) -> float:
    """Calculate the CVSS 3.1 Base Score for the given vector string.

    Raises ValueError for invalid or malformed vectors.
    """
    metrics = _parse_vector(vector)

    scope = metrics["S"]
    av = _AV_VALUES[metrics["AV"]]
    ac = _AC_VALUES[metrics["AC"]]
    pr = (_PR_VALUES_UNCHANGED if scope == "U" else _PR_VALUES_CHANGED)[metrics["PR"]]
    ui = _UI_VALUES[metrics["UI"]]
    conf = _IMPACT_VALUES[metrics["C"]]
    integ = _IMPACT_VALUES[metrics["I"]]
    avail = _IMPACT_VALUES[metrics["A"]]

    iss = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail)

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        logger.debug("Impact sub-score <= 0; returning base score of 0.0")
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope == "U":
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    logger.debug("CVSS vector=%r score=%s", vector, base_score)
    return base_score


def cvss_to_severity(score: float) -> str:
    """Return the CVSS severity label for a given base score."""
    if score == 0.0:
        return "informational"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def validate_cvss_vector(vector: str) -> bool:
    """Return True if *vector* is a valid CVSS 3.1 vector string, False otherwise."""
    try:
        _parse_vector(vector)
        return True
    except ValueError:
        return False
