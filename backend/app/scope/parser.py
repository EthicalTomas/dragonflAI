import ipaddress
import logging
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ScopeRule(BaseModel):
    rule_type: str
    pattern: str
    kind: str


def _detect_kind(token: str) -> str:
    if token.startswith(("http://", "https://")):
        return "url"
    if token.startswith("*."):
        return "wildcard"
    if "/" in token:
        try:
            ipaddress.ip_network(token, strict=False)
            return "cidr"
        except ValueError:
            pass
    return "domain"


def parse_scope_text(scope_text: str) -> list[ScopeRule]:
    rules: list[ScopeRule] = []
    for raw_line in scope_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if line.startswith("!") or line.startswith("-"):
                rule_type = "exclude"
                token = line[1:].strip().rstrip(".").lower()
            else:
                rule_type = "include"
                token = line.rstrip(".").lower()
            if not token:
                continue
            kind = _detect_kind(token)
            rules.append(ScopeRule(rule_type=rule_type, pattern=token, kind=kind))
        except Exception as exc:
            logger.warning("Skipping unparseable scope line %r: %s", raw_line, exc)
    return rules
