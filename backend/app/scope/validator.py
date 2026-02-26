import ipaddress
import logging

from app.scope.parser import ScopeRule

logger = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    """Raised when a host is not within the defined scope."""


class ScopeValidator:
    def __init__(self, rules: list[ScopeRule]) -> None:
        self._include_rules = [r for r in rules if r.rule_type == "include"]
        self._exclude_rules = [r for r in rules if r.rule_type == "exclude"]

    def _matches(self, host: str, rule: ScopeRule) -> bool:
        host_lower = host.lower()
        pattern = rule.pattern  # already lowercased by parser

        if rule.kind == "url":
            return False

        if rule.kind == "domain":
            return host_lower == pattern

        if rule.kind == "wildcard":
            # pattern is "*.example.com" → strip leading "*"
            suffix = pattern[1:]  # ".example.com"
            return host_lower == suffix.lstrip(".") or host_lower.endswith(suffix)

        if rule.kind == "cidr":
            try:
                ip = ipaddress.ip_address(host_lower)
                network = ipaddress.ip_network(pattern, strict=False)
                return ip in network
            except ValueError:
                return False

        return False

    def is_in_scope(self, host: str) -> bool:
        if not self._include_rules:
            logger.debug("No include rules defined; host %r is out of scope by default.", host)
            return False

        included = any(self._matches(host, r) for r in self._include_rules)
        if not included:
            return False

        excluded = any(self._matches(host, r) for r in self._exclude_rules)
        return not excluded

    def check_or_raise(self, host: str) -> None:
        if not self.is_in_scope(host):
            raise ScopeViolationError(
                f"Host {host!r} is not within the defined scope."
            )
