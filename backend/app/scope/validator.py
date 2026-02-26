import ipaddress
import logging

from app.scope.parser import ScopeRule

logger = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    pass


class ScopeValidator:
    def __init__(self, rules: list[ScopeRule]) -> None:
        self._include_rules = [r for r in rules if r.rule_type == "include"]
        self._exclude_rules = [r for r in rules if r.rule_type == "exclude"]

    def _matches(self, rule: ScopeRule, host: str) -> bool:
        host_lower = host.lower()
        kind = rule.kind
        pattern = rule.pattern  # already lowercased by parser

        if kind == "url":
            return False

        if kind == "domain":
            return host_lower == pattern

        if kind == "wildcard":
            # pattern is like *.example.com → stored as *.example.com
            # host matches if it IS example.com OR ends with .example.com
            suffix = pattern[1:]  # ".example.com"
            return host_lower == suffix[1:] or host_lower.endswith(suffix)

        if kind == "cidr":
            try:
                ip = ipaddress.ip_address(host)
                network = ipaddress.ip_network(pattern, strict=False)
                return ip in network
            except ValueError:
                return False

        return False

    def is_in_scope(self, host: str) -> bool:
        if not self._include_rules:
            logger.debug("No include rules defined — default deny for host %r", host)
            return False

        included = any(self._matches(r, host) for r in self._include_rules)
        if not included:
            return False

        excluded = any(self._matches(r, host) for r in self._exclude_rules)
        return not excluded

    def check_or_raise(self, host: str) -> None:
        if not self.is_in_scope(host):
            raise ScopeViolationError(
                f"Host {host!r} is not within the defined scope."
            )
