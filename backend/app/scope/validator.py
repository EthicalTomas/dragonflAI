from __future__ import annotations

import fnmatch


def is_in_scope(host: str, rules: list[str]) -> bool:
    """Return True if *host* matches at least one scope rule."""
    for rule in rules:
        if rule.startswith("*."):
            # wildcard: *.example.com matches sub.example.com and example.com
            domain = rule[2:]
            if host == domain or host.endswith("." + domain):
                return True
        elif fnmatch.fnmatch(host, rule):
            return True
    return False
