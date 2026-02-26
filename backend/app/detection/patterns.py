import logging
import re

logger = logging.getLogger(__name__)


class PatternMatcher:
    INTERESTING_PARAMS: dict[str, str] = {
        # Open Redirect / SSRF
        "redirect": "open_redirect",
        "redirect_url": "open_redirect",
        "redirect_uri": "open_redirect",
        "return": "open_redirect",
        "return_url": "open_redirect",
        "returnTo": "open_redirect",
        "next": "open_redirect",
        "next_url": "open_redirect",
        "url": "ssrf",
        "uri": "ssrf",
        "callback": "open_redirect",
        "continue": "open_redirect",
        "dest": "open_redirect",
        "destination": "open_redirect",
        "go": "open_redirect",
        "out": "open_redirect",
        "rurl": "open_redirect",
        "target": "ssrf",
        # SSRF
        "fetch": "ssrf",
        "site": "ssrf",
        "host": "ssrf",
        "domain": "ssrf",
        "proxy": "ssrf",
        "page": "ssrf",
        "feed": "ssrf",
        "load": "ssrf",
        # LFI / Path Traversal
        "file": "lfi",
        "path": "lfi",
        "folder": "lfi",
        "dir": "lfi",
        "document": "lfi",
        "doc": "lfi",
        "root": "lfi",
        "include": "lfi",
        "require": "lfi",
        "read": "lfi",
        "download": "lfi",
        "filename": "lfi",
        "filepath": "lfi",
        # SQL Injection
        "id": "sqli",
        "user_id": "sqli",
        "item_id": "sqli",
        "order": "sqli",
        "sort": "sqli",
        "column": "sqli",
        "table": "sqli",
        "query": "sqli",
        "search": "sqli",
        "filter": "sqli",
        "where": "sqli",
        "select": "sqli",
        "from": "sqli",
        "limit": "sqli",
        "offset": "sqli",
        # XSS
        "q": "xss",
        "s": "xss",
        "keyword": "xss",
        "keywords": "xss",
        "name": "xss",
        "title": "xss",
        "body": "xss",
        "content": "xss",
        "message": "xss",
        "comment": "xss",
        "text": "xss",
        "value": "xss",
        "input": "xss",
        "data": "xss",
        "payload": "xss",
        "html": "xss",
        "error": "xss",
        "msg": "xss",
        # IDOR
        "account": "idor",
        "user": "idor",
        "uid": "idor",
        "profile": "idor",
        "email": "idor",
        "account_id": "idor",
        "order_id": "idor",
        "invoice_id": "idor",
        "report_id": "idor",
        # RCE / Command Injection
        "cmd": "rce",
        "exec": "rce",
        "command": "rce",
        "execute": "rce",
        "run": "rce",
        "ping": "rce",
        "process": "rce",
        "ip": "rce",
        # SSTI
        "template": "ssti",
        "preview": "ssti",
        "render": "ssti",
        "layout": "ssti",
        "theme": "ssti",
    }

    INTERESTING_PATHS: list[str] = [
        r"/admin",
        r"/administrator",
        r"/dashboard",
        r"/panel",
        r"/console",
        r"/debug",
        r"/devtools",
        r"/api/",
        r"/api/v\d+",
        r"/graphql",
        r"/graphiql",
        r"/swagger",
        r"/api-docs",
        r"/openapi",
        r"/\.git",
        r"/\.env",
        r"/\.config",
        r"/\.htaccess",
        r"/\.htpasswd",
        r"/backup",
        r"/dump",
        r"/export",
        r"/db",
        r"/database",
        r"/phpinfo",
        r"/phpmyadmin",
        r"/wp-admin",
        r"/wp-login",
        r"/server-status",
        r"/server-info",
        r"/status",
        r"/health",
        r"/actuator",
        r"/metrics",
        r"/trace",
        r"/upload",
        r"/file-upload",
        r"/reset",
        r"/password",
        r"/forgot",
        r"/token",
        r"/oauth",
        r"/auth",
        r"/login",
        r"/signup",
        r"/register",
        r"/internal",
        r"/private",
        r"/secret",
        r"/hidden",
        r"/cgi-bin",
        r"/shell",
        r"/cmd",
        r"/test",
        r"/staging",
        r"/dev",
        r"/qa",
        r"\.bak$",
        r"\.old$",
        r"\.orig$",
        r"\.sql$",
        r"\.log$",
        r"\.xml$",
        r"\.json$",
        r"\.yaml$",
        r"\.yml$",
        r"\.conf$",
    ]

    INTERESTING_HEADERS: dict[str, str] = {
        "x-powered-by": "tech_disclosure",
        "server": "tech_disclosure",
        "x-aspnet-version": "tech_disclosure",
        "x-debug-token": "debug_enabled",
        "x-debug-token-link": "debug_enabled",
        "access-control-allow-origin: *": "cors_wildcard",
    }

    MISSING_SECURITY_HEADERS: list[str] = [
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    ]

    _SEVERITY_MAP: dict[str, str] = {
        "rce": "high",
        "ssti": "high",
        "sqli": "high",
        "ssrf": "high",
        "lfi": "high",
        "xss": "medium",
        "open_redirect": "medium",
        "idor": "medium",
    }

    _compiled_paths: list[re.Pattern] = [
        re.compile(pattern, re.IGNORECASE) for pattern in INTERESTING_PATHS
    ]

    # Normalised lookup: lowercase key → vuln_type
    _params_lower: dict[str, str] = {k.lower(): v for k, v in INTERESTING_PARAMS.items()}

    def match_params(self, params: list[dict]) -> list[dict]:
        results: list[dict] = []
        for param in params:
            name: str = param.get("name", "")
            name_lower = name.lower()
            vuln_type = self._params_lower.get(name_lower)
            if vuln_type is not None:
                severity_hint = self._SEVERITY_MAP.get(vuln_type, "medium")
                results.append(
                    {
                        "param": name,
                        "vuln_type": vuln_type,
                        "severity_hint": severity_hint,
                    }
                )
                logger.debug(
                    "Param %r matched vuln_type=%r severity=%r",
                    name,
                    vuln_type,
                    severity_hint,
                )
        return results

    def match_path(self, path: str) -> list[dict]:
        results: list[dict] = []
        for pattern_re in self._compiled_paths:
            if pattern_re.search(path):
                results.append(
                    {
                        "pattern": pattern_re.pattern,
                        "reason": f"Path matches sensitive pattern {pattern_re.pattern!r}",
                    }
                )
                logger.debug("Path %r matched pattern %r", path, pattern_re.pattern)
        return results

    def check_headers(self, response_headers: dict) -> list[dict]:
        results: list[dict] = []
        lowered = {k.lower(): v for k, v in response_headers.items()}

        for header_key, issue in self.INTERESTING_HEADERS.items():
            # Special case: "access-control-allow-origin: *" means the header
            # must be present AND its value must be "*".
            if ": " in header_key:
                name, _, expected_value = header_key.partition(": ")
                if name in lowered and lowered[name].strip() == expected_value:
                    results.append(
                        {
                            "header": header_key,
                            "issue": issue,
                            "type": "present_bad",
                        }
                    )
                    logger.debug("Interesting header present: %r (%s)", header_key, issue)
            elif header_key in lowered:
                results.append(
                    {
                        "header": header_key,
                        "issue": issue,
                        "type": "present_bad",
                    }
                )
                logger.debug("Interesting header present: %r (%s)", header_key, issue)

        for security_header in self.MISSING_SECURITY_HEADERS:
            if security_header not in lowered:
                results.append(
                    {
                        "header": security_header,
                        "issue": "missing_security_header",
                        "type": "missing_good",
                    }
                )
                logger.debug("Missing security header: %r", security_header)

        return results
