FULL_REPORT_TEMPLATE = """\
# Vulnerability Report: {title}

**Severity:** {severity}
**CVSS Score:** {cvss_score} ({cvss_vector})
**Vulnerability Type:** {vulnerability_type}
**Status:** {status}
**Date:** {created_at}

---

## Affected Endpoint
- **URL:** {url}
- **Parameter:** {parameter}
- **Method:** {method}

---

## Summary
{description}

---

## Steps to Reproduce
{steps_to_reproduce}

---

## Impact
{impact}

---

## Proof of Concept
### HTTP Request/Response
```
{request_response}
```

### Evidence
{evidence_list}

---

## Remediation
{remediation}

---

## References
{references_list}
"""

SUMMARY_REPORT_TEMPLATE = """\
## {title}
**Severity:** {severity} | **Type:** {vulnerability_type} | **Endpoint:** {url}

{description}

**Impact:** {impact}
"""

PLATFORM_REPORT_TEMPLATE = """\
## Summary
{description}

## Vulnerability Type
{vulnerability_type}

## Steps to Reproduce
{steps_to_reproduce}

## Supporting Material/References
{evidence_list}
{references_list}

## Impact
{impact}

## Suggested Remediation
{remediation}
"""

_TEMPLATES = {
    "full": FULL_REPORT_TEMPLATE,
    "summary": SUMMARY_REPORT_TEMPLATE,
    "platform": PLATFORM_REPORT_TEMPLATE,
}


def get_template(template_name: str) -> str:
    try:
        return _TEMPLATES[template_name]
    except KeyError:
        raise ValueError(f"Unknown template name: {template_name!r}")
