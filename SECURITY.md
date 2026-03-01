# Security Policy

## Supported Versions

The following versions of dragonflAI currently receive security updates:

| Version | Supported          |
| ------- | ------------------ |
| latest (`main`) | ✅ Yes |
| older releases  | ❌ No  |

We recommend always running the latest commit from `main` to receive all security fixes.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability, open a [GitHub Security Advisory](https://github.com/EthicalTomas/dragonflAI/security/advisories/new) (private disclosure). This keeps the details confidential until a fix is available.

If you are unsure whether a behaviour constitutes a security issue, err on the side of caution and report it privately.

### What to include in your report

To help us triage and reproduce the issue quickly, please provide:

- A clear description of the vulnerability and its potential impact.
- The affected component(s) (e.g. API endpoint, worker, UI page).
- Step-by-step reproduction instructions.
- Any relevant logs, error messages, or screenshots (redacted where necessary).
- Your suggested CVSS 3.1 vector, if you have one.

### What NOT to include

To protect yourself, the project, and any third parties, **do not include**:

- Real credentials, API keys, tokens, or passwords.
- Personal data belonging to yourself or others.
- Data obtained from live targets or production systems outside your own control.
- Proof-of-concept payloads that could cause irreversible damage if accidentally executed.

---

## Response Timeline

| Milestone | Target timeframe |
| --------- | ---------------- |
| Acknowledgement of report | Within **3 business days** |
| Initial triage / severity assessment | Within **7 days** |
| Fix or mitigation available | Within **30 days** for critical/high; best-effort for others |
| Public disclosure (coordinated) | After a fix is released and reporters are notified |

We aim to keep you informed throughout the process. If you have not received an acknowledgement within 3 business days, please follow up by adding a comment to the advisory.

---

## Coordinated Disclosure

We follow a coordinated disclosure model. Once a fix is released, we will:

1. Publish a GitHub Security Advisory with full details.
2. Credit the reporter (unless they prefer to remain anonymous).
3. Tag a new release that includes the fix.

We ask that you do not publicly disclose the vulnerability before a fix is available, unless you have not received a response within **90 days** of your initial report.

---

> **Note:** dragonflAI is a local-first tool. Many classes of vulnerability (e.g. SSRF, path traversal) are only exploitable if an attacker already has local access. Please consider the realistic threat model when assessing severity.
