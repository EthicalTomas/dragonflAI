# dragonflAI Safety & Ethics Policy

This document defines the guardrails and ethical guidelines for using dragonflAI. It is a reference for users and contributors — not legal advice.

---

## 1. Scope Enforcement

- All recon tools **MUST** validate targets against the program's scope rules before execution.
- Out-of-scope targets are blocked at the code level — not just by policy.
- **Default deny**: if no scope rules are defined, nothing can be scanned.

---

## 2. Rate Limiting

- All tools respect configurable rate limits.
- Default limits are conservative (e.g. 50 requests/second for httpx, 10 threads for subfinder).
- Never override rate limits specified by a bug bounty program.

---

## 3. Active vs Passive

- **Passive tools** (subfinder, gau, waybackurls, dnsx) are safer and can run more broadly.
- **Active tools** (nmap, httpx, nuclei, ffuf) MUST be explicitly opted in per-target.
- Exploitation tools are **NOT** included — dragonflAI assists discovery and reporting, not exploitation.

---

## 4. Data Handling

- All findings, reports, and evidence are stored locally.
- No data is sent to external services except the configured LLM API (if enabled).
- Sensitive HTTP requests/responses in findings should be handled carefully — never commit them to version control.

---

## 5. Reporting Ethics

- Reports must be factual. Do not exaggerate severity or impact.
- CVSS scores must accurately reflect the vulnerability.
- Steps to reproduce must be honest and reproducible.
- If the LLM enhances a report, verify the output before submission.

---

## 6. Audit Log

- Every tool execution is logged with: command, target, timestamp, tool version, user.
- Logs are stored in the run's `log_text` field and in raw artifact files.
- Maintain logs for accountability.

---

## 7. Bug Bounty Program Rules

- Always read and follow the program's rules before scanning.
- Respect testing windows, rate limits, and excluded endpoints.
- When in doubt, ask the program — don't scan.

---

> **Disclaimer**: This document is not legal advice. Users are solely responsible for ensuring their use of dragonflAI complies with applicable laws, platform terms of service, and bug bounty program rules.
