# dragonflAI — Usage Guide

Step-by-step walkthrough for using dragonflAI to find bugs in bug bounty programs.

---

## Overview

dragonflAI automates the reconnaissance, detection, and reporting phases of a bug bounty workflow:

1. **Create a Program** — model the bug bounty program and its rules.
2. **Add Targets** — define the in-scope domains and scope rules.
3. **Run Recon** — execute subfinder, httpx, dnsx, and nmap against your targets.
4. **Review Assets & Endpoints** — browse discovered subdomains and HTTP endpoints.
5. **Import External Scans** — load Burp Suite or OWASP ZAP results.
6. **Review Detection Signals** — inspect heuristic findings flagged by dragonflAI.
7. **Create & Triage Findings** — document confirmed vulnerabilities with CVSS scores.
8. **Generate Reports** — produce platform-ready reports for HackerOne, Bugcrowd, etc.
9. **Diff Runs** — compare recon runs to spot new or changed assets over time.

> **Ethics reminder:** Only scan targets you are explicitly authorized to test. Always read the program's rules before starting. See [docs/safety.md](safety.md) for full policy.

---

## Step 1 — Create a Program

A **Program** represents a bug bounty program (e.g. a HackerOne or Bugcrowd program).

### Via the UI

1. Open the UI at <http://127.0.0.1:8501>.
2. Navigate to **Programs** in the sidebar.
3. Click **New Program**.
4. Fill in:
   - **Name** — the program name (e.g. `Acme Corp`).
   - **Platform** — e.g. `HackerOne`, `Bugcrowd`, `Intigriti`, or `Private`.
   - **URL** — link to the program page (for reference).
   - **Notes** — any additional context (optional).
5. Click **Save**.

### Via the API

```bash
curl -X POST http://127.0.0.1:8000/programs \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "platform": "HackerOne",
    "url": "https://hackerone.com/acmecorp",
    "notes": "Public program, VDP + paid rewards"
  }'
```

---

## Step 2 — Add Targets and Define Scope

A **Target** is a root domain or IP range within a program. Scope rules control what dragonflAI is allowed to scan.

### Via the UI

1. Open **Targets** in the sidebar.
2. Click **New Target**.
3. Fill in:
   - **Program** — select the program created in Step 1.
   - **Name** — a human-readable label (e.g. `Main web app`).
   - **Root Domain** — the root domain to scan (e.g. `acmecorp.com`).
4. Add **Scope Rules**:
   - `*.acmecorp.com` — include all subdomains.
   - `acmecorp.com` — include the apex domain.
   - Add exclusions for out-of-scope assets (e.g. `blog.acmecorp.com` if explicitly excluded by the program).
5. Click **Save**.

### Via the API

```bash
curl -X POST http://127.0.0.1:8000/targets \
  -H "Content-Type: application/json" \
  -d '{
    "program_id": 1,
    "name": "Main web app",
    "root_domain": "acmecorp.com",
    "scope_rules": ["*.acmecorp.com", "acmecorp.com"]
  }'
```

> **Important:** dragonflAI enforces scope validation before any tool runs. Out-of-scope assets are blocked automatically.

---

## Step 3 — Run Recon

A **Run** executes the full recon pipeline against a target: subdomain enumeration, DNS resolution, HTTP probing, and port scanning.

### Via the UI

1. Navigate to **Runs** in the sidebar.
2. Click **New Run**.
3. Select the **Target** from the dropdown.
4. Choose which tools to include:
   - **subfinder** — passive subdomain enumeration.
   - **dnsx** — DNS resolution and validation.
   - **httpx** — HTTP probing (status codes, titles, technologies).
   - **nmap** — port and service scanning (active; use only if permitted by the program).
5. Click **Start Run**.
6. Watch the live progress log as each tool completes.

### Via the API

```bash
curl -X POST http://127.0.0.1:8000/runs \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "tools": ["subfinder", "dnsx", "httpx", "nmap"]
  }'
```

Poll for status:

```bash
curl http://127.0.0.1:8000/runs/{run_id}
```

The run transitions through: `queued → running → succeeded` (or `failed`).

---

## Step 4 — Review Assets and Endpoints

After a run completes, dragonflAI stores all discovered assets and HTTP endpoints.

### Assets (Subdomains)

1. Navigate to **Assets** in the sidebar.
2. Filter by target or run.
3. Look for interesting subdomains, e.g.:
   - `admin.acmecorp.com` — admin panels.
   - `api.acmecorp.com` — API endpoints.
   - `dev.acmecorp.com` / `staging.acmecorp.com` — pre-production environments.
   - `vpn.acmecorp.com` — VPN or remote access endpoints.

### Endpoints

1. Navigate to **Endpoints** in the sidebar.
2. Filter by status code, content type, or technology.
3. Pay attention to:
   - Endpoints returning **401 / 403** — potential access control issues.
   - Endpoints with query parameters — potential injection points.
   - **Interesting paths** flagged by heuristics (see Step 6).

---

## Step 5 — Import External Scans

If you have already collected traffic in Burp Suite or OWASP ZAP, you can import it into dragonflAI.

### Burp Suite XML Import

1. In Burp Suite, select items in the **Proxy → HTTP history** tab.
2. Right-click → **Save items** → save as XML.
3. In the dragonflAI UI, go to **Imports**.
4. Choose **Burp Suite XML** and upload the file.
5. Select the target to associate the imported endpoints with.
6. Click **Import**.

### OWASP ZAP Import

1. In ZAP, export the session: **File → Export Sessions** (JSON or XML format).
2. In the dragonflAI UI, go to **Imports**.
3. Choose **OWASP ZAP** and upload the file.
4. Select the target and click **Import**.

Imported endpoints are deduplicated against existing data and stored alongside recon-discovered endpoints.

---

## Step 6 — Review Detection Signals

dragonflAI runs heuristic analysis over all discovered endpoints and flags items that are commonly associated with vulnerabilities.

### What Gets Flagged

| Signal | Examples | Potential Vulnerability |
|---|---|---|
| Interesting parameters | `?redirect=`, `?url=`, `?file=`, `?path=` | Open Redirect, SSRF, Path Traversal |
| Interesting parameters | `?id=`, `?user_id=`, `?order=` | IDOR, SQLi |
| Interesting paths | `/admin`, `/debug`, `/actuator`, `/.git` | Exposed admin panels, debug endpoints |
| Interesting headers | `X-Debug: true`, `X-Forwarded-For` accepted | Debug mode, IP spoofing |
| Error responses | Stack traces, verbose 500 errors | Information disclosure |

### Reviewing in the UI

1. Navigate to **Detection** in the sidebar.
2. Filter by signal type or severity.
3. For each signal, review the raw endpoint and decide:
   - **Investigate** — manually test the endpoint.
   - **Confirm** — promote to a finding (Step 7).
   - **Dismiss** — mark as false positive.

---

## Step 7 — Create and Triage Findings

A **Finding** documents a confirmed (or suspected) vulnerability, including reproduction steps, impact, and CVSS score.

### Creating a Finding from a Detection Signal

1. In the **Detection** page, click **Promote to Finding** next to a signal.
2. dragonflAI pre-populates the affected endpoint and a draft title.
3. Complete the finding details (see below) and save.

### Creating a Finding Manually

**Via the UI:**

1. Navigate to **Findings** in the sidebar.
2. Click **New Finding**.
3. Fill in:
   - **Title** — concise vulnerability name (e.g. `Reflected XSS in search parameter`).
   - **Target** — the affected target.
   - **Affected Endpoint** — full URL of the vulnerable endpoint.
   - **Severity** — `critical`, `high`, `medium`, `low`, or `informational`.
   - **CVSS Vector** — CVSS 3.1 base vector string (the score is calculated automatically).
   - **Steps to Reproduce** — numbered steps that reproduce the issue.
   - **Impact** — what an attacker can achieve.
   - **Remediation** — recommended fix.
4. Click **Save**.

**Via the API:**

```bash
curl -X POST http://127.0.0.1:8000/findings \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Reflected XSS in search parameter",
    "target_id": 1,
    "affected_endpoint": "https://acmecorp.com/search?q=",
    "severity": "medium",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "steps_to_reproduce": "1. Navigate to https://acmecorp.com/search\n2. Enter <script>alert(1)</script> in the q parameter\n3. Observe JavaScript execution in the browser",
    "impact": "An attacker can execute arbitrary JavaScript in the context of the victim'\''s browser session.",
    "remediation": "HTML-encode all user-supplied output before rendering it in an HTML context."
  }'
```

### CVSS 3.1 Quick Reference

| Vulnerability | CVSS Vector | Score | Severity |
|---|---|---|---|
| Reflected XSS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium |
| Stored XSS | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 | Medium |
| IDOR | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | Medium |
| SSRF (internal) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | 8.6 | High |
| SQLi | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| Open Redirect | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium |
| Path Traversal | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | High |

---

## Step 8 — Generate and Export Reports

dragonflAI can generate professional, platform-ready reports from your findings.

### Report Templates

| Template | Description | Best for |
|---|---|---|
| `full` | Comprehensive report with all details | Your records, internal review |
| `platform` | Formatted for bug bounty platform submission | HackerOne, Bugcrowd, Intigriti copy-paste |
| `summary` | Short overview of the finding | Quick triage communication |

### Generate a Single Report

**Via the UI:**

1. Navigate to **Findings**.
2. Open the finding you want to report.
3. Click **Generate Report**.
4. Choose the template (`platform` is recommended for submission).
5. Review the generated report in the preview pane.
6. Click **Copy to Clipboard** or **Download**.

**Via the API:**

```bash
curl -X POST http://127.0.0.1:8000/findings/{finding_id}/generate-report \
  -H "Content-Type: application/json" \
  -d '{"template": "platform"}'
```

### Export a Report File

```bash
# Markdown (.md) — ready to paste into HackerOne / Bugcrowd
curl "http://127.0.0.1:8000/findings/{finding_id}/export?format=markdown" -o report.md

# Plain text (.txt)
curl "http://127.0.0.1:8000/findings/{finding_id}/export?format=plaintext" -o report.txt
```

### Generate a Batch Assessment Report

Combine multiple findings into a single assessment document:

```bash
curl -X POST http://127.0.0.1:8000/findings/batch-report \
  -H "Content-Type: application/json" \
  -d '{
    "finding_ids": [1, 2, 3],
    "template": "full"
  }'
```

The batch report includes a severity breakdown header followed by each individual finding separated by a horizontal rule.

### Submit to the Bug Bounty Platform

1. Open the generated `platform` report.
2. Copy the contents.
3. Create a new submission on HackerOne/Bugcrowd/Intigriti.
4. Paste the report contents into the submission form.
5. Attach any supporting evidence (screenshots, PoC files) as attachments.
6. Submit.

---

## Step 9 — Diff Runs to Spot New Attack Surface

As a program's infrastructure changes over time, new assets appear. Running recon regularly and diffing the results helps you catch new attack surface before other researchers.

### Running a Diff

1. Complete at least two recon runs against the same target.
2. Navigate to **Diff** in the sidebar.
3. Select the **baseline run** (older) and the **comparison run** (newer).
4. Click **Compare**.

### Reading the Diff

| Category | What to look for |
|---|---|
| **New assets** | Newly discovered subdomains — investigate these first |
| **Removed assets** | Assets that disappeared — may indicate a decommission |
| **New endpoints** | New HTTP endpoints — fresh attack surface |
| **Changed endpoints** | Status code or title changes — a 403 becoming 200 is interesting |

New assets found in a diff are often the most valuable targets — they are likely to be less hardened and less tested by other researchers.

---

## End-to-End Example

The following example walks through a complete bug bounty workflow:

```bash
# 1. Start dragonflAI
./scripts/dev.sh all

# 2. Create a program
curl -X POST http://127.0.0.1:8000/programs \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "platform": "HackerOne"}'

# 3. Add a target
curl -X POST http://127.0.0.1:8000/targets \
  -H "Content-Type: application/json" \
  -d '{"program_id": 1, "name": "Main app", "root_domain": "acmecorp.com", "scope_rules": ["*.acmecorp.com"]}'

# 4. Start a recon run
curl -X POST http://127.0.0.1:8000/runs \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1, "tools": ["subfinder", "dnsx", "httpx"]}'

# 5. Wait for the run to complete, then review assets and endpoints in the UI
open http://127.0.0.1:8501

# 6. After confirming a finding, create it
curl -X POST http://127.0.0.1:8000/findings \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Open Redirect via redirect parameter",
    "target_id": 1,
    "affected_endpoint": "https://acmecorp.com/login?redirect=",
    "severity": "medium",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "steps_to_reproduce": "1. Visit https://acmecorp.com/login?redirect=https://evil.com\n2. Complete login\n3. Observe redirect to https://evil.com",
    "impact": "Attacker can redirect authenticated users to a phishing site after login.",
    "remediation": "Validate the redirect parameter against an allowlist of trusted domains."
  }'

# 7. Generate a platform report
curl -X POST http://127.0.0.1:8000/findings/1/generate-report \
  -H "Content-Type: application/json" \
  -d '{"template": "platform"}'

# 8. Export and submit
curl "http://127.0.0.1:8000/findings/1/export?format=markdown" -o submission.md
```

---

## Tips for Effective Bug Bounty Hunting with dragonflAI

- **Run recon on a schedule.** New subdomains and endpoints appear as programs expand. Run recon weekly and use diffs to find fresh attack surface.
- **Focus on interesting parameters first.** Detection signals for `?redirect=`, `?url=`, `?file=`, and `?id=` parameters have the highest yield for open redirects, SSRF, path traversal, and IDOR respectively.
- **Check pre-production environments.** `dev.*`, `staging.*`, `test.*`, and `beta.*` subdomains are often less hardened.
- **Import Burp traffic.** After manual browsing, import your Burp history to centralize all observed endpoints.
- **Be accurate with CVSS scores.** Platforms down-grade or reject findings with inflated severity. Use the vectors in the quick reference table as a guide.
- **Review the generated report before submitting.** The platform template is a starting point — add screenshots and PoC files before submission.

---

## See Also

- [Setup Guide](setup.md) — installation and configuration.
- [Safety & Ethics Policy](safety.md) — scope enforcement and responsible disclosure.
- [Roadmap](roadmap.md) — planned features including LLM-enhanced reporting.
