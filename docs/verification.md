# Verification

The verification subsystem provides an **automated second-technique proof step** for suspected findings. It reduces false positives by independently confirming or denying a signal using a different technique, and it produces reproducible evidence artefacts for bug bounty workflows.

---

## What verification does

| Stage | Description |
|-------|-------------|
| **Queue** | A `Verification` record is created with `status=queued` and a worker job is enqueued on the `verifications` RQ queue. |
| **Scope check** | Before any active action, the target host is validated against the program's scope rules. Out-of-scope targets are blocked at the code level. |
| **Run** | The chosen verification method is executed. The `http_replay` method routes to a per-vulnerability-type strategy via `VulnRouter`. |
| **Verdict** | The record is updated with one of: `confirmed`, `unconfirmed`, `inconclusive`, or `failed`. |
| **Evidence** | Structured evidence (HTTP request/response, resolved IPs, screenshot path) is stored in `evidence_json` and written to the artefacts directory. |

---

## Conservative verdict rules

dragonflAI applies **bug bounty grade** verification rigor:

| Verdict | When it is returned |
|---------|---------------------|
| `confirmed` | Strong, vuln-specific evidence collected (e.g. canary domain in `Location` header, marker reflected in body, provider fingerprint matched). |
| `unconfirmed` | The target responded normally and the proof condition **clearly failed** (e.g. marker not reflected, 5xx server error, 404 on a sensitive-file check). |
| `inconclusive` | Proof is ambiguous or incomplete (e.g. network error, auth wall, 200 with no stable marker, no marker specified, no matching strategy). |
| `failed` | The verification job itself crashed or was blocked by a scope violation. |

> **Important**: A bare non-5xx HTTP response is **never** sufficient to return `confirmed`. Every `confirmed` verdict requires finding-specific evidence.

---

## Verification methods

### `http_replay` — VulnRouter dispatch (default, safe, low-impact)

The `http_replay` method routes to a **per-vulnerability-type strategy** via `VulnRouter`. The strategy is chosen automatically based on (in priority order):

1. `finding.vulnerability_type` (explicit classification)
2. Nuclei template tags
3. Finding title heuristics

#### Per-type strategies

| Category | Trigger keywords | Proof condition for `confirmed` |
|----------|-----------------|----------------------------------|
| **Open redirect** | `redirect`, `open redirect`, tag `open-redirect` | `Location` header contains canary domain after parameter injection |
| **Reflected XSS** | `xss`, `cross-site scripting`, tag `xss` | Harmless marker string reflected verbatim in response body |
| **Sensitive file / admin panel** | `exposure`, `admin`, `panel`, `sensitive`, tag `exposure` | Stable title/body marker (admin dashboard, control panel, etc.) present in 200 response |
| **Subdomain takeover** | `takeover`, `subdomain`, tag `takeover` | DNS resolves **and** known provider error-page fingerprint found in response |
| **Generic** (fallback) | anything else | Always `inconclusive` — no finding-specific proof available |

For **open redirect**, dragonflAI injects an unresolvable canary URL (`dragonflai-verify.invalid`) into common redirect parameters (`redirect`, `redirect_uri`, `return`, `next`, etc.) and checks the `Location` header of the (non-redirected) response.

For **reflected XSS**, a harmless marker string (`dragonflai-xss-probe-7f3a9b`) is injected into common input parameters and checked for verbatim reflection.

If `http_replay` is requested without a finding, the `generic` fallback strategy is used, which always returns `inconclusive`.

**Evidence always includes:**
- `schema_version: 1`
- `method: "GET"`
- `final_url` (after any redirects)
- `elapsed_s` (total request time)
- `status_code`, `response_headers` (redacted), `body_snippet`
- `body_truncated: true/false`
- `resolved_ips` (for strategies that DNS-resolve the host)

### `dns_recheck` (passive)

Re-resolves the hostname via the system resolver and optionally compares against expected IPs.

**Verdict logic:**
- `confirmed` – resolution succeeds (and expected IPs match, if provided).
- `unconfirmed` – resolution succeeds but expected IPs are absent.
- `inconclusive` – DNS resolution fails.

### `screenshot` (opt-in, active)

Uses a headless Chromium browser (via Playwright) to navigate to the URL, capture the page title, and save a full PNG screenshot.

> **This method is disabled by default.** It requires explicit opt-in because it is heavier and more active.
> A `WARNING`-level log message is emitted every time a screenshot is captured so the activity is always visible in logs.

To enable it, set the environment variable:

```
VERIFY_SCREENSHOT_ENABLED=1
```

Playwright must also be installed:

```bash
pip install playwright
playwright install chromium
```

---

## Safety guardrails

- **Default deny**: if no scope rules are configured for a program, all verification requests fail with a scope violation.
- **Scope enforcement**: The `ScopeValidator` checks every host before running any active step. Out-of-scope hosts raise `ScopeViolationError`, which marks the verification as `failed` and re-raises so the RQ job is visible as failed.
- **Secret redaction**: The following headers are replaced with `[REDACTED]` in all captured evidence:
  `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token`,
  `X-Amz-Security-Token`, `Proxy-Authorization`, `X-Forwarded-Authorization`.
- **Body size limit**: Response bodies are capped at 1 MB capture and 2 000 chars in the DB snippet. The `body_truncated` flag in evidence indicates when truncation occurred.
- **No full bodies stored**: Only the first 2 000 chars of the response body are persisted in `evidence_json`.
- **Screenshot opt-in**: Screenshots require `VERIFY_SCREENSHOT_ENABLED=1` and the Playwright package.

---

## Auto-verify

By default, verifications must be triggered manually via the API. Set `auto_verify=true` in the application configuration (or `AUTO_VERIFY=true` in environment) to automatically queue verification jobs:

- For high-confidence detection signals after the `detect` pipeline module completes.
- For Nuclei scan results with severity `medium` or above after `execute_scan` finishes.

```env
# .env
AUTO_VERIFY=true
```

---

## API

### Queue a verification

```http
POST /verifications
Content-Type: application/json

{
  "target_id": 1,
  "finding_id": 42,
  "method": "http_replay"
}
```

Optional fields: `run_id`, `finding_id`. `method` defaults to `http_replay`.

### List verifications

```http
GET /verifications?target_id=1&finding_id=42&status=confirmed
```

### Get details

```http
GET /verifications/7
```

---

## Evidence artefacts

Evidence files are written to:

```
$VERIFICATION_ARTIFACTS_DIR/<target_id>/<run_id>/verify/<verification_id>/
├── request.txt      # Captured request (if present)
├── response.txt     # Captured response (if present)
├── screenshot.png   # Screenshot (screenshot method only)
└── meta.json        # Structured summary
```

The default base directory is `/tmp/dragonflai_verify`. Override with the `VERIFICATION_ARTIFACTS_DIR` environment variable.

The `evidence_json` column on the `Verification` record contains a JSON object with all evidence pointers, including `artifacts_dir`.

---

## Rate limiting and concurrency

RQ worker concurrency is controlled at the worker level. To limit concurrent verification jobs, run fewer worker processes on the `verifications` queue:

```bash
# Run a single worker for verifications
rq worker verifications
```

Each `http_replay` request has a 10-second timeout by default. The `screenshot` verifier uses a 15-second navigation timeout. The overall RQ job timeout is inherited from `job_timeout_seconds` (default 3600 s).

---

## Example: evidence output

`meta.json`:

```json
{
  "verification_id": 7,
  "method": "http_replay",
  "status": "confirmed",
  "notes": "Open redirect confirmed: Location header redirects to 'dragonflai-verify.invalid' via parameter 'redirect'."
}
```

`evidence_json` on the `Verification` record (open redirect example):

```json
{
  "schema_version": 1,
  "method": "GET",
  "final_url": "https://example.com/login?redirect=https%3A%2F%2Fdragonflai-verify.invalid%2F",
  "elapsed_s": 0.312,
  "status_code": 302,
  "response_headers": {
    "content-type": "text/html",
    "location": "https://dragonflai-verify.invalid/",
    "authorization": "[REDACTED]"
  },
  "body_snippet": "",
  "body_truncated": false,
  "resolved_ips": ["93.184.216.34"],
  "probe_param": "redirect",
  "canary": "https://dragonflai-verify.invalid/",
  "location_header": "https://dragonflai-verify.invalid/",
  "matched_param": "redirect",
  "params_tried": ["redirect"],
  "artifacts_dir": "/tmp/dragonflai_verify/1/verify/7"
}
```

