# Verification

The verification subsystem provides an **automated second-technique proof step** for suspected findings. It reduces false positives by independently confirming or denying a signal using a different technique, and it produces reproducible evidence artefacts for bug bounty workflows.

---

## What verification does

| Stage | Description |
|-------|-------------|
| **Queue** | A `Verification` record is created with `status=queued` and a worker job is enqueued on the `verifications` RQ queue. |
| **Scope check** | Before any active action, the target host is validated against the program's scope rules. Out-of-scope targets are blocked at the code level. |
| **Run** | The chosen verification method is executed. |
| **Verdict** | The record is updated with one of: `confirmed`, `unconfirmed`, `inconclusive`, or `failed`. |
| **Evidence** | Structured evidence (HTTP request/response, resolved IPs, screenshot path) is stored in `evidence_json` and written to the artefacts directory. |

---

## Verification methods

### `http_replay` (default, safe, low-impact)

Issues a controlled HTTP GET request using `httpx` and captures:
- Status code
- Response headers (secrets redacted automatically)
- First 1 MB of the response body (truncated in the DB to 2 000 chars)

**Verdict logic:**
- If **markers** are provided (e.g. reflected payload text), the verdict is `confirmed` when at least one marker appears in the response.
- Without markers, any non-5xx response gives `confirmed`; a 5xx gives `unconfirmed`.
- Network errors give `inconclusive`.

### `dns_recheck` (passive)

Re-resolves the hostname via the system resolver and optionally compares against expected IPs.

**Verdict logic:**
- `confirmed` – resolution succeeds (and expected IPs match, if provided).
- `unconfirmed` – resolution succeeds but expected IPs are absent.
- `inconclusive` – DNS resolution fails.

### `screenshot` (opt-in, active)

Uses a headless Chromium browser (via Playwright) to navigate to the URL, capture the page title, and save a full PNG screenshot.

> **This method is disabled by default.** It requires explicit opt-in because it is heavier and more active.

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
- **Secret redaction**: Authorization, Cookie, Set-Cookie, X-API-Key, and similar headers are replaced with `[REDACTED]` in captured evidence.
- **Body size limit**: Response bodies are capped at 1 MB capture and 2 000 chars in the DB snippet.
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
  "notes": "HTTP 200 received from target."
}
```

`evidence_json` on the `Verification` record:

```json
{
  "url": "https://example.com/admin",
  "status_code": 200,
  "response_headers": {
    "content-type": "text/html; charset=utf-8",
    "authorization": "[REDACTED]"
  },
  "body_snippet": "<!DOCTYPE html><html>...",
  "artifacts_dir": "/tmp/dragonflai_verify/1/verify/7"
}
```
