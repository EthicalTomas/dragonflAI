# Scanning with dragonflAI

dragonflAI integrates Nuclei-based vulnerability scanning as part of the recon pipeline, with safe defaults, scope enforcement, and template pinning designed for bug bounty workflows.

---

## Overview

Scanning is **disabled by default** and requires explicit opt-in. Once enabled, it can be triggered:

- **On-demand** — by selecting the `nuclei` module when starting a recon run.
- **After recon** — automatically after all other pipeline steps complete (opt-in via `scan_mode`).

Scanning never runs on out-of-scope URLs: the scope filter is enforced **in code**, not just policy. A URL cannot reach the nuclei command list unless it passes the `ScopeValidator` for the target.

---

## Enabling Scanning

Scanning is controlled by environment variables (or `.env`):

```env
# Master switch — set to true to allow scans to run
SCAN_ENABLED=true

# When to trigger scanning:
#   on_demand        – only when "nuclei" is explicitly selected as a module
#   auto_after_recon – auto-appended to every pipeline run
SCAN_MODE=on_demand
```

> **Warning:** Never set `SCAN_ENABLED=true` for a target you are not authorised to test.

---

## Safe Defaults

dragonflAI enforces conservative scan parameters that comply with typical bug bounty program rate limits:

| Parameter | Default | Notes |
|-----------|---------|-------|
| Concurrency (`-c`) | 10 | Max parallel HTTP requests |
| Rate limit (`-rl`) | 5 req/s | Requests per second per target |
| Timeout (`-timeout`) | 10 s | Per-request timeout |
| Retries (`-retries`) | 1 | Retry failed requests once |
| Tag allow-list | `cve,misconfig,exposure,takeover` | Only these template categories run |
| Tag deny-list | `dos,fuzz,intrusive,bruteforce` | These are never run |

Hard caps can be configured via environment (must not exceed program limits):

```env
MAX_SCAN_TARGETS=500           # Max URLs fed to a single nuclei invocation
MAX_REQUESTS_PER_MINUTE=5      # Rate limit (req/s passed to -rl)
MAX_SCAN_RUNTIME_SECONDS=3600  # Max wall-clock time for a scan job
MAX_RESPONSE_SIZE_BYTES=1048576  # Max response body captured for evidence
```

---

## Template Pinning

Nuclei templates are pinned to a specific commit via `infra/scanners/templates.lock`:

```
url=https://github.com/projectdiscovery/nuclei-templates
commit=<SHA>
```

Before each scan, `preflight()` verifies that:

1. `docker compose` is available.
2. The templates directory exists at `infra/scanners/nuclei-templates`.
3. The checked-out commit matches the locked SHA.

If any check fails, the scan is aborted with a descriptive error. This ensures reproducibility: the same templates run every time, and any unexpected template update is caught immediately.

To update pinned templates:

```bash
cd infra/scanners/nuclei-templates
git fetch origin
git checkout <new-sha>
# Update the lock file
echo "url=https://github.com/projectdiscovery/nuclei-templates" > ../templates.lock
echo "commit=$(git rev-parse HEAD)" >> ../templates.lock
```

---

## Scope Enforcement (Code-Level)

Scope is enforced at two layers:

1. **URL export** (`scan_preflight_scope_filter`) — before `urls.txt` is written, every URL's hostname is checked against the target's `ScopeValidator`. Out-of-scope URLs are **dropped and logged**, never written to disk.

2. **Default deny** — if no include rules are configured for the target, the export function raises a `RuntimeError` and the scan is refused. A scan cannot run against an unconstrained target.

```
scope rules → ScopeValidator → scan_preflight_scope_filter → urls.txt → nuclei
```

This means that even if an endpoint was incorrectly stored in the database, it will not be scanned unless it passes the scope check.

---

## Running a Scan

### Via the pipeline (recommended)

Select `nuclei` as a module when creating or running a pipeline:

```bash
curl -X POST http://127.0.0.1:8000/runs \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1, "tools": ["subfinder", "httpx", "nuclei"]}'
```

The pipeline will:

1. Run the other selected modules first (subfinder, httpx, …).
2. Export in-scope URLs to `artifacts/<target>/<run>/scan/urls.txt`.
3. Run `nuclei` via Docker Compose with safe defaults.
4. Parse JSONL output and store results as `ScanResult` records.
5. If `AUTO_VERIFY=true`, queue `http_replay` verification jobs for high/critical results.

### Via the API (on-demand scan)

```bash
# Create and immediately queue a scan for a target
curl -X POST http://127.0.0.1:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1}'

# Check status
curl http://127.0.0.1:8000/scans/1
```

### Checking results

```bash
# List results for a scan
curl "http://127.0.0.1:8000/scan-results?scan_id=1"

# Filter by severity
curl "http://127.0.0.1:8000/scan-results?scan_id=1&severity=high"

# Promote a result to a tracked finding
curl -X POST http://127.0.0.1:8000/scan-results/42/promote
```

---

## Artifacts

Evidence files are stored at:

```
artifacts/<target_id>/<run_id>/scan/
├── urls.txt          # Scope-filtered URL list fed to nuclei
└── nuclei.jsonl      # Raw nuclei output (one JSON object per line)
```

The `Scan.config_json` field records the exact configuration used:

```json
{
  "scanner": "nuclei",
  "template_commit": "abc123...",
  "templates_url": "https://github.com/projectdiscovery/nuclei-templates",
  "tags": "cve,misconfig,exposure,takeover",
  "etags": "dos,fuzz,intrusive,bruteforce",
  "flags": {"concurrency": 10, "rate_limit": 5, "timeout": 10, "retries": 1},
  "artifacts_dir": "/tmp/dragonflai_scans/1"
}
```

This config is stored permanently so any scan can be reproduced exactly.

---

## Intrusive Categories (Explicit Opt-In)

The following template categories are denied by default:

- `dos` — denial-of-service tests
- `fuzz` — fuzzing (high request volume)
- `intrusive` — exploits and active attacks
- `bruteforce` — credential brute-forcing

These can only be enabled by modifying the tag allow/deny lists in `backend/app/scans/nuclei_runner.py`. There is no environment variable to enable them; this is intentional to prevent accidental escalation.

> **Policy reminder:** Only use intrusive categories on programs that explicitly permit active testing. Read the program's rules before making any changes.

---

## Deduplication and Severity Normalisation

Each `ScanResult` captures:

- `template_id` — the nuclei template identifier (e.g. `cve-2021-44228`).
- `severity` — normalised to `info / low / medium / high / critical`.
- `matched_url` — the exact URL where the finding was triggered.
- `tags_json` — template tags as a JSON array.
- `evidence_json` — captured request/response excerpts.
- `raw_json` — original nuclei output line.

Duplicates (same endpoint + same template) are deduplicated at the `promote` stage: promoting a `ScanResult` creates a `Finding` that can be further triaged.

---

## Observability

Every scan transition is logged to `Scan.log_text`:

```
[execute_scan] status -> running
[execute_scan] running preflight checks
[execute_scan] exporting URLs
[execute_scan] running nuclei
[execute_scan] parsing results
[execute_scan] done: 12 findings
```

Failed jobs re-raise exceptions so RQ marks them as **failed** — the status is visible in the UI and API with a full traceback stored in `log_text`.

---

## See Also

- [Verification](verification.md) — automated proof stage to reduce false positives.
- [Usage Guide](USAGE.md) — end-to-end workflow: recon → scan → verify → report.
- [Safety & Ethics Policy](safety.md) — scope enforcement and responsible disclosure.
