# dragonflAI Bug Bounty Readiness Audit

**Audit date:** 2026-03-12  
**Repository:** `EthicalTomas/dragonflAI`  
**Auditor:** GitHub Copilot Coding Agent

---

## Verdict

**GO with cautions**

- ✅ Scope enforcement is implemented correctly at the recon-pipeline layer with a default-deny `ScopeValidator` (`backend/app/scope/validator.py`) and a code-level URL filter (`scan_preflight_scope_filter` in `backend/app/scans/url_export.py`).
- ✅ Safety defaults are conservative: scanning is off by default (`scan_enabled=False`), intrusive Nuclei categories are deny-listed in code (`nuclei_runner.py`), and hard rate-limit / concurrency / target caps are enforced.
- ✅ Verification verdicts are conservative: a bare non-5xx response never produces `confirmed`; each vulnerability type has a dedicated proof strategy (`backend/app/verify/vuln_router.py`).
- ✅ Human-review gate is enforced in code: findings cannot be exported or promoted to `ready_to_submit` without `reviewed_by_human=True` (`backend/app/api/routes/findings.py`).
- ⚠️ Three concrete bugs were found and fixed during this audit (see [Remaining Work](#remaining-work-backlog) for details that were resolved by accompanying code changes).
- ⚠️ LLM providers (Ollama, OpenAI, Anthropic) have real implementations but require external services; the default `NullProvider` means AI report enhancement is disabled out-of-the-box.

---

## Checklist

### 1. Scope Enforcement

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `backend/app/scope/validator.py` — `ScopeValidator.check_or_raise()` raises `ScopeViolationError` for out-of-scope hosts. `backend/app/scans/url_export.py` — `scan_preflight_scope_filter()` drops out-of-scope URLs before writing `urls.txt`; raises `RuntimeError` when no include rules are defined (default-deny). `backend/app/runs/orchestrator.py` — aborts with `RunStatus.FAILED` when `scope_text` is empty. ~~`worker/jobs/execute_scan.py`~~ — **fixed in this PR**: scope validator now built from the target's program rules and passed to `export_scan_urls()`. |
| **Risk** | Without scope enforcement at scan time, a misconfigured target could trigger Nuclei against out-of-scope hosts. |
| **Resolved** | `worker/jobs/execute_scan.py` now calls `_build_scope_validator(db, target_id)` and passes the result to `export_scan_urls()`. |

---

### 2. Safety Defaults

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `backend/app/core/config.py`: `scan_enabled=False`, `scan_mode="on_demand"`, `auto_verify=False`, `max_requests_per_minute=5`, `max_scan_targets=500`, `max_scan_runtime_seconds=3600`. `backend/app/scans/nuclei_runner.py`: intrusive tags (`dos`, `fuzz`, `intrusive`, `bruteforce`) are deny-listed in code with no env-var override; enabling them requires a code change. ~~`backend/app/api/routes/scans.py`~~ — **fixed in this PR**: `POST /scans` now returns HTTP 403 when `scan_enabled=False`, closing a kill-switch bypass. |
| **Risk** | Without the API-level `scan_enabled` check, scans could be enqueued even when the operator had disabled scanning. |
| **Resolved** | `create_scan()` route now checks `settings.scan_enabled` and raises `HTTPException(403)` if disabled. |

---

### 3. Scanning Quality

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `infra/scanners/templates.lock` — template pinning to a specific commit SHA. `backend/app/scans/nuclei_runner.py` — `preflight()` verifies the checked-out commit matches the lock file before allowing a scan to proceed. `backend/app/scans/nuclei_parser.py` — raw JSONL stored; `template_id`, `severity`, `matched_url`, `tags_json`, `evidence_json` normalised per result. `backend/app/models/scan.py` — `config_json` persists exact flags, template commit, and tags for reproducibility. ~~`scan_mode=auto_after_recon`~~ — **fixed in this PR**: pipeline now auto-appends `nuclei` to `ordered_modules` when `SCAN_MODE=auto_after_recon` and `SCAN_ENABLED=true`. |
| **Risk** | Without `auto_after_recon` working, the documented workflow was silently ignoring the setting. |
| **Resolved** | `backend/app/runs/pipeline.py` `ReconPipeline.execute()` now checks `settings.scan_mode == "auto_after_recon"` and appends `nuclei` when appropriate. |

---

### 4. Verification / Proof Stage Quality

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `backend/app/verify/vuln_router.py` — per-vulnerability dispatch: open-redirect (canary in `Location`), reflected-XSS (marker in body), sensitive-file (title/body marker), subdomain-takeover (DNS + provider fingerprint), generic (always `inconclusive`). `backend/app/verify/base.py` — `VerificationResult` DTO. `backend/app/verify/screenshot.py` — disabled by default; requires `VERIFY_SCREENSHOT_ENABLED=1` env var and Playwright install. `worker/jobs/execute_verification.py` — scope check runs before any active step. Evidence artefacts written to `artifacts/<target>/<run>/verify/<id>/`. |
| **Risk** | Low — verdict rules are conservative. A bare non-5xx response never produces `confirmed`. |
| **Recommended Fix** | None. Current design is correct. |

---

### 5. Exception Handling and Observability

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | All three job functions (`execute_run`, `execute_scan`, `execute_verification`) follow the same pattern: catch → log exception → set status to `FAILED` → re-raise. Re-raising ensures RQ marks the job as failed and it becomes visible in the RQ dashboard. `backend/app/services/runs_service.py` — `append_log()` persists tracebacks to `Run.log_text`. |
| **Risk** | Low — failures are visible in the RQ failed-job queue and in the run/scan/verification `log_text`. |
| **Recommended Fix** | None critical. Consider adding a `SCAN_ARTIFACTS_DIR` env var to the `.env.example` template. |

---

### 6. UX / Workflow Readiness

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `backend/app/api/routes/findings.py` — `GET /findings/{id}/export` and `POST /findings/{id}/review` enforce the review gate. `backend/app/models/finding.py` — `FindingStatus` lifecycle: `draft → needs_review → ready_to_submit → submitted`. `docs/USAGE.md` — "Before Submitting / Human Review Checklist" section is present. |
| **Risk** | Low — human review is enforced in code, not just policy. |
| **Recommended Fix** | None. |

---

### 7. Documentation Accuracy

| | |
|---|---|
| **Status** | ⚠️ (resolved) |
| **Evidence** | `docs/scanning.md` described `SCAN_MODE=auto_after_recon` as a working trigger mode, but prior to this audit the pipeline code did not implement it. `docs/verification.md` correctly describes conservative verdict rules and screenshot opt-in. |
| **Risk** | Operators who set `SCAN_MODE=auto_after_recon` would have received no scan without any error message. |
| **Resolved** | Pipeline now implements the documented `auto_after_recon` behaviour. |

---

### 8. Dependency and Environment Hygiene

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `requirements.txt` — fully pinned (`pip-compile` style). `requirements-dev.txt` — pinned. `backend/app/runs/preflight.py` — `check_binaries()` verifies subfinder, dnsx, httpx, nmap before pipeline runs. `docs/setup.md` — install instructions for all required binaries. `infra/docker-compose.yml` + `infra/docker-compose.scanners.yml` — scanner services defined. |
| **Risk** | Low. |
| **Recommended Fix** | None critical. `katana` and `gau` tools exist in `backend/app/tools/` but are not yet wired into `AVAILABLE_STEPS`; if added they should be included in `preflight.py`. |

---

### 9. Data Handling and Privacy

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `backend/app/verify/http_replay.py` — `_REDACTED_HEADERS` list covers `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token`, `X-Amz-Security-Token`, `Proxy-Authorization`, `X-Forwarded-Authorization`. `backend/app/core/config.py` — `max_response_size_bytes=1_048_576` (1 MB cap). `backend/app/verify/` — body snippets capped at 2 000 chars in `evidence_json`; `body_truncated` flag set when truncation occurs. |
| **Risk** | Low. |
| **Recommended Fix** | None. |

---

### 10. Legal / Ethics Guardrails

| | |
|---|---|
| **Status** | ✅ |
| **Evidence** | `SECURITY.md` — responsible disclosure policy with 3-day acknowledgement, 7-day triage, 30-day fix SLA for critical/high. `docs/safety.md` — scope enforcement policy, rate-limit policy, data handling, audit log, bug bounty programme rules. `docs/USAGE.md` — ethics reminder on step 1. `LICENSE` — MIT. |
| **Risk** | Low. |
| **Recommended Fix** | None. |

---

## Remaining Work (Backlog)

All P0 items listed below were **resolved by code changes in this PR**.

### P0 — Blocking (Resolved)

| # | Title | Description | File | Acceptance Criteria |
|---|-------|-------------|------|---------------------|
| 1 | Scope enforcement missing in standalone scan job | `execute_scan.py` called `export_scan_urls()` without a `ScopeValidator`. Standalone API scans could target out-of-scope hosts. | `worker/jobs/execute_scan.py` | `_build_scope_validator()` called; `ScopeValidator` passed to `export_scan_urls()`; `RuntimeError` on unconfigured scope. ✅ Fixed |
| 2 | `scan_enabled` kill-switch bypassed by API | `POST /scans` enqueued jobs even when `SCAN_ENABLED=false`. | `backend/app/api/routes/scans.py` | Returns HTTP 403 when `settings.scan_enabled is False`. ✅ Fixed |
| 3 | `scan_mode=auto_after_recon` not implemented | Setting documented and configurable but had no effect in the pipeline. | `backend/app/runs/pipeline.py` | When `SCAN_MODE=auto_after_recon` and `SCAN_ENABLED=true`, nuclei is auto-appended to ordered_modules. ✅ Fixed |

### P1 — Important

| # | Title | Description | File | Acceptance Criteria |
|---|-------|-------------|------|---------------------|
| 4 | `scan_result_id` traceability in Verification | Auto-verify jobs created `Verification` records without linking to the originating `ScanResult`. Resolved in this PR by adding the `scan_result_id` FK column. | `backend/app/models/verification.py`, migration `d4e5f6a7b8c9` | `Verification.scan_result_id` populated for auto-verify records; `GET /verifications?scan_result_id=N` filter works. ✅ Fixed |
| 5 | `katana` and `gau` tools not wired into pipeline | Tool stubs exist (`backend/app/tools/katana.py`, `backend/app/tools/gau.py`) but neither is in `AVAILABLE_STEPS` or `preflight._BINARY_INFO`. | `backend/app/runs/pipeline.py`, `backend/app/runs/preflight.py` | Steps selectable in UI and via API; binary checked at preflight time. |

### P2 — Nice to Have

| # | Title | Description | File | Acceptance Criteria |
|---|-------|-------------|------|---------------------|
| 6 | LLM providers require external services | `NullLLMProvider` is the default; Ollama/OpenAI/Anthropic providers exist but need infrastructure. | `backend/app/llm/` | Out-of-the-box AI report enhancement with at least one local option (Ollama). |
| 7 | No scheduled / recurring scans | Only one-off manual runs supported. | New scheduler module | Cron-like scheduling with notifications for new findings. |
| 8 | `SCAN_ARTIFACTS_DIR` missing from `.env.example` | Environment variable documented in code but not in the template. | `.env.example` | Variable listed with default value `/tmp/dragonflai_scans`. |

---

## Consistency Checks

### Auto-verify severity thresholds match docs

**✅ Consistent.** `docs/verification.md` states default threshold is `"high"` (high and critical auto-verified). `backend/app/core/config.py` sets `auto_verify_min_severity: str = "high"`. `_get_auto_verify_severities()` in `backend/app/runs/pipeline.py` falls back to `"high"` on unknown values and logs a warning — consistent with docs.

### Scan triggering modes match docs

**⚠️ Fixed.** `docs/scanning.md` documented `SCAN_MODE=auto_after_recon` as triggering nuclei after every pipeline run. Before this audit, `backend/app/runs/pipeline.py` had **no code** checking `settings.scan_mode`. After the fix, the pipeline checks `settings.scan_mode == "auto_after_recon"` and auto-appends nuclei when `scan_enabled=True`.

### Verification verdict rules are conservative

**✅ Conservative.** Reviewed in `backend/app/verify/vuln_router.py`, `backend/app/verify/http_replay.py`:
- A bare `200 OK` with no markers → `inconclusive`.
- A `5xx` response with no markers → `unconfirmed`.
- A `4xx` response → `inconclusive`.
- `confirmed` requires finding-specific evidence (canary in Location header, marker in body, provider fingerprint, etc.).
- Generic fallback always returns `inconclusive`.

### Scope validation enforced at scan time (not just recon)

**⚠️ Fixed.** Before this audit, `worker/jobs/execute_scan.py` called `export_scan_urls()` without a `scope_validator`, meaning API-triggered standalone scans bypassed scope enforcement. After the fix, `_build_scope_validator(db, target_id)` builds a `ScopeValidator` from the target's program scope rules and passes it to `export_scan_urls()`. The `default-deny` behavior (`RuntimeError` when no include rules are defined) now applies to all scan entry points.

---

## Notes / Risks

1. **LLM is disabled by default.** `LLM_PROVIDER=null` is the default. AI-enhanced reports and remediation suggestions require an Ollama, OpenAI, or Anthropic provider to be configured. This is a known limitation, not a safety issue.

2. **Template pinning requires a templates directory.** `nuclei_runner.preflight()` will fail if `infra/scanners/nuclei-templates` is not cloned and checked out to the pinned commit. Operators must run `scripts/fetch_nuclei_templates.sh` before scanning.

3. **Screenshot verifier requires Playwright.** `VERIFY_SCREENSHOT_ENABLED=1` alone is not sufficient — `playwright install chromium` must also be run. The code handles the missing package gracefully (returns `inconclusive`) but operators should read `docs/verification.md`.

4. **RQ retry policy.** All jobs are configured with `Retry(max=3, interval=[10, 30, 60])`. A scope-violation failure on the first attempt will be retried twice before the job is marked as definitively failed. This is minor but means a misconfigured scan could consume up to 3 worker slots before failing permanently.

5. **No multi-user auth.** The FastAPI backend has no authentication layer. It is designed as a local-only single-researcher tool. Do **not** expose port 8000 to untrusted networks.
