# dragonflAI Roadmap

## Milestone 1: Foundation ✅

- Docker Compose infrastructure (Postgres 5433, Redis 6380).
- FastAPI backend skeleton.
- SQLAlchemy models + Alembic migrations.
- RQ worker with dummy job.
- Streamlit UI shell (Programs, Targets, Runs pages).
- LLM adapter interface with NullProvider.

## Milestone 2: Recon Pipeline 🔄

- Tool wrappers: subfinder, httpx, dnsx, nmap.
- Output parsers for each tool.
- Asset storage with upsert logic.
- Endpoint storage with upsert logic.
- Pipeline orchestrator (ordered module execution).
- Scope parsing and validation (safety guardrail).
- Updated UI: Assets page, Endpoints page with filters and parameter analysis.

## Milestone 3: Detection & Reporting 🔄

- Heuristic-based vulnerability detection.
- Pattern matching (interesting params, paths, headers).
- Auto-generation of draft findings from signals.
- Vulnerability report generation (full, summary, platform templates).
- CVSS 3.1 calculator.
- Report export (Markdown, plain text).
- Batch assessment reports.
- Updated UI: Detection page, Findings page, Reports page.

## Milestone 4: Import & Diff 📋

- Burp Suite XML import + parser.
- OWASP ZAP JSON/XML import + parser.
- Run-to-run diffing (new/removed/changed assets and endpoints).
- Diff UI page with visual indicators.

## Milestone 5: LLM Integration ✅

- Ollama provider (local, free).
- OpenAI / Anthropic providers (paid, optional).
- LLM-enhanced report generation (improve clarity, suggest remediation).
- LLM provider factory (`build_llm_provider()`) reads from `.env`.
- RAG: index artifacts + notes into pgvector, "ask your recon data" chat. 📋
- Chat UI page. 📋

## Milestone 6: Advanced Features 🔄

- Katana web crawler tool (endpoint discovery, JS route extraction). ✅
- GAU / Wayback Machine historical URL discovery. ✅
- Scheduled/recurring recon runs. 📋
- Notification system (new assets, new high-confidence signals). 📋
- Additional tools: ffuf, nuclei template management. 📋
- Mobile target support (APK/IPA endpoint extraction). 📋
- Multi-user support (if needed). 📋
- Dashboard with historical trends. 📋

## Status Legend

- ✅ Complete
- 🔄 In progress
- 📋 Planned
