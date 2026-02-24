# Roadmap

## v0.1 — Scaffold (current)
- [x] Project structure
- [x] FastAPI backend with Programs / Targets / Runs CRUD
- [x] RQ worker skeleton
- [x] Streamlit UI skeleton
- [x] Alembic migrations setup
- [x] Scope parser + validator
- [x] Tool wrappers: subfinder, httpx, nmap, dnsx
- [x] Output parsers: subfinder, httpx, nmap, Burp, ZAP
- [x] LLM stub (NullLLMProvider)

## v0.2 — Live Recon
- [ ] Wire tool wrappers into `runs/orchestrator.py`
- [ ] Persist discovered subdomains and endpoints to the DB
- [ ] Real-time run log streaming via SSE or WebSocket
- [ ] Asset browser UI page (page 4)

## v0.3 — Analysis
- [ ] Run-to-run diff engine
- [ ] Diff viewer UI page (page 6)
- [ ] Endpoint fingerprinting and severity tagging

## v0.4 — LLM Integration
- [ ] OpenAI / Ollama LLM provider implementations
- [ ] AI-assisted triage suggestions
- [ ] Natural language scope input

## v0.5 — Polish
- [ ] Authentication (API key or OAuth)
- [ ] Docker image for backend + worker
- [ ] CI/CD pipeline
