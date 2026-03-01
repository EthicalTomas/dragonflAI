# 🐉 dragonflAI

> AI-assisted bug bounty hunting platform

## What is dragonflAI?

dragonflAI is a local-first, lightweight platform that automates recon, organizes findings, detects potential vulnerabilities using heuristics, and generates professional reports for bug bounty submissions.

- Designed to run on modest hardware (8GB RAM, no GPU required).
- No cloud dependency — runs entirely on your machine.

## Features

- ✅ Program & target management with scope enforcement.
- ✅ Recon pipeline: subfinder, httpx, dnsx, nmap (pluggable architecture).
- ✅ Asset & endpoint storage with upsert and deduplication.
- ✅ Burp Suite & OWASP ZAP import.
- ✅ Heuristic vulnerability detection (interesting params, paths, headers).
- ✅ Auto-generation of draft findings from detection signals.
- ✅ Vulnerability report generation (full, platform-ready, summary).
- ✅ CVSS 3.1 scoring.
- ✅ Run-to-run diffing (new/removed/changed assets and endpoints).
- ✅ Background job execution with live progress.
- ✅ LLM adapter interface (upgrade-ready, no LLM required).
- ✅ Streamlit web UI + FastAPI backend.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Streamlit   │────▶│   FastAPI     │────▶│  Postgres   │
│  UI (:8501)  │     │  API (:8000)  │     │  (:5433)    │
└─────────────┘     └──────┬───────┘     └─────────────┘
                           │
                    ┌──────▼───────┐     ┌─────────────┐
                    │  RQ Worker   │────▶│   Redis     │
                    │              │     │  (:6380)    │
                    └──────┬───────┘     └─────────────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
          subfinder     httpx       nmap
            dnsx        burp        zap
```

## Quick Start

**Prerequisites:** Python 3.11+, Docker, uv.

```bash
git clone https://github.com/EthicalTomas/dragonflAI.git
cd dragonflAI
cp .env.example .env
docker compose -f infra/docker-compose.yml up -d
uv venv && source .venv/bin/activate
uv pip install -r requirements.in
alembic -c migrations/alembic.ini upgrade head
./scripts/dev.sh all
```

Open <http://127.0.0.1:8501>.

## Documentation

- [Usage guide](docs/USAGE.md)
- [Full setup guide](docs/setup.md)
- [Ethics and guardrails](docs/safety.md)
- [Planned features](docs/roadmap.md)

## Safety & Ethics

dragonflAI enforces scope validation before any tool execution. Default deny: nothing runs without defined scope rules. Built for authorized testing only.

See [docs/safety.md](docs/safety.md) for full policy.

## License

[MIT](LICENSE) (SPDX: `MIT`)
