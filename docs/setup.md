# dragonflAI — Setup Guide

Step-by-step instructions for running dragonflAI on Linux.

---

## 1. Prerequisites

Install the following tools before proceeding.

### Python 3.11+

```bash
python3 --version   # must be 3.11 or newer
```

Download from <https://www.python.org/downloads/> or use your distro's package manager.

### Docker + Docker Compose v2

```bash
docker --version
docker compose version   # v2 plugin (ships with Docker Desktop / Engine ≥ 23)
```

Follow the official guide: <https://docs.docker.com/engine/install/>

### uv (Python package manager)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv --version
```

Docs: <https://docs.astral.sh/uv/>

### Git

```bash
git --version
```

Install via your distro's package manager if not already present (e.g. `sudo apt install git`).

### Recon tools (installed on host)

| Tool | Install |
|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) (CLI) | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| [nmap](https://nmap.org/) | `sudo apt install nmap` |

> **Note:** Go 1.21+ is required for the ProjectDiscovery tools (subfinder, httpx, dnsx).  
> Ensure `$HOME/go/bin` is on your `PATH`: `export PATH=$PATH:$HOME/go/bin`

---

## 2. Clone & Configure

```bash
git clone https://github.com/EthicalTomas/dragonflAI.git && cd dragonflAI
cp .env.example .env
```

Open `.env` and adjust the values for your environment:

| Variable | Description |
|---|---|
| `DATABASE_URL` | Postgres connection string. The default uses port **5433** to avoid conflict with a locally-installed Postgres instance. |
| `REDIS_URL` | Redis connection URL. The default uses port **6380**. |
| `BACKEND_HOST` | Host the FastAPI server binds to. |
| `BACKEND_PORT` | Port the FastAPI server listens on. |
| `BACKEND_URL` | URL used by Streamlit to reach the API. Must match `BACKEND_HOST` and `BACKEND_PORT`. |
| `UI_HOST` | Host the Streamlit server binds to. |
| `UI_PORT` | Port the Streamlit server listens on. |

The defaults work out-of-the-box for a local single-machine setup.

---

## 3. Start Infrastructure

Bring up the PostgreSQL and Redis containers in the background:

```bash
docker compose -f infra/docker-compose.yml up -d
```

Verify both services are healthy:

```bash
docker compose -f infra/docker-compose.yml ps
```

Both containers should show a **healthy** status before continuing.

Test Postgres connectivity:

```bash
psql -h localhost -p 5433 -U dragonflai -d dragonflai
```

Test Redis connectivity:

```bash
redis-cli -p 6380 ping   # expected output: PONG
```

---

## 4. Install Python Dependencies

Create a virtual environment, activate it, and install all required packages:

```bash
uv venv && source .venv/bin/activate
uv pip install -r requirements.in
```

---

## 5. Run Database Migrations

Apply all pending migrations to bring the schema up to date:

```bash
alembic -c migrations/alembic.ini upgrade head
```

To create a new migration after changing models:

```bash
alembic -c migrations/alembic.ini revision --autogenerate -m "description"
```

---

## 6. Start the Application

Open three terminal windows (all with the virtualenv activated):

**Terminal 1 — API:**

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

**Terminal 2 — Worker:**

```bash
python -m worker.worker
```

**Terminal 3 — UI:**

```bash
streamlit run ui/app.py --server.port 8501
```

Or start everything with the dev script:

```bash
./scripts/dev.sh all
```

**Access:**

| Service | URL |
|---|---|
| API | <http://127.0.0.1:8000> |
| API docs (Swagger) | <http://127.0.0.1:8000/docs> |
| UI | <http://127.0.0.1:8501> |

---

## 7. Verify Everything Works

1. Open the UI at <http://127.0.0.1:8501>.
2. Create a **Program**.
3. Add a **Target** with one or more root domains.
4. Start a dummy run and confirm it transitions from **queued → running → succeeded**.
5. Check the API docs at <http://127.0.0.1:8000/docs> and exercise a few endpoints.

---

## 8. Vulnerability Reports

dragonflAI lets you document findings and produce polished reports without leaving the tool.

### Creating a Finding

**Via the UI:** Open the **Findings** page, click **New Finding**, fill in the required fields (title, affected endpoint, severity, steps to reproduce, impact), and optionally enter a CVSS vector string. Save to create the finding.

**Via the API (`POST /findings`):**

```bash
curl -X POST http://127.0.0.1:8000/findings \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Reflected XSS in search parameter",
    "target_id": 1,
    "affected_endpoint": "https://example.com/search?q=",
    "severity": "medium",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "steps_to_reproduce": "1. Navigate to the search page\n2. Enter <script>alert(1)</script> in the q parameter\n3. Observe JS execution",
    "impact": "Attacker can execute arbitrary JavaScript in the victim browser.",
    "remediation": "Encode all user-supplied output before rendering in HTML context."
  }'
```

The system auto-calculates the CVSS score and severity label from the vector string before saving.

---

### Report Template Types

| Template | Best for |
|---|---|
| `full` | Comprehensive report with all details — for your records. |
| `platform` | Formatted for HackerOne/Bugcrowd submission — copy-paste ready. |
| `summary` | Short summary — for quick triage. |

Generate a report via the API:

```bash
curl -X POST http://127.0.0.1:8000/findings/{finding_id}/generate-report \
  -H "Content-Type: application/json" \
  -d '{"template": "platform"}'
```

---

### CVSS Scoring

Enter a **CVSS 3.1 base vector string** when creating or updating a finding. The system parses the vector and automatically calculates the numeric score and severity label.

**Example vectors:**

| Vulnerability | Vector | Score | Severity |
|---|---|---|---|
| Reflected XSS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium |
| SSRF (internal) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | 8.6 | High |
| IDOR | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | Medium |
| RCE | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |

---

### Exporting

Download the generated report in Markdown or plain text:

```bash
# Markdown (.md)
curl "http://127.0.0.1:8000/findings/{finding_id}/export?format=markdown" -o report.md

# Plain text (.txt)
curl "http://127.0.0.1:8000/findings/{finding_id}/export?format=plaintext" -o report.txt
```

---

### Batch Reports

Generate a combined assessment report for all findings:

```bash
curl -X POST http://127.0.0.1:8000/findings/batch-report \
  -H "Content-Type: application/json" \
  -d '{
    "finding_ids": [1, 2, 3],
    "template": "full"
  }'
```

The batch report includes a severity breakdown header followed by each individual finding separated by a horizontal rule.

---

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| **Port conflict** | Change the conflicting port in `.env` and `infra/docker-compose.yml`, then restart the containers. |
| **Postgres connection refused** | Ensure the Docker container is running and healthy: `docker compose -f infra/docker-compose.yml ps`. |
| **Recon tool not found** | Ensure Go tools are on your PATH: `export PATH=$PATH:$HOME/go/bin` (add to `~/.bashrc` or `~/.zshrc` to persist). |
| **Alembic migration errors** | Ensure all SQLAlchemy models are imported in `migrations/env.py` before running migrations. |
| **Worker not picking up jobs** | Ensure Redis is reachable (`redis-cli -p 6380 ping`) and the worker is listening on the `recon` queue. |
