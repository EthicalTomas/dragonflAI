# dragonflAI – Local Setup Guide

Step-by-step instructions for running dragonflAI on Linux.

---

## 1. Prerequisites

Install the following tools before proceeding.

### Python 3.11+

```bash
python3 --version   # must be 3.11 or newer
```

Download from <https://www.python.org/downloads/> or use your distro's package manager.

### Docker and Docker Compose

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

### Recon tools

| Tool | Purpose | Install |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) (CLI) | HTTP probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [nmap](https://nmap.org/) | Port/service scanning | `sudo apt install nmap` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution & brute-force | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |

> **Note:** The Go-based tools (subfinder, httpx, dnsx) require Go 1.21+.  
> Ensure `$(go env GOPATH)/bin` is on your `PATH`.

---

## 2. Clone and Configure

```bash
git clone https://github.com/EthicalTomas/dragonflAI.git
cd dragonflAI
cp .env.example .env
```

Open `.env` and adjust the values for your environment:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://dragonflai:dragonflai_dev@localhost:5433/dragonflai` | SQLAlchemy connection string for PostgreSQL. The default matches the Docker Compose service on port **5433**. |
| `REDIS_URL` | `redis://localhost:6380/0` | Redis connection URL. The default matches the Docker Compose service on port **6380**. |
| `BACKEND_HOST` | `127.0.0.1` | Host the FastAPI backend binds to. |
| `BACKEND_PORT` | `8000` | Port the FastAPI backend listens on. |
| `BACKEND_URL` | `http://127.0.0.1:8000` | URL the Streamlit UI uses to reach the backend API. Must match `BACKEND_HOST` and `BACKEND_PORT`. |
| `UI_HOST` | `127.0.0.1` | Host the Streamlit UI binds to. |
| `UI_PORT` | `8501` | Port the Streamlit UI listens on. |

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

Both containers (`dragonflai-postgres` on port 5433, `dragonflai-redis` on port 6380) should show a **healthy** status before continuing.

---

## 4. Install Python Dependencies

Create a virtual environment, activate it, and install all required packages:

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.in
```

You are now ready to run the backend and worker. Refer to the project README for the next steps.
