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

---

## Vulnerability Reports

dragonflAI lets you document findings and produce polished reports without leaving the tool.

### Creating a Finding

**Via the UI:** Open the **Findings** page, click **New Finding**, and fill in the title, affected endpoint, severity, steps to reproduce, impact, and (optionally) a CVSS vector string. Save to create the finding.

**Via the API:**

```bash
curl -X POST http://localhost:8000/findings \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Reflected XSS in search parameter",
    "target_id": 1,
    "affected_endpoint": "https://example.com/search?q=",
    "severity": "medium",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "steps_to_reproduce": "1. Navigate to the search page\n2. Enter <script>alert(1)</script> in the q parameter\n3. Observe JS execution",
    "impact": "Attacker can execute arbitrary JavaScript in the victim's browser.",
    "remediation": "Encode all user-supplied output before rendering in HTML context."
  }'
```

The system auto-calculates the CVSS score and severity label from the vector string before saving.

---

### Generating Reports

Call the generate-report endpoint (or click **Generate Report** on the Finding detail page) and choose a template:

```bash
curl -X POST http://localhost:8000/findings/{finding_id}/generate-report \
  -H "Content-Type: application/json" \
  -d '{"template": "platform"}'
```

| Template | Best for |
|---|---|
| `full` | Comprehensive report with all details — keep this for your own records. |
| `platform` | Formatted for bug bounty platform submission (HackerOne / Bugcrowd style) — copy-paste ready. |
| `summary` | Short one-liner summary — for quick triage and internal review. |

---

### CVSS Scoring

Enter a **CVSS 3.1 base vector string** when creating or updating a finding. The system parses the vector and automatically calculates the numeric score and severity label.

**Format:** `CVSS:3.1/AV:<V>/AC:<V>/PR:<V>/UI:<V>/S:<V>/C:<V>/I:<V>/A:<V>`

**Common examples:**

| Vulnerability type | Example vector | Score | Severity |
|---|---|---|---|
| Reflected XSS (no auth) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium |
| SQL Injection (auth required) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High |
| Unauthenticated RCE | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| IDOR (limited data) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | 4.3 | Medium |
| Local privilege escalation | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 | High |

Severity thresholds: **Critical** ≥ 9.0 · **High** ≥ 7.0 · **Medium** ≥ 4.0 · **Low** ≥ 0.1 · **Informational** = 0.0.

---

### Exporting

Download the generated report in two formats:

```bash
# Markdown (default)
curl "http://localhost:8000/findings/{finding_id}/export?format=markdown" -o report.md

# Plain text (markdown stripped)
curl "http://localhost:8000/findings/{finding_id}/export?format=plaintext" -o report.txt
```

Files are saved under `artifacts/{target_id}/reports/` on the server.

---

### Batch Reports

Generate a single combined assessment report for all findings in a target:

```bash
curl -X POST http://localhost:8000/findings/batch-report \
  -H "Content-Type: application/json" \
  -d '{
    "finding_ids": [1, 2, 3],
    "template": "full"
  }'
```

The batch report includes a header with a severity breakdown (critical / high / medium / low counts), followed by each individual finding report separated by a horizontal rule.

---

### LLM Enhancement *(future)*

When an LLM provider is configured in your `.env`, dragonflAI will automatically enhance each generated report for clarity and professionalism — tightening the impact statement, suggesting concrete remediation steps, and improving readability — without altering the factual content. No extra steps needed; the enhancement runs transparently after the base template is rendered. With the default configuration (no provider set), standard template output is used.

---

### Example Workflow

```
1. Discover a vulnerability during recon or manual testing.

2. Create a finding:
   POST /findings  (or use the Findings page in the UI)
   Include your CVSS vector — the score is calculated automatically.

3. Generate a report:
   POST /findings/{id}/generate-report  {"template": "platform"}

4. Export the report:
   GET /findings/{id}/export?format=markdown

5. Submit:
   Open the exported .md file, copy the contents, and paste into
   HackerOne, Bugcrowd, or your client's reporting portal.
```
