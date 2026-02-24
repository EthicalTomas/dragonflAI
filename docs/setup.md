# Setup

## Prerequisites

- Python 3.11+
- Docker + Docker Compose
- `pip-tools` (`pip install pip-tools`)

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/EthicalTomas/dragonflAI.git
cd dragonflAI

# 2. Start infrastructure (Postgres + Redis)
docker compose -f infra/docker-compose.yml up -d

# 3. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 4. Install dependencies
pip-compile requirements.in -o requirements.txt
pip install -r requirements.txt

# 5. Copy environment variables
cp .env.example .env

# 6. Run database migrations
cd backend
alembic -c ../migrations/alembic.ini upgrade head
cd ..

# 7. Start the backend API
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload

# 8. Start the RQ worker (separate terminal)
python -m worker.worker

# 9. Start the Streamlit UI (separate terminal)
streamlit run ui/app.py
```

## Quick Start (all-in-one)

```bash
bash scripts/dev.sh
```
