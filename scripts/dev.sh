#!/usr/bin/env bash
# dev.sh — start all dragonflAI services for local development
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Starting infrastructure (Postgres + Redis)..."
docker compose -f "$REPO_ROOT/infra/docker-compose.yml" up -d

echo "==> Waiting for Postgres to be ready..."
sleep 3

echo "==> Running Alembic migrations..."
(cd "$REPO_ROOT/backend" && alembic -c "$REPO_ROOT/migrations/alembic.ini" upgrade head)

echo "==> Starting backend API (uvicorn)..."
uvicorn app.main:app --app-dir "$REPO_ROOT/backend" --host 127.0.0.1 --port 8000 --reload &
UVICORN_PID=$!

echo "==> Starting RQ worker..."
(cd "$REPO_ROOT" && python -m worker.worker) &
WORKER_PID=$!

echo "==> Starting Streamlit UI..."
streamlit run "$REPO_ROOT/ui/app.py" &
UI_PID=$!

echo ""
echo "Services running:"
echo "  Backend  → http://127.0.0.1:8000/docs"
echo "  UI       → http://127.0.0.1:8501"
echo ""
echo "Press Ctrl+C to stop all services."

trap "kill $UVICORN_PID $WORKER_PID $UI_PID 2>/dev/null; docker compose -f $REPO_ROOT/infra/docker-compose.yml down" EXIT
wait
