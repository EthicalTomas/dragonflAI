#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: required command '$1' not found in PATH." >&2
    exit 1
  }
}

usage() {
  cat <<EOF
Usage: $0 <command> [args]

Commands:
  infra            Start infrastructure services (docker compose)
  api              Start API server on port 8000 (uvicorn, with --reload)
  worker           Start background worker
  ui               Start Streamlit UI on port 8501
  migrate          Run database migrations (alembic upgrade head)
  makemigration    Generate a new migration (requires a message argument)
  all              Start infra, then api, worker, and ui in the background
  help             Show this help message
EOF
}

case "${1:-}" in
  infra)
    require_cmd docker
    docker compose -f infra/docker-compose.yml up -d
    ;;
  api)
    require_cmd uvicorn
    uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
    ;;
  worker)
    require_cmd python
    python -m worker.worker
    ;;
  ui)
    require_cmd streamlit
    streamlit run ui/app.py --server.port 8501
    ;;
  migrate)
    require_cmd alembic
    alembic -c migrations/alembic.ini upgrade head
    ;;
  makemigration)
    require_cmd alembic
    if [ -z "${2:-}" ]; then
      echo "Error: makemigration requires a message argument." >&2
      usage
      exit 1
    fi
    alembic -c migrations/alembic.ini revision --autogenerate -m "$2"
    ;;
  all)
    require_cmd docker
    require_cmd uvicorn
    require_cmd python
    require_cmd streamlit
    require_cmd pg_isready
    require_cmd redis-cli
    docker compose -f infra/docker-compose.yml up -d

    INFRA_TIMEOUT="${INFRA_WAIT_SECONDS:-60}"
    echo "Waiting up to ${INFRA_TIMEOUT}s for Postgres..."
    deadline=$(( $(date +%s) + ${INFRA_TIMEOUT} ))
    until pg_isready -h 127.0.0.1 -p 5433 -U dragonflai -d dragonflai >/dev/null 2>&1; do
      if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "Error: Postgres was not ready after ${INFRA_TIMEOUT}s." >&2
        exit 1
      fi
      sleep 1
    done
    echo "Postgres is ready."

    echo "Waiting up to ${INFRA_TIMEOUT}s for Redis..."
    deadline=$(( $(date +%s) + ${INFRA_TIMEOUT} ))
    until redis-cli -h 127.0.0.1 -p 6380 ping >/dev/null 2>&1; do
      if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "Error: Redis was not ready after ${INFRA_TIMEOUT}s." >&2
        exit 1
      fi
      sleep 1
    done
    echo "Redis is ready."

    uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000 &
    API_PID=$!
    python -m worker.worker &
    WORKER_PID=$!
    streamlit run ui/app.py --server.port 8501 &
    UI_PID=$!
    echo "Started api     PID: $API_PID"
    echo "Started worker  PID: $WORKER_PID"
    echo "Started ui      PID: $UI_PID"
    ;;
  help|"")
    usage
    exit 0
    ;;
  *)
    echo "Error: Unknown command '$1'" >&2
    usage
    exit 1
    ;;
esac
