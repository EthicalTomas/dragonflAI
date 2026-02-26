#!/usr/bin/env bash
set -e

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
    docker compose -f infra/docker-compose.yml up -d
    ;;
  api)
    uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
    ;;
  worker)
    python -m worker.worker
    ;;
  ui)
    streamlit run ui/app.py --server.port 8501
    ;;
  migrate)
    alembic -c migrations/alembic.ini upgrade head
    ;;
  makemigration)
    if [ -z "${2:-}" ]; then
      echo "Error: makemigration requires a message argument." >&2
      usage
      exit 1
    fi
    alembic -c migrations/alembic.ini revision --autogenerate -m "$2"
    ;;
  all)
    docker compose -f infra/docker-compose.yml up -d
    echo "Waiting ${INFRA_WAIT_SECONDS:-5} seconds for infrastructure to be ready..."
    sleep "${INFRA_WAIT_SECONDS:-5}"
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
