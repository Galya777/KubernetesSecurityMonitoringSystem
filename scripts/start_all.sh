#!/usr/bin/env bash
set -euo pipefail

# start_all.sh - start DB (docker-compose) and then run backend in foreground
# Usage: ./scripts/start_all.sh [PORT]
# Notes:
# - This uses the project's docker-compose.yml to start the `db` service.
# - docker must be installed and running.
# - The docker-compose maps host port 5433 -> container 5432 (see docker-compose.yml),
#   but if that port is unavailable, the script will attempt to use the local Postgres
#   (DB_HOST=localhost, DB_PORT=5432) as a fallback.

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SELF_DIR/.."
cd "$REPO_ROOT"

PORT_ARG=${1:-}
PORT=${PORT_ARG:-8081}

echo "[start_all] working dir: $REPO_ROOT"

USE_LOCAL_DB=false

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "[start_all] attempting to start postgres container (db) via docker compose..."
  if docker compose up -d db 2>&1 | sed -n '1,200p'; then
    echo "[start_all] docker compose started db service"
    PGHOST=localhost
    PGPORT=5433
    PGUSER=postgres
    PGPASSWORD=${PGPASSWORD:-admin123}
    export PGPASSWORD
    echo -n "[start_all] waiting for Postgres on ${PGHOST}:${PGPORT}"
    # wait up to 60s
    for i in {1..60}; do
      if pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" >/dev/null 2>&1; then
        echo " OK"
        break
      fi
      echo -n "."
      sleep 1
      if [ "$i" -eq 60 ]; then
        echo "\n[start_all] timed out waiting for Postgres in docker. Falling back to local Postgres (if available)."
        USE_LOCAL_DB=true
      fi
    done
  else
    echo "[start_all] docker compose failed to start db. Falling back to local Postgres (if available)."
    USE_LOCAL_DB=true
  fi
else
  echo "[start_all] docker or docker compose not available; will try to use local Postgres"
  USE_LOCAL_DB=true
fi

if [ "$USE_LOCAL_DB" = true ]; then
  PGHOST=localhost
  PGPORT=5432
  PGUSER=postgres
  PGPASSWORD=${PGPASSWORD:-admin123}
  export PGPASSWORD
  echo -n "[start_all] checking local Postgres on ${PGHOST}:${PGPORT}"
  # check local Postgres
  for i in {1..30}; do
    if pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" >/dev/null 2>&1; then
      echo " OK"
      break
    fi
    echo -n "."
    sleep 1
    if [ "$i" -eq 30 ]; then
      echo "\n[start_all] timed out waiting for local Postgres. Aborting."
      exit 1
    fi
  done
fi

echo "[start_all] Postgres is ready. Running backend in foreground (you can stop with Ctrl-C)."

# Export env expected by the app
export DB_HOST=${DB_HOST:-$PGHOST}
export DB_PORT=${DB_PORT:-$PGPORT}
export DB_USER=${DB_USER:-$PGUSER}
export DB_PASSWORD=${DB_PASSWORD:-$PGPASSWORD}
export DB_NAME=${DB_NAME:-ksms}
export PORT=${PORT:-$PORT}

# Run backend in foreground so IDE console shows logs and you can stop the process
exec env PGPASSWORD="$DB_PASSWORD" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" DB_NAME="$DB_NAME" PORT="$PORT" go run main.go
