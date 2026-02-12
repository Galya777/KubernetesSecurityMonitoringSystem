#!/usr/bin/env bash
set -euo pipefail

# run_backend.sh - run backend (main.go) with sensible defaults for env vars
# Usage: ./scripts/run_backend.sh [PORT]
PORT=${1:-8081}
export DB_HOST=${DB_HOST:-localhost}
export DB_PORT=${DB_PORT:-5432}
export DB_USER=${DB_USER:-postgres}
export DB_PASSWORD=${DB_PASSWORD:-admin123}
export DB_NAME=${DB_NAME:-ksms}
export PORT

echo "[run_backend] Running backend on :$PORT connecting to $DB_HOST:$DB_PORT"
exec env PGPASSWORD="$DB_PASSWORD" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" DB_NAME="$DB_NAME" PORT="$PORT" go run main.go

