#!/usr/bin/env bash
set -eu
# start_demo.sh
# Kills old server, builds binary, ensures local auth file exists (or creates via helper), starts server and attempts a login test.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "Stopping previous server (if any)..."
if [ -f run_server.pid ]; then
  pid=$(cat run_server.pid)
  echo "Killing PID $pid"
  kill -9 "$pid" || true
  rm -f run_server.pid
fi
pkill -f ksms-local || true
pkill -f 'go run main.go' || true
pkill -f '/.cache/go-build/.*/main' || true
sleep 1

echo "Building binary..."
go build -o ksms-local .

# If there is no local users file, create one with a demo admin using helper
LOCAL_FILE=".local_users_demo.json"
if [ ! -f "$LOCAL_FILE" ]; then
  echo "Local auth file not found, creating demo admin..."
  if [ -f scripts/add_local_user.go ]; then
    go run scripts/add_local_user.go -email=demo-admin@local -password=demoPass123 -file="$LOCAL_FILE"
  else
    cat > "$LOCAL_FILE" <<'JSON'
[
]
JSON
  fi
else
  echo "Using existing $LOCAL_FILE"
fi

# Start server
PORT=8081 LOCAL_AUTH_FILE="$LOCAL_FILE" nohup ./ksms-local > run_server.log 2>&1 &
echo $! > run_server.pid
sleep 1

echo "Server started (PID $(cat run_server.pid)). Tail of run_server.log:"
sed -n '1,200p' run_server.log || true

# Try to login with demo credentials (if present)
echo
echo "Testing login (demo-admin@local / demoPass123) ..."
curl -v -s -X POST "http://localhost:8081/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo-admin@local","password":"demoPass123"}' -w '\nHTTP_STATUS:%{http_code}\n' || true

echo

echo "If login returns 200 and a token JSON, you're good."

echo "If not, inspect run_server.log and the JSON file ($LOCAL_FILE)."

exit 0

