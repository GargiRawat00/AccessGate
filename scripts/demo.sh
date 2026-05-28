#!/usr/bin/env bash

set -e

echo "========================================"
echo "AccessGate Demo"
echo "========================================"

echo
echo "[1] Building project..."
rm -rf build
cmake -S . -B build -G Ninja
cmake --build build

echo
echo "[2] Starting AccessGate proxy on 127.0.0.1:8080..."
echo "    This script will start the proxy in the background."
echo

fuser -k 8080/tcp 2>/dev/null || true

./build/accessgate-agent --proxy > accessgate_proxy.log 2>&1 &
PROXY_PID=$!

sleep 1

echo "[3] Proxy process PID: $PROXY_PID"
echo

echo "[4] Testing ALLOW request:"
echo "    curl -> public-api.local"
echo

curl -i -x http://127.0.0.1:8080 http://public-api.local/status || true

echo
echo
echo "[5] Testing DENY request:"
echo "    curl -> internal-api.local"
echo

curl -i -x http://127.0.0.1:8080 http://internal-api.local/data || true

echo
echo
echo "[6] Recent audit events from SQLite:"
echo

sqlite3 accessgate.db "SELECT id, app, destination, decision, trust_status, compliance_status FROM access_events ORDER BY id DESC LIMIT 10;"

echo
echo "[7] Proxy log:"
echo

cat accessgate_proxy.log

echo
echo "[8] Stopping proxy..."
kill $PROXY_PID 2>/dev/null || true

echo
echo "AccessGate demo completed."
