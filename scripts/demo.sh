#!/usr/bin/env bash

set -euo pipefail

echo "========================================"
echo "AccessGate Demo"
echo "========================================"

echo
echo "[1] Enrolling local /usr/bin/curl into TrustStore..."
python3 scripts/enroll_trust_store.py

echo
echo "[2] Building project..."
rm -rf build
cmake -S . -B build -G Ninja
cmake --build build

echo
echo "[3] Starting AccessGate proxy on 127.0.0.1:8080..."

fuser -k 8080/tcp 2>/dev/null || true

./build/accessgate-agent --proxy > accessgate_proxy.log 2>&1 &
PROXY_PID=$!

cleanup() {
    kill "$PROXY_PID" 2>/dev/null || true
}

trap cleanup EXIT

sleep 1

echo "Proxy process PID: $PROXY_PID"

echo
echo "[4] Testing ALLOW request: curl -> public-api.local"
ALLOW_RESPONSE="$(curl -s -i -x http://127.0.0.1:8080 http://public-api.local/status)"
echo "$ALLOW_RESPONSE"

echo "$ALLOW_RESPONSE" | grep -q '"decision": "ALLOW"'
echo "$ALLOW_RESPONSE" | grep -q '"identity_found": true'
echo "$ALLOW_RESPONSE" | grep -q '"trust_status": "TRUSTED"'

echo
echo "[5] Testing DENY request: curl -> internal-api.local"
DENY_RESPONSE="$(curl -s -i -x http://127.0.0.1:8080 http://internal-api.local/data)"
echo "$DENY_RESPONSE"

echo "$DENY_RESPONSE" | grep -q '"decision": "DENY"'
echo "$DENY_RESPONSE" | grep -q '"matched_rule_id": "DENY_INTERNAL_API_FOR_CURL"'
echo "$DENY_RESPONSE" | grep -q '"identity_found": true'
echo "$DENY_RESPONSE" | grep -q '"trust_status": "TRUSTED"'

echo
echo "[6] Recent audit events from SQLite:"
sqlite3 accessgate.db "SELECT id, app, destination, decision, trust_status, compliance_status FROM access_events ORDER BY id DESC LIMIT 10;"

echo
echo "[7] Proxy log:"
cat accessgate_proxy.log

echo
echo "AccessGate demo completed successfully."
