# AccessGate Demo Guide

This document explains how to run the current AccessGate MVP demo.

AccessGate currently demonstrates:

- JSON-based access policy evaluation
- executable trust verification using SHA256
- endpoint compliance checking
- final access decision generation through DecisionEngine
- SQLite audit logging
- local HTTP proxy enforcement
- Linux process identity resolution using /proc socket-to-PID mapping

---

## 1. Build the Project

Run:

~~~bash
rm -rf build
cmake -S . -B build -G Ninja
cmake --build build
~~~

Expected result:

~~~text
[9/9] Linking CXX executable accessgate-agent
~~~

OpenSSL SHA256 deprecation warnings may appear. These are warnings, not build errors.

---

## 2. Run Console Decision Demo

Run:

~~~bash
./build/accessgate-agent
~~~

This runs AccessGate in normal console mode.

It demonstrates:

~~~text
trusted curl + public-api.local   => ALLOW
trusted curl + internal-api.local => DENY
unknown app                       => DENY
wrong executable path             => DENY
~~~

The decisions are also written to the SQLite audit database.

---

## 3. Run Proxy Mode

Terminal 1:

~~~bash
./build/accessgate-agent --proxy
~~~

Expected output:

~~~text
AccessGate local proxy listening on 127.0.0.1:8080
~~~

Keep this terminal running.

---

## 4. Test ALLOW Request

Open Terminal 2.

Run:

~~~bash
cd ~/omnissa-projects/accessgate
curl -i -x http://127.0.0.1:8080 http://public-api.local/status
~~~

Expected result:

~~~text
HTTP/1.1 200 OK
~~~

Expected JSON fields:

~~~json
{
  "decision": "ALLOW",
  "destination": "public-api.local",
  "identity_found": true,
  "trust_status": "TRUSTED",
  "compliance_status": "HEALTHY"
}
~~~

Meaning:

~~~text
curl is trusted
device is healthy
policy allows public-api.local
therefore request is allowed
~~~

---

## 5. Test DENY Request

Run:

~~~bash
curl -i -x http://127.0.0.1:8080 http://internal-api.local/data
~~~

Expected result:

~~~text
HTTP/1.1 403 Forbidden
~~~

Expected JSON fields:

~~~json
{
  "decision": "DENY",
  "destination": "internal-api.local",
  "identity_found": true,
  "trust_status": "TRUSTED",
  "matched_rule_id": "DENY_INTERNAL_API_FOR_CURL"
}
~~~

Meaning:

~~~text
curl is trusted
device is healthy
but policy denies curl from accessing internal-api.local
therefore request is blocked
~~~

---

## 6. Verify SQLite Audit Logs

Run:

~~~bash
sqlite3 accessgate.db "SELECT id, app, destination, decision, trust_status, compliance_status FROM access_events ORDER BY id DESC LIMIT 10;"
~~~

Expected rows:

~~~text
curl|public-api.local|ALLOW|TRUSTED|HEALTHY
curl|internal-api.local|DENY|TRUSTED|HEALTHY
~~~

This proves that AccessGate stores every access decision.

---

## 7. Run One-Command Demo Script

Run:

~~~bash
./scripts/demo.sh
~~~

The script should:

1. Build the project
2. Start the proxy
3. Send an ALLOW request
4. Send a DENY request
5. Print recent SQLite audit events
6. Stop the proxy

---

## 8. Current MVP Flow

Current verified flow:

~~~text
curl request
    -> AccessGate LocalProxy
    -> ProcessIdentityResolver
    -> /proc/net/tcp socket lookup
    -> socket inode
    -> /proc/<pid>/fd PID mapping
    -> process name and executable path
    -> TrustStore SHA256 verification
    -> ComplianceChecker
    -> PolicyEngine
    -> DecisionEngine
    -> ALLOW / DENY
    -> SQLiteAuditStore
~~~

---

## 9. Important Limitation

The current LocalProxy MVP supports HTTP proxy-style requests.

HTTPS CONNECT tunneling is not fully implemented yet.

This is acceptable for the current MVP because the main focus is:

~~~text
process identity
+ executable trust
+ endpoint compliance
+ policy enforcement
+ audit logging
~~~

not full TLS interception.

---

## 10. Current Completion Estimate

Current AccessGate completion:

~~~text
85%
~~~

After documentation, demo script, and README cleanup:

~~~text
90%
~~~

Remaining work:

~~~text
HTTPS CONNECT handling
unit tests
GitHub Actions build check
mock UEM backend/dashboard
final README and interview polish
~~~
