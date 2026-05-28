# AccessGate

AccessGate is a C++20 endpoint access-control project designed around the idea of **per-app Zero Trust network access**.

The project simulates how an endpoint agent can decide whether a local application should be allowed to access a protected destination based on:

1. Application identity  
2. Destination resource  
3. Endpoint compliance state  
4. Policy rules  
5. Executable trust status  
6. Auditability of every access decision  

The long-term goal is to build a lightweight endpoint agent inspired by enterprise endpoint-management and per-app tunnel systems, where access is not granted only because a machine is connected to the network, but because the application, device state, and policy all satisfy access requirements.

---

## Current Project Status

### Completed

- C++20 project setup
- CMake + Ninja build configuration
- Dependency integration:
  - `nlohmann/json`
  - `SQLite3`
  - `OpenSSL`
  - `Boost`
- JSON-based access policy file
- PolicyEngine MVP
- Access decision evaluation based on:
  - application name
  - destination
  - endpoint compliance state
  - default deny behavior
- GitHub repository setup

### Current Working Module

The current implementation focuses on the first core module:

```text
PolicyEngine
```

The PolicyEngine loads rules from:

```text
config/access_policy.json
```

and evaluates whether a request should be allowed or denied.

---

## Why This Project Exists

A normal firewall usually works with:

```text
IP address
port number
protocol
```

For example:

```text
allow TCP port 443
block port 22
allow traffic to 10.0.0.5
```

AccessGate asks a more endpoint-aware question:

```text
Should this specific application on this specific endpoint be allowed to access this specific destination right now?
```

That means the decision is not only based on the network. It is based on:

```text
which application is making the request
where it wants to connect
whether the endpoint is compliant
whether the application binary is trusted
what the access policy says
```

This makes AccessGate different from a basic proxy, firewall rule, or shell-script-based network blocker.

---

## High-Level Goal

The final version of AccessGate should behave like a small endpoint access-control agent.

Expected final flow:

```text
Application tries to access destination
        |
        v
AccessGate identifies the application
        |
        v
AccessGate verifies executable trust
        |
        v
AccessGate checks endpoint compliance
        |
        v
AccessGate evaluates access policy
        |
        v
Decision: ALLOW or DENY
        |
        v
Decision is stored in local audit database
        |
        v
Decision is reported to mock UEM control plane
```

---

## Current Working Demo

The current demo runs inside `src/main.cpp`.

It creates sample access requests and sends them to the PolicyEngine.

### Demo Case 1

```text
Application: curl
Destination: public-api.local
Compliance: HEALTHY
```

Expected decision:

```text
ALLOW
```

Reason:

```text
curl is allowed to access public-api.local
```

---

### Demo Case 2

```text
Application: curl
Destination: internal-api.local
Compliance: HEALTHY
```

Expected decision:

```text
DENY
```

Reason:

```text
CLI tools are not allowed to access internal API
```

---

### Demo Case 3

```text
Application: chromium
Destination: hr-portal.local
Compliance: NON_COMPLIANT
```

Expected decision:

```text
DENY
```

Reason:

```text
Device is not compliant for this protected resource
```

---

## Example Output

When the current project is built and executed, it prints output similar to:

```text
{
    "goal": "per-app zero trust access control",
    "module": "PolicyEngine MVP",
    "owner": "Gargi",
    "project": "AccessGate",
    "status": "running"
}
Loaded policy version: v1
Loaded rules: 3

--- Demo Decision 1: curl accessing public API ---
{
    "app": "curl",
    "compliance_status": "HEALTHY",
    "decision": "ALLOW",
    "destination": "public-api.local",
    "matched_rule": true,
    "matched_rule_id": "ALLOW_PUBLIC_API_FOR_CURL",
    "reason": "policy matched"
}

--- Demo Decision 2: curl accessing internal API ---
{
    "app": "curl",
    "compliance_status": "HEALTHY",
    "decision": "DENY",
    "destination": "internal-api.local",
    "matched_rule": true,
    "matched_rule_id": "DENY_INTERNAL_API_FOR_CURL",
    "reason": "CLI tools are not allowed to access internal API"
}

--- Demo Decision 3: chromium accessing HR portal while non-compliant ---
{
    "app": "chromium",
    "compliance_status": "NON_COMPLIANT",
    "decision": "DENY",
    "destination": "hr-portal.local",
    "matched_rule": true,
    "matched_rule_id": "ALLOW_HR_PORTAL_FOR_BROWSER_IF_COMPLIANT",
    "reason": "Device is not compliant for this protected resource"
}

AccessGate PolicyEngine demo completed.
```

---

## Project Architecture

Current and planned architecture:

```text
+--------------------------------------------------+
|                  Application                     |
|        curl / chromium / python / other app       |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
|                 AccessGate Agent                 |
+--------------------------------------------------+
|  Process Identity Resolver                       |
|  TrustStore                                      |
|  ComplianceChecker                               |
|  PolicyEngine                                    |
|  DecisionEngine                                  |
|  SQLiteAuditStore                                |
|  LocalProxy                                      |
|  HeartbeatClient                                 |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
|             Mock UEM Control Plane               |
|     dashboard / policy server / audit receiver   |
+--------------------------------------------------+
```

---

## Implemented Module: PolicyEngine

The PolicyEngine is the first working module of AccessGate.

### Responsibility

The PolicyEngine answers:

```text
Based on the policy file, should this app access this destination?
```

It takes an access request:

```text
app
destination
compliance status
```

and returns an access decision:

```text
ALLOW or DENY
reason
matched rule ID
whether any rule matched
```

---

## Policy File

The current policy file is:

```text
config/access_policy.json
```

Current sample policy:

```json
{
  "policy_version": "v1",
  "default_action": "DENY",
  "rules": [
    {
      "rule_id": "ALLOW_PUBLIC_API_FOR_CURL",
      "app": "curl",
      "destination": "public-api.local",
      "action": "ALLOW",
      "requires_compliance": false
    },
    {
      "rule_id": "DENY_INTERNAL_API_FOR_CURL",
      "app": "curl",
      "destination": "internal-api.local",
      "action": "DENY",
      "reason": "CLI tools are not allowed to access internal API"
    },
    {
      "rule_id": "ALLOW_HR_PORTAL_FOR_BROWSER_IF_COMPLIANT",
      "app": "chromium",
      "destination": "hr-portal.local",
      "action": "ALLOW",
      "requires_compliance": true
    }
  ]
}
```

---

## Policy Evaluation Logic

The PolicyEngine follows this logic:

```text
1. Load JSON policy file.
2. Read all policy rules.
3. For each request:
   - match application name
   - match destination
   - check whether compliance is required
   - if compliance is required and device is not healthy, deny access
   - otherwise apply the matched rule action
4. If no rule matches, apply default action.
```

The default action is currently:

```text
DENY
```

This follows a safer security design because unknown access should not be allowed by default.

---

## Planned Modules

### 1. TrustStore

The TrustStore will verify whether an application binary is trusted.

It will check:

```text
application name
executable path
SHA256 hash
```

Why this matters:

```text
The app name alone is not enough.
A malicious binary can pretend to be a trusted application.
```

Example:

```text
App name: curl
Path: /usr/bin/curl
SHA256: actual binary hash
Trust status: TRUSTED
```

If the hash does not match the enrolled value:

```text
Trust status: HASH_MISMATCH
Decision: DENY
```

Planned config file:

```text
config/trust_store.json
```

Current starter trust store:

```json
{
  "trust_store_version": "v1",
  "trusted_apps": [
    {
      "name": "curl",
      "path": "/usr/bin/curl",
      "sha256": "TO_BE_ENROLLED"
    },
    {
      "name": "chromium",
      "path": "/usr/bin/chromium",
      "sha256": "TO_BE_ENROLLED"
    }
  ]
}
```

---

### 2. ComplianceChecker

The ComplianceChecker will determine whether the endpoint is healthy enough to access protected resources.

Possible compliance states:

```text
HEALTHY
WARNING
NON_COMPLIANT
CRITICAL
```

Example checks:

```text
firewall enabled
required service running
policy version up to date
no critical local risk flag
agent heartbeat active
```

Example decision:

```text
Destination: hr-portal.local
Requires compliance: true
Device state: NON_COMPLIANT
Decision: DENY
```

---

### 3. DecisionEngine

The DecisionEngine will combine the outputs of multiple modules.

It will combine:

```text
process identity
trust status
compliance status
policy result
```

Expected final decision input:

```text
app = curl
destination = internal-api.local
compliance = HEALTHY
trust = TRUSTED
```

Expected output:

```text
DENY
reason = curl is not allowed to access internal-api.local
```

The PolicyEngine is currently doing a simplified version of this.

---

### 4. SQLiteAuditStore

The SQLiteAuditStore will persist every access decision locally.

Planned database table:

```sql
CREATE TABLE access_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    app TEXT NOT NULL,
    destination TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    compliance_status TEXT,
    matched_rule_id TEXT,
    executable_path TEXT,
    executable_hash TEXT
);
```

Why this matters:

```text
A real endpoint agent must keep an audit trail.
Access decisions should not disappear after the program exits.
```

---

### 5. LocalProxy

The LocalProxy will be the first enforcement mechanism.

Initial demo idea:

```text
curl -> AccessGate local proxy -> policy decision -> allow or deny
```

Example command:

```bash
curl -x http://127.0.0.1:8080 http://internal-api.local/data
```

Expected result:

```text
DENY: curl is not allowed to access internal-api.local
```

Important:

The proxy is not the main project by itself.

The main project is:

```text
process identity + compliance + policy decision + audit trail
```

The proxy is only the first way to demonstrate enforcement.

---

### 6. Socket-to-PID Mapping

This is one of the most important advanced features.

The agent should not trust user-provided values like:

```text
X-App-Name: curl
```

Instead, it should identify the real process behind a connection.

Target mapping:

```text
socket -> inode -> PID -> executable path -> SHA256 hash
```

Linux sources planned:

```text
/proc/net/tcp
/proc/<pid>/fd
/proc/<pid>/exe
/proc/<pid>/cmdline
```

Why this matters:

```text
This makes AccessGate stronger than a basic proxy.
The application should not be allowed to self-identify.
The endpoint agent should resolve identity independently.
```

---

### 7. Mock UEM Control Plane

The mock UEM control plane will receive endpoint data from AccessGate.

Planned backend responsibilities:

```text
receive access events
receive heartbeat messages
show blocked requests
show device compliance status
show policy version
show recent decisions
```

Planned stack:

```text
FastAPI or Node.js
REST API
simple dashboard
```

---

## Tech Stack

### C++20

C++20 is used for the endpoint agent.

Used for:

```text
policy engine
trust store
process identity resolver
local proxy
audit store
network decision logic
```

---

### CMake

CMake is used as the build system.

It defines:

```text
project name
C++ standard
source files
include directories
libraries
executable target
```

Current build target:

```text
accessgate-agent
```

---

### Ninja

Ninja is used as the build backend.

It is fast and works cleanly with CMake.

Build command:

```bash
cmake --build build
```

---

### nlohmann/json

This library is used to parse JSON files in C++.

Used for:

```text
access policies
trust store
structured output
future API payloads
```

---

### SQLite

SQLite will be used for local audit logging.

Why SQLite:

```text
lightweight
file-based
easy to use locally
good for endpoint-agent prototypes
```

Planned database file:

```text
accessgate.db
```

---

### OpenSSL

OpenSSL will be used for SHA256 hashing.

Used for:

```text
hashing executable binaries
verifying trusted applications
detecting hash mismatch
```

---

### Boost.Asio

Boost.Asio will be used for the local proxy and socket programming.

Used for:

```text
listening on local port
accepting client connections
reading HTTP requests
forwarding allowed requests
blocking denied requests
```

---

### Linux /proc

The `/proc` filesystem exposes runtime process and network metadata.

Planned usage:

```text
/proc/net/tcp
/proc/<pid>/fd
/proc/<pid>/exe
/proc/<pid>/cmdline
```

Used for:

```text
socket-to-PID mapping
process identity resolution
executable path lookup
command-line lookup
```

---

## Build Instructions

### 1. Configure

```bash
cmake -S . -B build -G Ninja
```

### 2. Build

```bash
cmake --build build
```

### 3. Run

```bash
./build/accessgate-agent
```

---

## Development Environment

Current development environment:

```text
OS: Ubuntu 24.04 on WSL2
Editor: VS Code with WSL extension
Compiler: g++ 13.3.0
Build system: CMake + Ninja
Language: C++20
```

---

## Current Repository Structure

```text
accessgate/
├── CMakeLists.txt
├── CLAUDE.md
├── README.md
├── config/
│   ├── access_policy.json
│   └── trust_store.json
├── include/
│   └── PolicyEngine.hpp
├── src/
│   ├── main.cpp
│   └── PolicyEngine.cpp
├── tests/
├── backend/
├── scripts/
├── docs/
└── sample_requests/
```

---

## Project Roadmap

### Phase 1: PolicyEngine MVP

Status:

```text
Completed
```

Features:

```text
load JSON policy
evaluate app + destination + compliance
return ALLOW or DENY
return reason and matched rule
```

---

### Phase 2: TrustStore

Status:

```text
Next
```

Goal:

```text
verify executable path and SHA256 hash
```

Expected demo:

```text
/usr/bin/curl -> SHA256 -> TRUSTED or TO_BE_ENROLLED
```

---

### Phase 3: ComplianceChecker

Status:

```text
Planned
```

Goal:

```text
compute endpoint compliance state
```

Example:

```text
HEALTHY
NON_COMPLIANT
```

---

### Phase 4: SQLiteAuditStore

Status:

```text
Planned
```

Goal:

```text
store every access decision in local SQLite database
```

---

### Phase 5: LocalProxy MVP

Status:

```text
Planned
```

Goal:

```text
intercept demo HTTP requests through local proxy
apply policy decision
allow or deny request
```

---

### Phase 6: Socket-to-PID Mapping

Status:

```text
Planned advanced feature
```

Goal:

```text
identify the real process behind a network request
```

This is the key feature that makes AccessGate stronger than a basic proxy.

---

### Phase 7: Mock UEM Control Plane

Status:

```text
Planned
```

Goal:

```text
send access decisions and endpoint posture to a backend dashboard
```

---

## Why AccessGate Is Not Just a Proxy

A basic proxy only forwards traffic.

AccessGate makes endpoint-aware decisions.

It considers:

```text
which app is making the request
whether the app is trusted
whether the endpoint is compliant
what destination is requested
what policy says
whether the decision should be audited
```

So the proxy is only the enforcement layer.

The core value is the decision system around it.

---

## Why AccessGate Is Not Just a Firewall

A firewall usually works at network level:

```text
IP
port
protocol
```

AccessGate works at endpoint-application level:

```text
process identity
executable trust
device compliance
destination policy
```

That makes it more suitable for a Zero Trust endpoint access-control prototype.

---

## Interview Explanation

AccessGate is a C++ endpoint access-control agent inspired by per-app Zero Trust access systems.

The current version implements the PolicyEngine, which loads JSON access rules and decides whether an application should be allowed to access a destination based on compliance state.

The next module is TrustStore, which will verify the executable using SHA256 so the system does not rely only on application names.

The final version will combine process identity, executable trust, compliance state, policy rules, audit logging, and proxy-based enforcement to demonstrate endpoint-aware access control.

---

## Current Honest Limitations

The project currently does not yet implement:

```text
real proxy enforcement
socket-to-PID mapping
SHA256 trust verification
SQLite audit logging
backend dashboard
TUN/TAP or firewall-based routing
```

These are planned modules.

Current completed milestone:

```text
PolicyEngine MVP
```

This README will be updated after each working milestone.