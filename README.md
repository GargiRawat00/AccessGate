# AccessGate

AccessGate is a C++ per-app Zero Trust access-control agent designed as an Omnissa-targeted systems project.

The project simulates how an endpoint agent can decide whether a local application should be allowed to access a protected destination based on:

1. Application identity  
2. Destination resource  
3. Endpoint compliance state  
4. Policy rules  
5. Executable trust status  

The long-term goal is to build a lightweight endpoint access-control agent inspired by per-app tunnel and device-compliance enforcement systems.

---

## Current Status

### Completed

- Basic C++20 project setup using CMake and Ninja
- Dependency integration:
  - nlohmann/json
  - SQLite3
  - OpenSSL
  - Boost
- JSON-based access policy file
- PolicyEngine MVP
- Policy evaluation based on:
  - app name
  - destination
  - compliance state
  - default deny behavior

### Current Working Demo

The current demo loads `config/access_policy.json` and evaluates sample access requests.

Example decisions:

```text
curl + public-api.local + HEALTHY
=> ALLOW

curl + internal-api.local + HEALTHY
=> DENY

chromium + hr-portal.local + NON_COMPLIANT
=> DENY