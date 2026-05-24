# AccessGate Claude Instructions

Project:
AccessGate is a C++ per-app Zero Trust access-control agent for an Omnissa-targeted portfolio project.

Main idea:
The agent decides whether an application should be allowed to access a destination based on:
1. process identity,
2. destination resource,
3. endpoint compliance state,
4. policy rules,
5. executable trust status.

Important constraints:
- Do not turn this into a simple proxy.
- Do not turn this into a firewall script.
- The real value is process identity + compliance state + policy decision + audit trail.
- Start with local proxy MVP.
- Later Level 2 must implement socket-to-PID mapping using /proc/net/tcp and /proc/<pid>/fd.
- Use C++20, CMake, Boost.Asio, SQLite, nlohmann/json, and OpenSSL.
- Do not start with TUN/TAP.
- Do not run sudo commands unless explicitly approved.
- Before modifying code, explain the files you plan to edit.
- Keep code modular and testable.

Planned modules:
- Local proxy server
- Request parser
- Process identity resolver
- Policy engine
- Compliance checker
- Trust store
- Decision engine
- SQLite audit store
- Heartbeat client