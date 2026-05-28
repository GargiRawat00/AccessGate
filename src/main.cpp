#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

#include "PolicyEngine.hpp"
#include "TrustStore.hpp"
#include "ComplianceChecker.hpp"
#include "DecisionEngine.hpp"
#include "SQLiteAuditStore.hpp"
#include "LocalProxy.hpp"

void printFinalDecision(const FinalAccessDecision& decision) {
    nlohmann::json output = {
        {"app", decision.app},
        {"destination", decision.destination},
        {"executable_path", decision.executablePath},
        {"trust_status", decision.trustStatus},
        {"compliance_status", decision.complianceStatus},
        {"decision", decision.decision},
        {"allowed", decision.allowed},
        {"reason", decision.reason},
        {"matched_rule_id", decision.matchedRuleId},
        {"executable_hash", decision.executableHash}
    };

    std::cout << output.dump(4) << std::endl;
}

void printComplianceResult(const ComplianceResult& complianceResult) {
    nlohmann::json output = {
        {"device_id", complianceResult.deviceId},
        {"policy_version", complianceResult.policyVersion},
        {"compliance_status", ComplianceChecker::statusToString(complianceResult.status)},
        {"message", complianceResult.message},
        {"failed_checks", complianceResult.failedChecks}
    };

    std::cout << output.dump(4) << std::endl;
}

void evaluateAndAudit(
    const DecisionEngine& decisionEngine,
    SQLiteAuditStore& auditStore,
    const std::string& app,
    const std::string& destination,
    const std::string& executablePath,
    const ComplianceResult& complianceResult
) {
    FinalAccessDecision decision = decisionEngine.evaluate(
        app,
        destination,
        executablePath,
        complianceResult
    );

    printFinalDecision(decision);

    if (!auditStore.logDecision(decision)) {
        std::cerr << "Failed to write decision to audit store." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    const bool proxyMode =
        (argc > 1 && std::string(argv[1]) == "--proxy");

    nlohmann::json startup = {
        {"project", "AccessGate"},
        {"owner", "Gargi"},
        {"module", proxyMode ? "LocalProxy MVP" : "DecisionEngine + SQLiteAuditStore MVP"},
        {"status", "running"},
        {"goal", "per-app zero trust access control"}
    };

    std::cout << startup.dump(4) << std::endl;

    PolicyEngine policyEngine;
    if (!policyEngine.loadFromFile("config/access_policy.json")) {
        std::cerr << "AccessGate failed to start because policy loading failed." << std::endl;
        return 1;
    }

    TrustStore trustStore;
    if (!trustStore.loadFromFile("config/trust_store.json")) {
        std::cerr << "AccessGate failed to start because trust store loading failed." << std::endl;
        return 1;
    }

    ComplianceChecker complianceChecker;
    if (!complianceChecker.loadFromFile("config/compliance_policy.json")) {
        std::cerr << "AccessGate failed to start because compliance policy loading failed." << std::endl;
        return 1;
    }

    ComplianceResult complianceResult = complianceChecker.evaluate();

    std::cout << "\n--- Compliance Status ---\n";
    printComplianceResult(complianceResult);

    SQLiteAuditStore auditStore;
    if (!auditStore.open("accessgate.db")) {
        std::cerr << "AccessGate failed to start because audit DB open failed." << std::endl;
        return 1;
    }

    if (!auditStore.initializeSchema()) {
        std::cerr << "AccessGate failed to start because audit schema init failed." << std::endl;
        return 1;
    }

    DecisionEngine decisionEngine(policyEngine, trustStore);

    if (proxyMode) {
        LocalProxy proxy(
            "127.0.0.1",
            8080,
            decisionEngine,
            auditStore,
            complianceResult
        );

        proxy.run();
        return 0;
    }

    std::cout << "\n--- Final Decision 1: trusted curl accessing public API ---\n";
    evaluateAndAudit(
        decisionEngine,
        auditStore,
        "curl",
        "public-api.local",
        "/usr/bin/curl",
        complianceResult
    );

    std::cout << "\n--- Final Decision 2: trusted curl accessing internal API ---\n";
    evaluateAndAudit(
        decisionEngine,
        auditStore,
        "curl",
        "internal-api.local",
        "/usr/bin/curl",
        complianceResult
    );

    std::cout << "\n--- Final Decision 3: unknown app accessing public API ---\n";
    evaluateAndAudit(
        decisionEngine,
        auditStore,
        "unknown-app",
        "public-api.local",
        "/usr/bin/unknown-app",
        complianceResult
    );

    std::cout << "\n--- Final Decision 4: curl with wrong executable path ---\n";
    evaluateAndAudit(
        decisionEngine,
        auditStore,
        "curl",
        "public-api.local",
        "/tmp/fake-curl",
        complianceResult
    );

    auditStore.printRecentDecisions(10);

    std::cout << "\nAccessGate SQLiteAuditStore demo completed." << std::endl;
    return 0;
}
