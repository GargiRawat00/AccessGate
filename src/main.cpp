#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

#include "PolicyEngine.hpp"
#include "TrustStore.hpp"
#include "ComplianceChecker.hpp"
#include "DecisionEngine.hpp"

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

int main() {
    nlohmann::json startup = {
        {"project", "AccessGate"},
        {"owner", "Gargi"},
        {"module", "DecisionEngine MVP"},
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

    DecisionEngine decisionEngine(policyEngine, trustStore);

    std::cout << "\n--- Final Decision 1: trusted curl accessing public API ---\n";
    FinalAccessDecision decision1 = decisionEngine.evaluate(
        "curl",
        "public-api.local",
        "/usr/bin/curl",
        complianceResult
    );
    printFinalDecision(decision1);

    std::cout << "\n--- Final Decision 2: trusted curl accessing internal API ---\n";
    FinalAccessDecision decision2 = decisionEngine.evaluate(
        "curl",
        "internal-api.local",
        "/usr/bin/curl",
        complianceResult
    );
    printFinalDecision(decision2);

    std::cout << "\n--- Final Decision 3: unknown app accessing public API ---\n";
    FinalAccessDecision decision3 = decisionEngine.evaluate(
        "unknown-app",
        "public-api.local",
        "/usr/bin/unknown-app",
        complianceResult
    );
    printFinalDecision(decision3);

    std::cout << "\n--- Final Decision 4: curl with wrong executable path ---\n";
    FinalAccessDecision decision4 = decisionEngine.evaluate(
        "curl",
        "public-api.local",
        "/tmp/fake-curl",
        complianceResult
    );
    printFinalDecision(decision4);

    std::cout << "\nAccessGate DecisionEngine demo completed." << std::endl;

    return 0;
}