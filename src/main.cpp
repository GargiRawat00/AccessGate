#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

#include "PolicyEngine.hpp"
#include "TrustStore.hpp"
#include "ComplianceChecker.hpp"

std::string decisionToString(DecisionAction action) {
    return action == DecisionAction::ALLOW ? "ALLOW" : "DENY";
}

void runDemoDecision(
    const PolicyEngine& engine,
    const std::string& app,
    const std::string& destination,
    const std::string& complianceStatus
) {
    AccessRequest request{
        app,
        destination,
        complianceStatus
    };

    AccessDecision decision = engine.evaluate(request);

    nlohmann::json output = {
        {"app", app},
        {"destination", destination},
        {"compliance_status", complianceStatus},
        {"decision", decisionToString(decision.action)},
        {"reason", decision.reason},
        {"matched_rule_id", decision.matchedRuleId},
        {"matched_rule", decision.matchedRule}
    };

    std::cout << output.dump(4) << std::endl;
}

void runTrustStoreDemo(
    const TrustStore& trustStore,
    const std::string& appName,
    const std::string& executablePath
) {
    TrustCheckResult result = trustStore.verifyApp(appName, executablePath);

    nlohmann::json output = {
        {"app", result.appName},
        {"expected_path", result.expectedPath},
        {"actual_path", result.actualPath},
        {"expected_hash", result.expectedHash},
        {"actual_hash", result.actualHash},
        {"trust_status", TrustStore::statusToString(result.status)},
        {"message", result.message}
    };

    std::cout << output.dump(4) << std::endl;
}

void runComplianceDemo(const ComplianceResult& complianceResult) {
    std::string complianceStatus =
        ComplianceChecker::statusToString(complianceResult.status);

    nlohmann::json output = {
        {"device_id", complianceResult.deviceId},
        {"policy_version", complianceResult.policyVersion},
        {"compliance_status", complianceStatus},
        {"message", complianceResult.message},
        {"failed_checks", complianceResult.failedChecks}
    };

    std::cout << output.dump(4) << std::endl;
}

int main() {
    nlohmann::json startup = {
        {"project", "AccessGate"},
        {"owner", "Gargi"},
        {"module", "PolicyEngine + TrustStore + ComplianceChecker MVP"},
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
    std::string complianceStatus =
        ComplianceChecker::statusToString(complianceResult.status);

    std::cout << "\n--- ComplianceChecker Demo ---\n";
    runComplianceDemo(complianceResult);

    std::cout << "\n--- Policy Demo 1: curl accessing public API using actual compliance status ---\n";
    runDemoDecision(policyEngine, "curl", "public-api.local", complianceStatus);

    std::cout << "\n--- Policy Demo 2: curl accessing internal API using actual compliance status ---\n";
    runDemoDecision(policyEngine, "curl", "internal-api.local", complianceStatus);

    std::cout << "\n--- Policy Demo 3: chromium accessing HR portal while forced non-compliant ---\n";
    runDemoDecision(policyEngine, "chromium", "hr-portal.local", "NON_COMPLIANT");

    std::cout << "\n--- TrustStore Demo 1: verify curl binary ---\n";
    runTrustStoreDemo(trustStore, "curl", "/usr/bin/curl");

    std::cout << "\n--- TrustStore Demo 2: unknown app ---\n";
    runTrustStoreDemo(trustStore, "unknown-app", "/usr/bin/unknown-app");

    std::cout << "\nAccessGate ComplianceChecker demo completed." << std::endl;

    return 0;
}