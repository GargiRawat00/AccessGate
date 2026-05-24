#include <iostream>
#include <nlohmann/json.hpp>

#include "PolicyEngine.hpp"

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

int main() {
    nlohmann::json startup = {
        {"project", "AccessGate"},
        {"owner", "Gargi"},
        {"module", "PolicyEngine MVP"},
        {"status", "running"},
        {"goal", "per-app zero trust access control"}
    };

    std::cout << startup.dump(4) << std::endl;

    PolicyEngine engine;

    if (!engine.loadFromFile("config/access_policy.json")) {
        std::cerr << "AccessGate failed to start because policy loading failed." << std::endl;
        return 1;
    }

    std::cout << "\n--- Demo Decision 1: curl accessing public API ---\n";
    runDemoDecision(engine, "curl", "public-api.local", "HEALTHY");

    std::cout << "\n--- Demo Decision 2: curl accessing internal API ---\n";
    runDemoDecision(engine, "curl", "internal-api.local", "HEALTHY");

    std::cout << "\n--- Demo Decision 3: chromium accessing HR portal while non-compliant ---\n";
    runDemoDecision(engine, "chromium", "hr-portal.local", "NON_COMPLIANT");

    std::cout << "\nAccessGate PolicyEngine demo completed." << std::endl;

    return 0;
}