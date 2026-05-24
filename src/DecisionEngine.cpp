#include "DecisionEngine.hpp"

DecisionEngine::DecisionEngine(
    const PolicyEngine& policyEngine,
    const TrustStore& trustStore
)
    : policyEngine_(policyEngine),
      trustStore_(trustStore) {}

FinalAccessDecision DecisionEngine::evaluate(
    const std::string& app,
    const std::string& destination,
    const std::string& executablePath,
    const ComplianceResult& complianceResult
) const {
    FinalAccessDecision finalDecision;

    finalDecision.app = app;
    finalDecision.destination = destination;
    finalDecision.executablePath = executablePath;
    finalDecision.complianceStatus =
        ComplianceChecker::statusToString(complianceResult.status);

    TrustCheckResult trustResult = trustStore_.verifyApp(app, executablePath);

    finalDecision.trustStatus = TrustStore::statusToString(trustResult.status);
    finalDecision.executableHash = trustResult.actualHash;

    if (trustResult.status != TrustStatus::TRUSTED) {
        finalDecision.allowed = false;
        finalDecision.decision = "DENY";
        finalDecision.reason =
            "Executable trust check failed: " + trustResult.message;
        finalDecision.matchedRuleId = "TRUST_STORE";
        return finalDecision;
    }

    AccessRequest policyRequest{
        app,
        destination,
        finalDecision.complianceStatus
    };

    AccessDecision policyDecision = policyEngine_.evaluate(policyRequest);

    finalDecision.allowed = (policyDecision.action == DecisionAction::ALLOW);
    finalDecision.decision = finalDecision.allowed ? "ALLOW" : "DENY";
    finalDecision.reason = policyDecision.reason;
    finalDecision.matchedRuleId = policyDecision.matchedRuleId;

    return finalDecision;
}
