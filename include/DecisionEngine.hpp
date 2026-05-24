#pragma once

#include <string>

#include "PolicyEngine.hpp"
#include "TrustStore.hpp"
#include "ComplianceChecker.hpp"

struct FinalAccessDecision {
    bool allowed;
    std::string decision;
    std::string app;
    std::string destination;
    std::string executablePath;
    std::string trustStatus;
    std::string complianceStatus;
    std::string reason;
    std::string matchedRuleId;
    std::string executableHash;
};

class DecisionEngine {
public:
    DecisionEngine(
        const PolicyEngine& policyEngine,
        const TrustStore& trustStore
    );

    FinalAccessDecision evaluate(
        const std::string& app,
        const std::string& destination,
        const std::string& executablePath,
        const ComplianceResult& complianceResult
    ) const;

private:
    const PolicyEngine& policyEngine_;
    const TrustStore& trustStore_;
};
