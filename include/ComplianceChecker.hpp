#pragma once

#include <string>
#include <vector>

enum class ComplianceStatus {
    HEALTHY,
    WARNING,
    NON_COMPLIANT,
    CRITICAL
};

struct ComplianceResult {
    ComplianceStatus status;
    std::string deviceId;
    std::string policyVersion;
    std::vector<std::string> failedChecks;
    std::string message;
};

class ComplianceChecker {
public:
    bool loadFromFile(const std::string& compliancePolicyPath);
    ComplianceResult evaluate() const;

    static std::string statusToString(ComplianceStatus status);

private:
    std::string policyVersion_;
    std::string deviceId_;
    std::string configuredStatus_ = "HEALTHY";

    bool firewallEnabled_ = true;
    bool agentHeartbeatActive_ = true;
    bool policyVersionCurrent_ = true;
    bool criticalRiskDetected_ = false;

    static ComplianceStatus parseStatus(const std::string& status);
};