#pragma once

#include <string>
#include <vector>

enum class DecisionAction {
    ALLOW,
    DENY
};

struct AccessRequest {
    std::string app;
    std::string destination;
    std::string complianceStatus;
};

struct AccessDecision {
    DecisionAction action;
    std::string reason;
    std::string matchedRuleId;
    bool matchedRule;
};

struct AccessRule {
    std::string ruleId;
    std::string app;
    std::string destination;
    std::string action;
    std::string reason;
    bool requiresCompliance;
};

class PolicyEngine {
public:
    bool loadFromFile(const std::string& policyPath);
    AccessDecision evaluate(const AccessRequest& request) const;

private:
    std::string policyVersion_;
    std::string defaultAction_ = "DENY";
    std::vector<AccessRule> rules_;

    static DecisionAction parseAction(const std::string& action);
};