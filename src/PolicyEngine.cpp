#include "PolicyEngine.hpp"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

DecisionAction PolicyEngine::parseAction(const std::string& action) {
    if (action == "ALLOW") {
        return DecisionAction::ALLOW;
    }
    return DecisionAction::DENY;
}

bool PolicyEngine::loadFromFile(const std::string& policyPath) {
    std::ifstream file(policyPath);

    if (!file.is_open()) {
        std::cerr << "Failed to open policy file: " << policyPath << std::endl;
        return false;
    }

    json policy;

    try {
        file >> policy;
    } catch (const std::exception& ex) {
        std::cerr << "Failed to parse policy JSON: " << ex.what() << std::endl;
        return false;
    }

    policyVersion_ = policy.value("policy_version", "unknown");
    defaultAction_ = policy.value("default_action", "DENY");

    rules_.clear();

    if (!policy.contains("rules") || !policy["rules"].is_array()) {
        std::cerr << "Policy file does not contain a valid rules array." << std::endl;
        return false;
    }

    for (const auto& item : policy["rules"]) {
        AccessRule rule;
        rule.ruleId = item.value("rule_id", "");
        rule.app = item.value("app", "");
        rule.destination = item.value("destination", "");
        rule.action = item.value("action", "DENY");
        rule.reason = item.value("reason", "policy matched");
        rule.requiresCompliance = item.value("requires_compliance", false);

        if (!rule.ruleId.empty() && !rule.app.empty() && !rule.destination.empty()) {
            rules_.push_back(rule);
        }
    }

    std::cout << "Loaded policy version: " << policyVersion_ << std::endl;
    std::cout << "Loaded rules: " << rules_.size() << std::endl;

    return true;
}

AccessDecision PolicyEngine::evaluate(const AccessRequest& request) const {
    for (const auto& rule : rules_) {
        const bool appMatches = (rule.app == request.app);
        const bool destinationMatches = (rule.destination == request.destination);

        if (!appMatches || !destinationMatches) {
            continue;
        }

        if (rule.requiresCompliance && request.complianceStatus != "HEALTHY") {
            return AccessDecision{
                DecisionAction::DENY,
                "Device is not compliant for this protected resource",
                rule.ruleId,
                true
            };
        }

        return AccessDecision{
            parseAction(rule.action),
            rule.reason.empty() ? "policy matched" : rule.reason,
            rule.ruleId,
            true
        };
    }

    return AccessDecision{
        parseAction(defaultAction_),
        "No matching rule found; default policy applied",
        "DEFAULT_POLICY",
        false
    };
}