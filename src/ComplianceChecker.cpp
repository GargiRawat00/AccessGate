#include "ComplianceChecker.hpp"

#include <fstream>
#include <iostream>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool ComplianceChecker::loadFromFile(const std::string& compliancePolicyPath) {
    std::ifstream file(compliancePolicyPath);

    if (!file.is_open()) {
        std::cerr << "Failed to open compliance policy file: "
                  << compliancePolicyPath << std::endl;
        return false;
    }

    json policy;

    try {
        file >> policy;
    } catch (const std::exception& ex) {
        std::cerr << "Failed to parse compliance policy JSON: "
                  << ex.what() << std::endl;
        return false;
    }

    policyVersion_ = policy.value("policy_version", "unknown");
    deviceId_ = policy.value("device_id", "unknown-device");
    configuredStatus_ = policy.value("compliance_status", "HEALTHY");

    if (policy.contains("checks") && policy["checks"].is_object()) {
        const auto& checks = policy["checks"];

        firewallEnabled_ = checks.value("firewall_enabled", true);
        agentHeartbeatActive_ = checks.value("agent_heartbeat_active", true);
        policyVersionCurrent_ = checks.value("policy_version_current", true);
        criticalRiskDetected_ = checks.value("critical_risk_detected", false);
    }

    std::cout << "Loaded compliance policy version: " << policyVersion_ << std::endl;
    std::cout << "Device ID: " << deviceId_ << std::endl;

    return true;
}

ComplianceResult ComplianceChecker::evaluate() const {
    ComplianceResult result;
    result.deviceId = deviceId_;
    result.policyVersion = policyVersion_;

    if (!firewallEnabled_) {
        result.failedChecks.push_back("firewall_disabled");
    }

    if (!agentHeartbeatActive_) {
        result.failedChecks.push_back("agent_heartbeat_inactive");
    }

    if (!policyVersionCurrent_) {
        result.failedChecks.push_back("policy_version_outdated");
    }

    if (criticalRiskDetected_) {
        result.failedChecks.push_back("critical_risk_detected");
    }

    if (criticalRiskDetected_) {
        result.status = ComplianceStatus::CRITICAL;
        result.message = "Critical local risk detected";
        return result;
    }

    if (!result.failedChecks.empty()) {
        result.status = ComplianceStatus::NON_COMPLIANT;
        result.message = "One or more compliance checks failed";
        return result;
    }

    result.status = parseStatus(configuredStatus_);
    result.message = "Endpoint compliance evaluated successfully";

    return result;
}

ComplianceStatus ComplianceChecker::parseStatus(const std::string& status) {
    if (status == "HEALTHY") {
        return ComplianceStatus::HEALTHY;
    }

    if (status == "WARNING") {
        return ComplianceStatus::WARNING;
    }

    if (status == "NON_COMPLIANT") {
        return ComplianceStatus::NON_COMPLIANT;
    }

    if (status == "CRITICAL") {
        return ComplianceStatus::CRITICAL;
    }

    return ComplianceStatus::NON_COMPLIANT;
}

std::string ComplianceChecker::statusToString(ComplianceStatus status) {
    switch (status) {
        case ComplianceStatus::HEALTHY:
            return "HEALTHY";
        case ComplianceStatus::WARNING:
            return "WARNING";
        case ComplianceStatus::NON_COMPLIANT:
            return "NON_COMPLIANT";
        case ComplianceStatus::CRITICAL:
            return "CRITICAL";
        default:
            return "NON_COMPLIANT";
    }
}