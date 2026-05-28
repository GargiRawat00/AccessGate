#include <iostream>
#include <stdexcept>
#include <string>

#include "PolicyEngine.hpp"
#include "TrustStore.hpp"
#include "ComplianceChecker.hpp"
#include "DecisionEngine.hpp"

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error("TEST FAILED: " + message);
    }
}

void testPolicyEngine() {
    PolicyEngine policyEngine;

    require(
        policyEngine.loadFromFile("config/access_policy.json"),
        "PolicyEngine should load config/access_policy.json"
    );

    AccessDecision allowDecision = policyEngine.evaluate(
        AccessRequest{"curl", "public-api.local", "HEALTHY"}
    );

    require(
        allowDecision.action == DecisionAction::ALLOW,
        "curl should be allowed to access public-api.local"
    );

    AccessDecision denyDecision = policyEngine.evaluate(
        AccessRequest{"curl", "internal-api.local", "HEALTHY"}
    );

    require(
        denyDecision.action == DecisionAction::DENY,
        "curl should be denied from accessing internal-api.local"
    );

    AccessDecision complianceDenyDecision = policyEngine.evaluate(
        AccessRequest{"chromium", "hr-portal.local", "NON_COMPLIANT"}
    );

    require(
        complianceDenyDecision.action == DecisionAction::DENY,
        "chromium should be denied from hr-portal.local when endpoint is non-compliant"
    );

    std::cout << "[PASS] PolicyEngine tests\n";
}

void testComplianceChecker() {
    ComplianceChecker complianceChecker;

    require(
        complianceChecker.loadFromFile("config/compliance_policy.json"),
        "ComplianceChecker should load config/compliance_policy.json"
    );

    ComplianceResult result = complianceChecker.evaluate();

    require(
        result.status == ComplianceStatus::HEALTHY,
        "ComplianceChecker should return HEALTHY for current config"
    );

    require(
        result.failedChecks.empty(),
        "ComplianceChecker should have no failed checks for healthy config"
    );

    std::cout << "[PASS] ComplianceChecker tests\n";
}

void testTrustStore() {
    TrustStore trustStore;

    require(
        trustStore.loadFromFile("config/trust_store.json"),
        "TrustStore should load config/trust_store.json"
    );

    TrustCheckResult curlResult = trustStore.verifyApp("curl", "/usr/bin/curl");

    require(
        curlResult.status == TrustStatus::TRUSTED,
        "curl should be trusted after trust-store enrollment"
    );

    TrustCheckResult unknownResult = trustStore.verifyApp(
        "unknown-app",
        "/usr/bin/unknown-app"
    );

    require(
        unknownResult.status == TrustStatus::UNKNOWN_APP,
        "unknown-app should not be trusted"
    );

    TrustCheckResult pathMismatchResult = trustStore.verifyApp(
        "curl",
        "/tmp/fake-curl"
    );

    require(
        pathMismatchResult.status == TrustStatus::PATH_MISMATCH,
        "curl with wrong executable path should produce PATH_MISMATCH"
    );

    std::cout << "[PASS] TrustStore tests\n";
}

void testDecisionEngine() {
    PolicyEngine policyEngine;
    TrustStore trustStore;
    ComplianceChecker complianceChecker;

    require(
        policyEngine.loadFromFile("config/access_policy.json"),
        "PolicyEngine should load policy"
    );

    require(
        trustStore.loadFromFile("config/trust_store.json"),
        "TrustStore should load trust store"
    );

    require(
        complianceChecker.loadFromFile("config/compliance_policy.json"),
        "ComplianceChecker should load compliance policy"
    );

    ComplianceResult complianceResult = complianceChecker.evaluate();

    DecisionEngine decisionEngine(policyEngine, trustStore);

    FinalAccessDecision allowDecision = decisionEngine.evaluate(
        "curl",
        "public-api.local",
        "/usr/bin/curl",
        complianceResult
    );

    require(
        allowDecision.allowed,
        "DecisionEngine should allow trusted curl to public-api.local"
    );

    FinalAccessDecision denyDecision = decisionEngine.evaluate(
        "curl",
        "internal-api.local",
        "/usr/bin/curl",
        complianceResult
    );

    require(
        !denyDecision.allowed,
        "DecisionEngine should deny trusted curl to internal-api.local"
    );

    FinalAccessDecision unknownDecision = decisionEngine.evaluate(
        "unknown-app",
        "public-api.local",
        "/usr/bin/unknown-app",
        complianceResult
    );

    require(
        !unknownDecision.allowed,
        "DecisionEngine should deny unknown app"
    );

    std::cout << "[PASS] DecisionEngine tests\n";
}

int main() {
    try {
        testPolicyEngine();
        testComplianceChecker();
        testTrustStore();
        testDecisionEngine();

        std::cout << "\nAll AccessGate core tests passed.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }
}
