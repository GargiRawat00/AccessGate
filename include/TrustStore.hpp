#pragma once

#include <string>
#include <vector>

enum class TrustStatus {
    TRUSTED,
    TO_BE_ENROLLED,
    HASH_MISMATCH,
    PATH_MISMATCH,
    UNKNOWN_APP,
    FILE_NOT_FOUND,
    ERROR
};

struct TrustedApp {
    std::string name;
    std::string path;
    std::string sha256;
};

struct TrustCheckResult {
    TrustStatus status;
    std::string appName;
    std::string expectedPath;
    std::string actualPath;
    std::string expectedHash;
    std::string actualHash;
    std::string message;
};

class TrustStore {
public:
    bool loadFromFile(const std::string& trustStorePath);

    TrustCheckResult verifyApp(
        const std::string& appName,
        const std::string& executablePath
    ) const;

    static std::string statusToString(TrustStatus status);

private:
    std::string trustStoreVersion_;
    std::vector<TrustedApp> trustedApps_;

    static std::string computeSha256(const std::string& filePath);
};