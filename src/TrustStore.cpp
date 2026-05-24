#include "TrustStore.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <nlohmann/json.hpp>
#include <openssl/sha.h>

using json = nlohmann::json;

bool TrustStore::loadFromFile(const std::string& trustStorePath) {
    std::ifstream file(trustStorePath);

    if (!file.is_open()) {
        std::cerr << "Failed to open trust store file: " << trustStorePath << std::endl;
        return false;
    }

    json trustStore;

    try {
        file >> trustStore;
    } catch (const std::exception& ex) {
        std::cerr << "Failed to parse trust store JSON: " << ex.what() << std::endl;
        return false;
    }

    trustStoreVersion_ = trustStore.value("trust_store_version", "unknown");
    trustedApps_.clear();

    if (!trustStore.contains("trusted_apps") || !trustStore["trusted_apps"].is_array()) {
        std::cerr << "Trust store does not contain a valid trusted_apps array." << std::endl;
        return false;
    }

    for (const auto& item : trustStore["trusted_apps"]) {
        TrustedApp app;
        app.name = item.value("name", "");
        app.path = item.value("path", "");
        app.sha256 = item.value("sha256", "");

        if (!app.name.empty() && !app.path.empty()) {
            trustedApps_.push_back(app);
        }
    }

    std::cout << "Loaded trust store version: " << trustStoreVersion_ << std::endl;
    std::cout << "Loaded trusted app entries: " << trustedApps_.size() << std::endl;

    return true;
}

TrustCheckResult TrustStore::verifyApp(
    const std::string& appName,
    const std::string& executablePath
) const {
    for (const auto& trustedApp : trustedApps_) {
        if (trustedApp.name != appName) {
            continue;
        }

        TrustCheckResult result;
        result.appName = appName;
        result.expectedPath = trustedApp.path;
        result.actualPath = executablePath;
        result.expectedHash = trustedApp.sha256;

        if (trustedApp.path != executablePath) {
            result.status = TrustStatus::PATH_MISMATCH;
            result.message = "Executable path does not match enrolled path";
            return result;
        }

        try {
            result.actualHash = computeSha256(executablePath);
        } catch (const std::runtime_error& ex) {
            result.status = TrustStatus::FILE_NOT_FOUND;
            result.message = ex.what();
            return result;
        } catch (const std::exception& ex) {
            result.status = TrustStatus::ERROR;
            result.message = ex.what();
            return result;
        }

        if (trustedApp.sha256 == "TO_BE_ENROLLED") {
            result.status = TrustStatus::TO_BE_ENROLLED;
            result.message = "Application exists but hash is not enrolled yet";
            return result;
        }

        if (trustedApp.sha256 == result.actualHash) {
            result.status = TrustStatus::TRUSTED;
            result.message = "Executable hash matches trust store";
            return result;
        }

        result.status = TrustStatus::HASH_MISMATCH;
        result.message = "Executable hash does not match trust store";
        return result;
    }

    TrustCheckResult result;
    result.status = TrustStatus::UNKNOWN_APP;
    result.appName = appName;
    result.actualPath = executablePath;
    result.message = "Application is not present in trust store";
    return result;
}

std::string TrustStore::computeSha256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open()) {
        throw std::runtime_error("Could not open executable file: " + filePath);
    }

    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);

    char buffer[8192];

    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        std::streamsize bytesRead = file.gcount();

        if (bytesRead > 0) {
            SHA256_Update(
                &sha256Context,
                reinterpret_cast<unsigned char*>(buffer),
                static_cast<size_t>(bytesRead)
            );
        }
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256Context);

    std::ostringstream result;

    for (unsigned char byte : hash) {
        result << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return result.str();
}

std::string TrustStore::statusToString(TrustStatus status) {
    switch (status) {
        case TrustStatus::TRUSTED:
            return "TRUSTED";
        case TrustStatus::TO_BE_ENROLLED:
            return "TO_BE_ENROLLED";
        case TrustStatus::HASH_MISMATCH:
            return "HASH_MISMATCH";
        case TrustStatus::PATH_MISMATCH:
            return "PATH_MISMATCH";
        case TrustStatus::UNKNOWN_APP:
            return "UNKNOWN_APP";
        case TrustStatus::FILE_NOT_FOUND:
            return "FILE_NOT_FOUND";
        case TrustStatus::ERROR:
            return "ERROR";
        default:
            return "ERROR";
    }
}
