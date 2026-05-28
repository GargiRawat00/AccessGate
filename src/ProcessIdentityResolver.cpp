#include "ProcessIdentityResolver.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

ProcessIdentity ProcessIdentityResolver::resolveFromTcpConnection(
    const std::string& clientIp,
    uint16_t clientPort,
    const std::string& serverIp,
    uint16_t serverPort
) const {
    ProcessIdentity identity;

    std::string inode = findSocketInode(
        clientIp,
        clientPort,
        serverIp,
        serverPort
    );

    if (inode.empty()) {
        identity.found = false;
        identity.source = "proc-net-tcp";
        identity.message = "Could not find matching socket inode in /proc/net/tcp";
        return identity;
    }

    int pid = findPidBySocketInode(inode);

    if (pid < 0) {
        identity.found = false;
        identity.source = "proc-fd";
        identity.message = "Socket inode found, but no owning PID was found";
        return identity;
    }

    identity.found = true;
    identity.pid = pid;
    identity.uid = readUid(pid);
    identity.executablePath = readExecutablePath(pid);
    identity.processName = readProcessName(pid);
    identity.source = "proc-socket-inode";
    identity.message = "Resolved process identity from TCP socket inode";

    return identity;
}

std::string ProcessIdentityResolver::ipv4ToProcHex(const std::string& ip) {
    in_addr addr{};

    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return "";
    }

    const unsigned char* bytes =
        reinterpret_cast<const unsigned char*>(&addr.s_addr);

    std::ostringstream oss;

    /*
     * /proc/net/tcp stores IPv4 addresses in little-endian hex.
     * Example: 127.0.0.1 becomes 0100007F.
     */
    for (int i = 3; i >= 0; --i) {
        oss << std::uppercase
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(bytes[i]);
    }

    return oss.str();
}

std::string ProcessIdentityResolver::portToProcHex(uint16_t port) {
    std::ostringstream oss;

    oss << std::uppercase
        << std::hex
        << std::setw(4)
        << std::setfill('0')
        << port;

    return oss.str();
}

std::string ProcessIdentityResolver::findSocketInode(
    const std::string& clientIp,
    uint16_t clientPort,
    const std::string& serverIp,
    uint16_t serverPort
) {
    const std::string expectedLocal =
        ipv4ToProcHex(clientIp) + ":" + portToProcHex(clientPort);

    const std::string expectedRemote =
        ipv4ToProcHex(serverIp) + ":" + portToProcHex(serverPort);

    std::ifstream file("/proc/net/tcp");

    if (!file.is_open()) {
        return "";
    }

    std::string line;
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::istringstream iss(line);

        std::string sl;
        std::string localAddress;
        std::string remoteAddress;
        std::string state;
        std::string txRxQueue;
        std::string trTimer;
        std::string retrnsmt;
        std::string uid;
        std::string timeout;
        std::string inode;

        iss >> sl
            >> localAddress
            >> remoteAddress
            >> state
            >> txRxQueue
            >> trTimer
            >> retrnsmt
            >> uid
            >> timeout
            >> inode;

        if (localAddress == expectedLocal &&
            remoteAddress == expectedRemote) {
            return inode;
        }
    }

    return "";
}

int ProcessIdentityResolver::findPidBySocketInode(const std::string& inode) {
    const std::string expectedTarget = "socket:[" + inode + "]";

    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) {
            continue;
        }

        const std::string pidText = entry.path().filename().string();

        bool numeric = true;
        for (char ch : pidText) {
            if (!std::isdigit(static_cast<unsigned char>(ch))) {
                numeric = false;
                break;
            }
        }

        if (!numeric) {
            continue;
        }

        const std::filesystem::path fdDir = entry.path() / "fd";

        if (!std::filesystem::exists(fdDir)) {
            continue;
        }

        try {
            for (const auto& fdEntry : std::filesystem::directory_iterator(fdDir)) {
                std::error_code ec;
                std::filesystem::path target =
                    std::filesystem::read_symlink(fdEntry.path(), ec);

                if (ec) {
                    continue;
                }

                if (target.string() == expectedTarget) {
                    return std::stoi(pidText);
                }
            }
        } catch (...) {
            continue;
        }
    }

    return -1;
}

std::string ProcessIdentityResolver::readExecutablePath(int pid) {
    std::filesystem::path exePath =
        std::filesystem::path("/proc") / std::to_string(pid) / "exe";

    std::error_code ec;
    std::filesystem::path target =
        std::filesystem::read_symlink(exePath, ec);

    if (ec) {
        return "";
    }

    return target.string();
}

std::string ProcessIdentityResolver::readProcessName(int pid) {
    std::filesystem::path commPath =
        std::filesystem::path("/proc") / std::to_string(pid) / "comm";

    std::ifstream file(commPath);

    if (!file.is_open()) {
        return "";
    }

    std::string name;
    std::getline(file, name);

    return name;
}

int ProcessIdentityResolver::readUid(int pid) {
    std::filesystem::path statusPath =
        std::filesystem::path("/proc") / std::to_string(pid) / "status";

    std::ifstream file(statusPath);

    if (!file.is_open()) {
        return -1;
    }

    std::string line;

    while (std::getline(file, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            std::istringstream iss(line);
            std::string label;
            int realUid = -1;

            iss >> label >> realUid;
            return realUid;
        }
    }

    return -1;
}
