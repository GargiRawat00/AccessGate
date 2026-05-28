#pragma once

#include <cstdint>
#include <string>

struct ProcessIdentity {
    bool found = false;
    int pid = -1;
    int uid = -1;
    std::string processName;
    std::string executablePath;
    std::string source;
    std::string message;
};

class ProcessIdentityResolver {
public:
    ProcessIdentity resolveFromTcpConnection(
        const std::string& clientIp,
        uint16_t clientPort,
        const std::string& serverIp,
        uint16_t serverPort
    ) const;

private:
    static std::string ipv4ToProcHex(const std::string& ip);
    static std::string portToProcHex(uint16_t port);

    static std::string findSocketInode(
        const std::string& clientIp,
        uint16_t clientPort,
        const std::string& serverIp,
        uint16_t serverPort
    );

    static int findPidBySocketInode(const std::string& inode);
    static std::string readExecutablePath(int pid);
    static std::string readProcessName(int pid);
    static int readUid(int pid);
};
