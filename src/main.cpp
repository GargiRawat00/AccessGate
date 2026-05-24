#include <iostream>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <sqlite3.h>
#include <openssl/sha.h>

int main() {
    nlohmann::json startup = {
        {"project", "AccessGate"},
        {"owner", "Gargi"},
        {"module", "startup"},
        {"status", "running"},
        {"mode", "local-proxy-mvp"},
        {"goal", "per-app zero trust access control"}
    };

    std::cout << startup.dump(4) << std::endl;
    std::cout << "AccessGate agent boot successful." << std::endl;

    return 0;
}