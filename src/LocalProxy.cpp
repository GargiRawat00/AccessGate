#include "LocalProxy.hpp"

#include <iostream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

using boost::asio::ip::tcp;

LocalProxy::LocalProxy(
    const std::string& host,
    int port,
    const DecisionEngine& decisionEngine,
    SQLiteAuditStore& auditStore,
    const ComplianceResult& complianceResult
)
    : host_(host),
      port_(port),
      decisionEngine_(decisionEngine),
      auditStore_(auditStore),
      complianceResult_(complianceResult),
      acceptor_(
          ioContext_,
          tcp::endpoint(boost::asio::ip::make_address(host), port)
      ) {}

void LocalProxy::run() {
    std::cout << "AccessGate local proxy listening on "
              << host_ << ":" << port_ << std::endl;

    while (true) {
        tcp::socket socket(ioContext_);
        acceptor_.accept(socket);
        handleClient(std::move(socket));
    }
}

void LocalProxy::handleClient(tcp::socket socket) {
    try {
        const auto remoteEndpoint = socket.remote_endpoint();
        const auto localEndpoint = socket.local_endpoint();

        const std::string clientIp = remoteEndpoint.address().to_string();
        const uint16_t clientPort =
            static_cast<uint16_t>(remoteEndpoint.port());

        const std::string serverIp = localEndpoint.address().to_string();
        const uint16_t serverPort =
            static_cast<uint16_t>(localEndpoint.port());

        boost::asio::streambuf buffer;
        boost::asio::read_until(socket, buffer, "\r\n\r\n");

        std::istream requestStream(&buffer);

        std::string requestLine;
        std::getline(requestStream, requestLine);
        requestLine = trimCarriageReturn(requestLine);

        std::ostringstream headers;
        std::string line;

        while (std::getline(requestStream, line) && line != "\r") {
            headers << line << "\n";
        }

        const std::string rawHeaders = headers.str();
        const std::string hostHeader = extractHostHeader(rawHeaders);

        std::string destination =
            extractDestinationFromRequest(requestLine, hostHeader);

        if (destination.empty()) {
            destination = "unknown-destination";
        }

        ProcessIdentity identity = identityResolver_.resolveFromTcpConnection(
            clientIp,
            clientPort,
            serverIp,
            serverPort
        );

        std::string appName = identity.processName;
        std::string executablePath = identity.executablePath;

        if (!identity.found || executablePath.empty()) {
            appName = "curl";
            executablePath = "/usr/bin/curl";
        }

        if (appName.empty()) {
            appName = basenameFromPath(executablePath);
        }

        std::cout << "\n--- Incoming Proxy Request ---\n";
        std::cout << "request_line: " << requestLine << "\n";
        std::cout << "destination: " << destination << "\n";
        std::cout << "client: " << clientIp << ":" << clientPort << "\n";
        std::cout << "server: " << serverIp << ":" << serverPort << "\n";
        std::cout << "identity_found: " << (identity.found ? "true" : "false") << "\n";
        std::cout << "identity_source: " << identity.source << "\n";
        std::cout << "identity_message: " << identity.message << "\n";
        std::cout << "pid: " << identity.pid << "\n";
        std::cout << "uid: " << identity.uid << "\n";
        std::cout << "process: " << appName << "\n";
        std::cout << "exe: " << executablePath << "\n";

        FinalAccessDecision decision = decisionEngine_.evaluate(
            appName,
            destination,
            executablePath,
            complianceResult_
        );

        auditStore_.logDecision(decision);

        nlohmann::json bodyJson = {
            {"project", "AccessGate"},
            {"mode", "local-proxy-mvp"},
            {"identity_found", identity.found},
            {"identity_source", identity.source},
            {"identity_message", identity.message},
            {"pid", identity.pid},
            {"uid", identity.uid},
            {"app", decision.app},
            {"destination", decision.destination},
            {"decision", decision.decision},
            {"allowed", decision.allowed},
            {"trust_status", decision.trustStatus},
            {"compliance_status", decision.complianceStatus},
            {"matched_rule_id", decision.matchedRuleId},
            {"reason", decision.reason}
        };

        std::string body = bodyJson.dump(4);

        std::string response;

        if (decision.allowed) {
            response = buildHttpResponse(200, "OK", body);
        } else {
            response = buildHttpResponse(403, "Forbidden", body);
        }

        boost::asio::write(socket, boost::asio::buffer(response));
        socket.shutdown(tcp::socket::shutdown_both);
        socket.close();

    } catch (const std::exception& ex) {
        std::cerr << "Proxy client handling failed: "
                  << ex.what() << std::endl;
    }
}

std::string LocalProxy::extractDestinationFromRequest(
    const std::string& requestLine,
    const std::string& hostHeader
) {
    std::istringstream iss(requestLine);

    std::string method;
    std::string target;
    std::string version;

    iss >> method >> target >> version;

    if (target.rfind("http://", 0) == 0) {
        std::string withoutScheme = target.substr(7);
        std::size_t slashPos = withoutScheme.find('/');

        if (slashPos == std::string::npos) {
            return withoutScheme;
        }

        return withoutScheme.substr(0, slashPos);
    }

    if (target.rfind("https://", 0) == 0) {
        std::string withoutScheme = target.substr(8);
        std::size_t slashPos = withoutScheme.find('/');

        if (slashPos == std::string::npos) {
            return withoutScheme;
        }

        return withoutScheme.substr(0, slashPos);
    }

    return hostHeader;
}

std::string LocalProxy::extractHostHeader(const std::string& rawHeaders) {
    std::istringstream iss(rawHeaders);
    std::string line;

    while (std::getline(iss, line)) {
        line = trimCarriageReturn(line);

        const std::string prefix = "Host:";

        if (line.rfind(prefix, 0) == 0) {
            std::string host = line.substr(prefix.size());

            while (!host.empty() && host.front() == ' ') {
                host.erase(host.begin());
            }

            return host;
        }
    }

    return "";
}

std::string LocalProxy::trimCarriageReturn(const std::string& value) {
    if (!value.empty() && value.back() == '\r') {
        return value.substr(0, value.size() - 1);
    }

    return value;
}

std::string LocalProxy::basenameFromPath(const std::string& path) {
    std::size_t pos = path.find_last_of('/');

    if (pos == std::string::npos) {
        return path;
    }

    return path.substr(pos + 1);
}

std::string LocalProxy::buildHttpResponse(
    int statusCode,
    const std::string& statusText,
    const std::string& body
) {
    std::ostringstream response;

    response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    response << "Content-Type: application/json\r\n";
    response << "Content-Length: " << body.size() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;

    return response.str();
}
