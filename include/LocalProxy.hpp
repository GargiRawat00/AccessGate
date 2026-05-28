#pragma once

#include <string>

#include <boost/asio.hpp>

#include "DecisionEngine.hpp"
#include "SQLiteAuditStore.hpp"
#include "ComplianceChecker.hpp"

class LocalProxy {
public:
    LocalProxy(
        const std::string& host,
        int port,
        const DecisionEngine& decisionEngine,
        SQLiteAuditStore& auditStore,
        const ComplianceResult& complianceResult
    );

    void run();

private:
    std::string host_;
    int port_;

    const DecisionEngine& decisionEngine_;
    SQLiteAuditStore& auditStore_;
    const ComplianceResult& complianceResult_;

    boost::asio::io_context ioContext_;
    boost::asio::ip::tcp::acceptor acceptor_;

    void handleClient(boost::asio::ip::tcp::socket socket);

    static std::string extractDestinationFromRequest(
        const std::string& requestLine,
        const std::string& hostHeader
    );

    static std::string extractHostHeader(const std::string& rawHeaders);
    static std::string trimCarriageReturn(const std::string& value);

    static std::string buildHttpResponse(
        int statusCode,
        const std::string& statusText,
        const std::string& body
    );
};
