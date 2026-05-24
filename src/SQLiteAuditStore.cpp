#include "SQLiteAuditStore.hpp"

#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

SQLiteAuditStore::SQLiteAuditStore()
    : db_(nullptr) {}

SQLiteAuditStore::~SQLiteAuditStore() {
    if (db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool SQLiteAuditStore::open(const std::string& dbPath) {
    int rc = sqlite3_open(dbPath.c_str(), &db_);

    if (rc != SQLITE_OK) {
        std::cerr << "Failed to open SQLite database: "
                  << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::cout << "Opened audit database: " << dbPath << std::endl;
    return true;
}

bool SQLiteAuditStore::initializeSchema() {
    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS access_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            app TEXT NOT NULL,
            destination TEXT NOT NULL,
            executable_path TEXT NOT NULL,
            executable_hash TEXT,
            trust_status TEXT NOT NULL,
            compliance_status TEXT NOT NULL,
            decision TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            reason TEXT NOT NULL,
            matched_rule_id TEXT NOT NULL
        );
    )SQL";

    char* errorMessage = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errorMessage);

    if (rc != SQLITE_OK) {
        std::cerr << "Failed to initialize audit schema: "
                  << errorMessage << std::endl;
        sqlite3_free(errorMessage);
        return false;
    }

    std::cout << "Audit schema initialized successfully." << std::endl;
    return true;
}

bool SQLiteAuditStore::logDecision(const FinalAccessDecision& decision) {
    const char* sql = R"SQL(
        INSERT INTO access_events (
            timestamp,
            app,
            destination,
            executable_path,
            executable_hash,
            trust_status,
            compliance_status,
            decision,
            allowed,
            reason,
            matched_rule_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare insert statement: "
                  << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string timestamp = currentTimestamp();

    sqlite3_bind_text(stmt, 1, timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, decision.app.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, decision.destination.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, decision.executablePath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, decision.executableHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, decision.trustStatus.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, decision.complianceStatus.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, decision.decision.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 9, decision.allowed ? 1 : 0);
    sqlite3_bind_text(stmt, 10, decision.reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, decision.matchedRuleId.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to insert audit event: "
                  << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

void SQLiteAuditStore::printRecentDecisions(int limit) const {
    const char* sql = R"SQL(
        SELECT
            id,
            timestamp,
            app,
            destination,
            decision,
            trust_status,
            compliance_status,
            reason
        FROM access_events
        ORDER BY id DESC
        LIMIT ?;
    )SQL";

    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare select statement: "
                  << sqlite3_errmsg(db_) << std::endl;
        return;
    }

    sqlite3_bind_int(stmt, 1, limit);

    std::cout << "\n--- Recent Audit Events ---\n";

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char* timestamp = sqlite3_column_text(stmt, 1);
        const unsigned char* app = sqlite3_column_text(stmt, 2);
        const unsigned char* destination = sqlite3_column_text(stmt, 3);
        const unsigned char* decision = sqlite3_column_text(stmt, 4);
        const unsigned char* trustStatus = sqlite3_column_text(stmt, 5);
        const unsigned char* complianceStatus = sqlite3_column_text(stmt, 6);
        const unsigned char* reason = sqlite3_column_text(stmt, 7);

        std::cout << "# " << id << "\n";
        std::cout << "  time: " << timestamp << "\n";
        std::cout << "  app: " << app << "\n";
        std::cout << "  destination: " << destination << "\n";
        std::cout << "  decision: " << decision << "\n";
        std::cout << "  trust: " << trustStatus << "\n";
        std::cout << "  compliance: " << complianceStatus << "\n";
        std::cout << "  reason: " << reason << "\n";
    }

    sqlite3_finalize(stmt);
}

std::string SQLiteAuditStore::currentTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm localTime{};

#if defined(_WIN32)
    localtime_s(&localTime, &now);
#else
    localtime_r(&now, &localTime);
#endif

    std::ostringstream oss;
    oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}
