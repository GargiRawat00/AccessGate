#pragma once

#include <string>

#include <sqlite3.h>

#include "DecisionEngine.hpp"

class SQLiteAuditStore {
public:
    SQLiteAuditStore();
    ~SQLiteAuditStore();

    bool open(const std::string& dbPath);
    bool initializeSchema();
    bool logDecision(const FinalAccessDecision& decision);
    void printRecentDecisions(int limit) const;

private:
    sqlite3* db_;

    static std::string currentTimestamp();
};
