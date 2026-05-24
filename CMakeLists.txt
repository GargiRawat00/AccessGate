cmake_minimum_required(VERSION 3.20)
project(AccessGate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(nlohmann_json REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread)

add_executable(accessgate-agent
    src/main.cpp
    src/PolicyEngine.cpp
)

target_include_directories(accessgate-agent
    PRIVATE
    include
)

target_link_libraries(accessgate-agent
    PRIVATE
    nlohmann_json::nlohmann_json
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
    Boost::thread
)