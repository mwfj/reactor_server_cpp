#pragma once

#include <string>
#include <chrono>

struct TlsConfig {
    bool enabled = false;
    std::string cert_file;
    std::string key_file;
    std::string min_version = "1.2";
};

struct LogConfig {
    std::string level = "info";
    std::string file;
    size_t max_file_size = 10485760;   // 10 MB
    int max_files = 3;
};

// NOTE: When adding fields, also update ConfigLoader::LoadFromString(),
// ConfigLoader::ToJson(), ConfigLoader::ApplyEnvOverrides(), and
// ConfigLoader::Validate() to keep serialization/deserialization in sync.
struct ServerConfig {
    std::string bind_host = "127.0.0.1";
    int bind_port = 8080;
    TlsConfig tls;
    LogConfig log;
    int max_connections = 10000;
    int idle_timeout_sec = 300;
    int worker_threads = 3;
    size_t max_header_size = 8192;       // 8 KB
    size_t max_body_size = 1048576;      // 1 MB
    size_t max_ws_message_size = 16777216; // 16 MB
    int request_timeout_sec = 30;
};
