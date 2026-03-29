#pragma once

#include <string>
#include <chrono>
#include <cstdint>

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

struct Http2Config {
    bool enabled = true;                         // Enable HTTP/2 (h2 + h2c)
    uint32_t max_concurrent_streams = 100;       // RFC 9113 default recommendation
    uint32_t initial_window_size = 65535;         // RFC 9113 default (64 KB - 1)
    uint32_t max_frame_size = 16384;             // RFC 9113 default (16 KB)
    uint32_t max_header_list_size = 65536;       // 64 KB
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
    int shutdown_drain_timeout_sec = 30; // Max seconds to wait for in-flight H2 streams during shutdown. 0 = immediate.
    Http2Config http2;
};
