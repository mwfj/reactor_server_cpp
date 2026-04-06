#pragma once

#include <string>
#include <vector>
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

struct UpstreamTlsConfig {
    bool enabled = false;
    std::string ca_file;
    bool verify_peer = true;
    std::string sni_hostname;
    std::string min_version = "1.2";

    bool operator==(const UpstreamTlsConfig& o) const {
        return enabled == o.enabled && ca_file == o.ca_file &&
               verify_peer == o.verify_peer && sni_hostname == o.sni_hostname &&
               min_version == o.min_version;
    }
    bool operator!=(const UpstreamTlsConfig& o) const { return !(*this == o); }
};

struct UpstreamPoolConfig {
    int max_connections = 64;
    int max_idle_connections = 16;
    int connect_timeout_ms = 5000;
    int idle_timeout_sec = 90;
    int max_lifetime_sec = 3600;
    int max_requests_per_conn = 0;

    bool operator==(const UpstreamPoolConfig& o) const {
        return max_connections == o.max_connections &&
               max_idle_connections == o.max_idle_connections &&
               connect_timeout_ms == o.connect_timeout_ms &&
               idle_timeout_sec == o.idle_timeout_sec &&
               max_lifetime_sec == o.max_lifetime_sec &&
               max_requests_per_conn == o.max_requests_per_conn;
    }
    bool operator!=(const UpstreamPoolConfig& o) const { return !(*this == o); }
};

struct UpstreamConfig {
    std::string name;
    std::string host;
    int port = 80;
    UpstreamTlsConfig tls;
    UpstreamPoolConfig pool;

    bool operator==(const UpstreamConfig& o) const {
        return name == o.name && host == o.host && port == o.port &&
               tls == o.tls && pool == o.pool;
    }
    bool operator!=(const UpstreamConfig& o) const { return !(*this == o); }
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
    std::vector<UpstreamConfig> upstreams;
};
