#include "config/config_loader.h"
#include "http2/http2_constants.h"
#include "http/route_trie.h"         // ParsePattern, ValidatePattern for proxy route_prefix
#include "log/logger.h"
#include "nlohmann/json.hpp"

#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <cstdlib>
#include <stdexcept>
#include <algorithm>
#include <unordered_set>

using json = nlohmann::json;

ServerConfig ConfigLoader::LoadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open config file: " + path);
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return LoadFromString(ss.str());
}

ServerConfig ConfigLoader::LoadFromString(const std::string& json_str) {
    json j;
    try {
        j = json::parse(json_str);
    } catch (const json::parse_error& e) {
        throw std::runtime_error(std::string("JSON parse error: ") + e.what());
    }

    ServerConfig config;

    // Top-level fields
    if (j.contains("bind_host")) {
        if (!j["bind_host"].is_string())
            throw std::runtime_error("bind_host must be a string");
        config.bind_host = j["bind_host"].get<std::string>();
    }
    if (j.contains("bind_port")) {
        if (!j["bind_port"].is_number_integer())
            throw std::runtime_error("bind_port must be an integer");
        config.bind_port = j["bind_port"].get<int>();
    }
    if (j.contains("max_connections")) {
        if (!j["max_connections"].is_number_integer())
            throw std::runtime_error("max_connections must be an integer");
        config.max_connections = j["max_connections"].get<int>();
    }
    if (j.contains("idle_timeout_sec")) {
        if (!j["idle_timeout_sec"].is_number_integer())
            throw std::runtime_error("idle_timeout_sec must be an integer");
        config.idle_timeout_sec = j["idle_timeout_sec"].get<int>();
    }
    if (j.contains("worker_threads")) {
        if (!j["worker_threads"].is_number_integer())
            throw std::runtime_error("worker_threads must be an integer");
        config.worker_threads = j["worker_threads"].get<int>();
    }
    if (j.contains("max_header_size")) {
        if (j["max_header_size"].is_number_unsigned()) {
            config.max_header_size = j["max_header_size"].get<size_t>();
        } else {
            throw std::runtime_error("max_header_size must be a non-negative integer");
        }
    }
    if (j.contains("max_body_size")) {
        if (j["max_body_size"].is_number_unsigned()) {
            config.max_body_size = j["max_body_size"].get<size_t>();
        } else {
            throw std::runtime_error("max_body_size must be a non-negative integer");
        }
    }
    if (j.contains("max_ws_message_size")) {
        if (j["max_ws_message_size"].is_number_unsigned()) {
            config.max_ws_message_size = j["max_ws_message_size"].get<size_t>();
        } else {
            throw std::runtime_error("max_ws_message_size must be a non-negative integer");
        }
    }
    if (j.contains("request_timeout_sec")) {
        if (!j["request_timeout_sec"].is_number_integer())
            throw std::runtime_error("request_timeout_sec must be an integer");
        config.request_timeout_sec = j["request_timeout_sec"].get<int>();
    }
    if (j.contains("shutdown_drain_timeout_sec")) {
        if (!j["shutdown_drain_timeout_sec"].is_number_integer())
            throw std::runtime_error("shutdown_drain_timeout_sec must be an integer");
        config.shutdown_drain_timeout_sec = j["shutdown_drain_timeout_sec"].get<int>();
    }

    // TLS section
    if (j.contains("tls")) {
        if (!j["tls"].is_object())
            throw std::runtime_error("tls must be an object");
    }
    if (j.contains("tls") && j["tls"].is_object()) {
        auto& tls = j["tls"];
        if (tls.contains("enabled")) {
            if (!tls["enabled"].is_boolean())
                throw std::runtime_error("tls.enabled must be a boolean");
            config.tls.enabled = tls["enabled"].get<bool>();
        }
        if (tls.contains("cert_file")) {
            if (!tls["cert_file"].is_string())
                throw std::runtime_error("tls.cert_file must be a string");
            config.tls.cert_file = tls["cert_file"].get<std::string>();
        }
        if (tls.contains("key_file")) {
            if (!tls["key_file"].is_string())
                throw std::runtime_error("tls.key_file must be a string");
            config.tls.key_file = tls["key_file"].get<std::string>();
        }
        if (tls.contains("min_version")) {
            if (!tls["min_version"].is_string())
                throw std::runtime_error("tls.min_version must be a string");
            config.tls.min_version = tls["min_version"].get<std::string>();
        }
    }

    // HTTP/2 section
    if (j.contains("http2")) {
        if (!j["http2"].is_object())
            throw std::runtime_error("http2 must be an object");
        auto& h2 = j["http2"];
        if (h2.contains("enabled")) {
            if (!h2["enabled"].is_boolean())
                throw std::runtime_error("http2.enabled must be a boolean");
            config.http2.enabled = h2["enabled"].get<bool>();
        }
        if (h2.contains("max_concurrent_streams")) {
            if (!h2["max_concurrent_streams"].is_number_unsigned())
                throw std::runtime_error("http2.max_concurrent_streams must be a non-negative integer");
            config.http2.max_concurrent_streams = h2["max_concurrent_streams"].get<uint32_t>();
        }
        if (h2.contains("initial_window_size")) {
            if (!h2["initial_window_size"].is_number_unsigned())
                throw std::runtime_error("http2.initial_window_size must be a non-negative integer");
            config.http2.initial_window_size = h2["initial_window_size"].get<uint32_t>();
        }
        if (h2.contains("max_frame_size")) {
            if (!h2["max_frame_size"].is_number_unsigned())
                throw std::runtime_error("http2.max_frame_size must be a non-negative integer");
            config.http2.max_frame_size = h2["max_frame_size"].get<uint32_t>();
        }
        if (h2.contains("max_header_list_size")) {
            if (!h2["max_header_list_size"].is_number_unsigned())
                throw std::runtime_error("http2.max_header_list_size must be a non-negative integer");
            config.http2.max_header_list_size = h2["max_header_list_size"].get<uint32_t>();
        }
    }

    // Log section
    if (j.contains("log")) {
        if (!j["log"].is_object())
            throw std::runtime_error("log must be an object");
    }
    if (j.contains("log") && j["log"].is_object()) {
        auto& log = j["log"];
        if (log.contains("level")) {
            if (!log["level"].is_string())
                throw std::runtime_error("log.level must be a string");
            config.log.level = log["level"].get<std::string>();
        }
        if (log.contains("file")) {
            if (!log["file"].is_string())
                throw std::runtime_error("log.file must be a string");
            config.log.file = log["file"].get<std::string>();
        }
        if (log.contains("max_file_size")) {
            if (log["max_file_size"].is_number_unsigned()) {
                config.log.max_file_size = log["max_file_size"].get<size_t>();
            } else {
                throw std::runtime_error("log.max_file_size must be a non-negative integer");
            }
        }
        if (log.contains("max_files")) {
            if (!log["max_files"].is_number_integer())
                throw std::runtime_error("log.max_files must be an integer");
            config.log.max_files = log["max_files"].get<int>();
        }
    }

    // Upstreams section
    if (j.contains("upstreams")) {
        if (!j["upstreams"].is_array())
            throw std::runtime_error("upstreams must be an array");
        for (const auto& item : j["upstreams"]) {
            if (!item.is_object())
                throw std::runtime_error("each upstream entry must be an object");
            UpstreamConfig upstream;
            upstream.name = item.value("name", "");
            upstream.host = item.value("host", "");
            upstream.port = item.value("port", 80);

            if (item.contains("tls")) {
                if (!item["tls"].is_object())
                    throw std::runtime_error("upstream tls must be an object");
                auto& tls = item["tls"];
                upstream.tls.enabled = tls.value("enabled", false);
                upstream.tls.ca_file = tls.value("ca_file", "");
                upstream.tls.verify_peer = tls.value("verify_peer", true);
                upstream.tls.sni_hostname = tls.value("sni_hostname", "");
                upstream.tls.min_version = tls.value("min_version", "1.2");
            }

            if (item.contains("pool")) {
                if (!item["pool"].is_object())
                    throw std::runtime_error("upstream pool must be an object");
                auto& pool = item["pool"];
                upstream.pool.max_connections = pool.value("max_connections", 64);
                upstream.pool.max_idle_connections = pool.value("max_idle_connections", 16);
                upstream.pool.connect_timeout_ms = pool.value("connect_timeout_ms", 5000);
                upstream.pool.idle_timeout_sec = pool.value("idle_timeout_sec", 90);
                upstream.pool.max_lifetime_sec = pool.value("max_lifetime_sec", 3600);
                upstream.pool.max_requests_per_conn = pool.value("max_requests_per_conn", 0);
            }

            if (item.contains("proxy")) {
                if (!item["proxy"].is_object())
                    throw std::runtime_error("upstream proxy must be an object");
                auto& proxy = item["proxy"];
                upstream.proxy.route_prefix = proxy.value("route_prefix", "");
                upstream.proxy.strip_prefix = proxy.value("strip_prefix", false);
                upstream.proxy.response_timeout_ms = proxy.value("response_timeout_ms", 30000);

                if (proxy.contains("methods")) {
                    if (!proxy["methods"].is_array())
                        throw std::runtime_error("upstream proxy methods must be an array");
                    for (const auto& m : proxy["methods"]) {
                        if (!m.is_string())
                            throw std::runtime_error("upstream proxy method must be a string");
                        upstream.proxy.methods.push_back(m.get<std::string>());
                    }
                }

                if (proxy.contains("header_rewrite")) {
                    if (!proxy["header_rewrite"].is_object())
                        throw std::runtime_error("upstream proxy header_rewrite must be an object");
                    auto& hr = proxy["header_rewrite"];
                    upstream.proxy.header_rewrite.set_x_forwarded_for = hr.value("set_x_forwarded_for", true);
                    upstream.proxy.header_rewrite.set_x_forwarded_proto = hr.value("set_x_forwarded_proto", true);
                    upstream.proxy.header_rewrite.set_via_header = hr.value("set_via_header", true);
                    upstream.proxy.header_rewrite.rewrite_host = hr.value("rewrite_host", true);
                }

                if (proxy.contains("retry")) {
                    if (!proxy["retry"].is_object())
                        throw std::runtime_error("upstream proxy retry must be an object");
                    auto& r = proxy["retry"];
                    upstream.proxy.retry.max_retries = r.value("max_retries", 0);
                    upstream.proxy.retry.retry_on_connect_failure = r.value("retry_on_connect_failure", true);
                    upstream.proxy.retry.retry_on_5xx = r.value("retry_on_5xx", false);
                    upstream.proxy.retry.retry_on_timeout = r.value("retry_on_timeout", false);
                    upstream.proxy.retry.retry_on_disconnect = r.value("retry_on_disconnect", true);
                    upstream.proxy.retry.retry_non_idempotent = r.value("retry_non_idempotent", false);
                }
            }

            config.upstreams.push_back(std::move(upstream));
        }
    }

    return config;
}

// Helper: parse env var as int, throw descriptive error on invalid input
static int EnvToInt(const char* val, const char* env_name) {
    try {
        size_t pos = 0;
        int result = std::stoi(val, &pos);
        // Reject trailing non-numeric characters (e.g., "8080junk")
        if (pos != std::strlen(val)) {
            throw std::runtime_error(
                std::string("Invalid integer for ") + env_name + ": " + val);
        }
        return result;
    } catch (const std::invalid_argument&) {
        throw std::runtime_error(
            std::string("Invalid integer for ") + env_name + ": " + val);
    } catch (const std::out_of_range&) {
        throw std::runtime_error(
            std::string("Integer out of range for ") + env_name + ": " + val);
    }
}

void ConfigLoader::ApplyEnvOverrides(ServerConfig& config) {
    const char* val = nullptr;

    val = std::getenv("REACTOR_BIND_HOST");
    if (val) config.bind_host = val;

    val = std::getenv("REACTOR_BIND_PORT");
    if (val) config.bind_port = EnvToInt(val, "REACTOR_BIND_PORT");

    val = std::getenv("REACTOR_TLS_ENABLED");
    if (val) {
        std::string s(val);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        if (s == "1" || s == "true" || s == "yes") {
            config.tls.enabled = true;
        } else if (s == "0" || s == "false" || s == "no") {
            config.tls.enabled = false;
        } else {
            throw std::invalid_argument(
                "Invalid REACTOR_TLS_ENABLED: '" + std::string(val) +
                "' (must be true/false/yes/no/1/0)");
        }
    }

    val = std::getenv("REACTOR_TLS_CERT");
    if (val) config.tls.cert_file = val;

    val = std::getenv("REACTOR_TLS_KEY");
    if (val) config.tls.key_file = val;

    val = std::getenv("REACTOR_LOG_LEVEL");
    if (val) config.log.level = val;

    val = std::getenv("REACTOR_LOG_FILE");
    if (val) config.log.file = val;

    val = std::getenv("REACTOR_MAX_CONNECTIONS");
    if (val) config.max_connections = EnvToInt(val, "REACTOR_MAX_CONNECTIONS");

    val = std::getenv("REACTOR_IDLE_TIMEOUT");
    if (val) config.idle_timeout_sec = EnvToInt(val, "REACTOR_IDLE_TIMEOUT");

    val = std::getenv("REACTOR_WORKER_THREADS");
    if (val) config.worker_threads = EnvToInt(val, "REACTOR_WORKER_THREADS");

    val = std::getenv("REACTOR_REQUEST_TIMEOUT");
    if (val) config.request_timeout_sec = EnvToInt(val, "REACTOR_REQUEST_TIMEOUT");

    val = std::getenv("REACTOR_SHUTDOWN_DRAIN_TIMEOUT");
    if (val) config.shutdown_drain_timeout_sec = EnvToInt(val, "REACTOR_SHUTDOWN_DRAIN_TIMEOUT");

    // HTTP/2 env overrides
    val = std::getenv("REACTOR_HTTP2_ENABLED");
    if (val) {
        std::string s(val);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        if (s == "1" || s == "true" || s == "yes") {
            config.http2.enabled = true;
        } else if (s == "0" || s == "false" || s == "no") {
            config.http2.enabled = false;
        } else {
            throw std::invalid_argument(
                "Invalid REACTOR_HTTP2_ENABLED: '" + std::string(val) +
                "' (must be true/false/yes/no/1/0)");
        }
    }
    val = std::getenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_MAX_CONCURRENT_STREAMS must be non-negative");
        config.http2.max_concurrent_streams = static_cast<uint32_t>(v);
    }
    val = std::getenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_INITIAL_WINDOW_SIZE must be non-negative");
        config.http2.initial_window_size = static_cast<uint32_t>(v);
    }
    val = std::getenv("REACTOR_HTTP2_MAX_FRAME_SIZE");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_MAX_FRAME_SIZE");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_MAX_FRAME_SIZE must be non-negative");
        config.http2.max_frame_size = static_cast<uint32_t>(v);
    }
    val = std::getenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_MAX_HEADER_LIST_SIZE must be non-negative");
        config.http2.max_header_list_size = static_cast<uint32_t>(v);
    }

    // No per-upstream environment variable overrides. Upstream configuration
    // is complex (array of named objects) and best managed through the JSON
    // config file. Individual upstream settings are not overridable via env.
}

void ConfigLoader::Validate(const ServerConfig& config) {
    // Validate bind_host is a strict dotted-quad IPv4 address.
    // Use inet_pton (not inet_addr) to reject legacy shorthand forms
    // like "1" (→ 0.0.0.1) or octal "0127.0.0.1" (→ 87.0.0.1).
    if (config.bind_host.empty()) {
        throw std::invalid_argument("bind_host must not be empty");
    }
    {
        struct in_addr addr{};
        if (inet_pton(AF_INET, config.bind_host.c_str(), &addr) != 1) {
            throw std::invalid_argument(
                "Invalid bind_host: '" + config.bind_host +
                "' (must be a dotted-quad IPv4 address, e.g. '0.0.0.0' or '127.0.0.1')");
        }
    }

    if (config.bind_port < 0 || config.bind_port > 65535) {
        throw std::invalid_argument(
            "Invalid bind_port: " + std::to_string(config.bind_port) +
            " (must be 0-65535)");
    }

    // 0 = unlimited (sentinel), negative = invalid
    if (config.max_connections < 0) {
        throw std::invalid_argument(
            "Invalid max_connections: " + std::to_string(config.max_connections) +
            " (must be >= 0, 0 = unlimited)");
    }

    // 0 = auto-detect (hardware_concurrency), negative = invalid
    if (config.worker_threads < 0) {
        throw std::invalid_argument(
            "Invalid worker_threads: " + std::to_string(config.worker_threads) +
            " (must be >= 0, 0 = auto)");
    }

    // 0 = disabled (sentinel), negative = invalid
    if (config.idle_timeout_sec < 0) {
        throw std::invalid_argument(
            "Invalid idle_timeout_sec: " + std::to_string(config.idle_timeout_sec) +
            " (must be >= 0, 0 = disabled)");
    }

    if (config.shutdown_drain_timeout_sec < 0 || config.shutdown_drain_timeout_sec > 300) {
        throw std::invalid_argument(
            "Invalid shutdown_drain_timeout_sec: " +
            std::to_string(config.shutdown_drain_timeout_sec) +
            " (must be 0-300)");
    }

    if (config.request_timeout_sec < 0) {
        throw std::invalid_argument(
            "Invalid request_timeout_sec: " + std::to_string(config.request_timeout_sec) +
            " (must be >= 0, 0 = disabled)");
    }

    // Bound size limits to prevent overflow in ComputeInputCap() where
    // max_header_size + max_body_size must not wrap size_t. Individual cap
    // at SIZE_MAX/2 ensures any pair sums safely on both 32-bit and 64-bit.
    static constexpr size_t MAX_SIZE_LIMIT = SIZE_MAX / 2;
    if (config.max_body_size > MAX_SIZE_LIMIT) {
        throw std::invalid_argument(
            "Invalid max_body_size: " + std::to_string(config.max_body_size) +
            " (exceeds maximum)");
    }
    if (config.max_header_size > MAX_SIZE_LIMIT) {
        throw std::invalid_argument(
            "Invalid max_header_size: " + std::to_string(config.max_header_size) +
            " (exceeds maximum)");
    }
    if (config.max_ws_message_size > MAX_SIZE_LIMIT) {
        throw std::invalid_argument(
            "Invalid max_ws_message_size: " + std::to_string(config.max_ws_message_size) +
            " (exceeds maximum)");
    }

    // Validate log level against the set recognized by logging::ParseLevel().
    // ParseLevel returns info for unrecognized strings — if the input isn't
    // literally "info" but maps to info, it's unrecognized (including empty).
    {
        spdlog::level::level_enum parsed = logging::ParseLevel(config.log.level);
        if (parsed == spdlog::level::info && config.log.level != "info") {
            throw std::invalid_argument(
                "Invalid log.level: '" + config.log.level +
                "' (must be trace, debug, info, warn, error, or critical)");
        }
    }

    // Validate log rotation settings when file logging is configured.
    // spdlog::rotating_file_sink_mt throws on max_size == 0, and negative
    // max_files converts to a huge size_t causing resource exhaustion.
    if (!config.log.file.empty()) {
        // Reject paths with empty basename (e.g., "/tmp/logs/" or just "/")
        // which would produce malformed date-based filenames.
        {
            auto last_slash = config.log.file.rfind('/');
            std::string basename = (last_slash != std::string::npos)
                ? config.log.file.substr(last_slash + 1)
                : config.log.file;
            if (basename.empty() || basename == "." || basename == "..") {
                throw std::invalid_argument(
                    "Invalid log.file: '" + config.log.file +
                    "' (must include a valid filename, not a directory path)");
            }
        }
        if (config.log.max_file_size == 0) {
            throw std::invalid_argument(
                "Invalid log.max_file_size: 0 (must be > 0 when log.file is set)");
        }
        if (config.log.max_files < 1) {
            throw std::invalid_argument(
                "Invalid log.max_files: " + std::to_string(config.log.max_files) +
                " (must be >= 1 when log.file is set)");
        }
    }

    // HTTP/2 validation (RFC 9113 constraints)
    if (config.http2.enabled) {
        if (config.http2.max_concurrent_streams < 1) {
            throw std::invalid_argument(
                "http2.max_concurrent_streams must be >= 1");
        }
        if (config.http2.initial_window_size < 1 ||
            config.http2.initial_window_size > HTTP2_CONSTANTS::MAX_WINDOW_SIZE) {
            throw std::invalid_argument(
                "http2.initial_window_size must be 1 to 2^31-1");
        }
        if (config.http2.max_frame_size < HTTP2_CONSTANTS::MIN_MAX_FRAME_SIZE ||
            config.http2.max_frame_size > HTTP2_CONSTANTS::MAX_MAX_FRAME_SIZE) {
            throw std::invalid_argument(
                "http2.max_frame_size must be 16384 to 16777215");
        }
        if (config.http2.max_header_list_size < 1) {
            throw std::invalid_argument(
                "http2.max_header_list_size must be >= 1");
        }
    }

    if (config.tls.enabled) {
        if (config.tls.cert_file.empty()) {
            throw std::invalid_argument(
                "TLS is enabled but cert_file is empty");
        }
        if (config.tls.key_file.empty()) {
            throw std::invalid_argument(
                "TLS is enabled but key_file is empty");
        }
        // Check cert/key files exist and are regular files. Uses stat()
        // which only needs directory traversal permission, not read access —
        // so CI/operator validation works even when the certs are owned by
        // the daemon user. TlsContext does the full OpenSSL load at runtime.
        {
            struct stat st{};
            if (stat(config.tls.cert_file.c_str(), &st) != 0) {
                if (errno == EACCES) {
                    // Can't traverse path — skip check, TlsContext handles it
                } else {
                    throw std::invalid_argument(
                        "TLS cert_file not found: '" + config.tls.cert_file +
                        "' (" + std::strerror(errno) + ")");
                }
            } else if (!S_ISREG(st.st_mode)) {
                throw std::invalid_argument(
                    "TLS cert_file is not a regular file: '" + config.tls.cert_file + "'");
            }
        }
        {
            struct stat st{};
            if (stat(config.tls.key_file.c_str(), &st) != 0) {
                if (errno == EACCES) {
                    // Can't traverse path — skip check, TlsContext handles it
                } else {
                    throw std::invalid_argument(
                        "TLS key_file not found: '" + config.tls.key_file +
                        "' (" + std::strerror(errno) + ")");
                }
            } else if (!S_ISREG(st.st_mode)) {
                throw std::invalid_argument(
                    "TLS key_file is not a regular file: '" + config.tls.key_file + "'");
            }
        }
        if (config.tls.min_version != "1.2" && config.tls.min_version != "1.3") {
            throw std::invalid_argument(
                "Invalid tls.min_version: '" + config.tls.min_version +
                "' (must be '1.2' or '1.3')");
        }
    }

    // Upstream validation
    {
        std::unordered_set<std::string> seen_names;
        for (size_t i = 0; i < config.upstreams.size(); ++i) {
            const auto& u = config.upstreams[i];
            const std::string idx = "upstreams[" + std::to_string(i) + "]";

            if (u.name.empty()) {
                throw std::invalid_argument(idx + ".name must not be empty");
            }
            if (!seen_names.insert(u.name).second) {
                throw std::invalid_argument(
                    "Duplicate upstream name: '" + u.name + "'");
            }
            if (u.host.empty()) {
                throw std::invalid_argument(
                    idx + " ('" + u.name + "'): host must not be empty");
            }
            // Upstream host must be a dotted-quad IPv4 address (no hostnames).
            // Hostnames would pass validation but fail at connect time with
            // inet_addr() returning INADDR_NONE. Reject early with a clear error.
            {
                struct in_addr upstream_addr{};
                if (inet_pton(AF_INET, u.host.c_str(), &upstream_addr) != 1) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name + "'): host must be a valid IPv4 address, got '" +
                        u.host + "'");
                }
            }
            if (u.port < 1 || u.port > 65535) {
                throw std::invalid_argument(
                    idx + " ('" + u.name + "'): port must be 1-65535, got " +
                    std::to_string(u.port));
            }

            // Pool constraints
            if (u.pool.max_connections < 1) {
                throw std::invalid_argument(
                    idx + " ('" + u.name + "'): pool.max_connections must be >= 1");
            }
            // When max_connections < worker_threads, some dispatcher
            // partitions will have zero capacity (requests queue and time
            // out). This is intentional for deployments that cap upstream
            // concurrency tightly (e.g., 4 backend connections across 8
            // workers). UpstreamHostPool logs a warning at construction;
            // validation does not reject the config.
            if (u.pool.max_idle_connections < 0 ||
                u.pool.max_idle_connections > u.pool.max_connections) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.max_idle_connections must be 0 to pool.max_connections (" +
                    std::to_string(u.pool.max_connections) + ")");
            }
            if (u.pool.connect_timeout_ms < 1000) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.connect_timeout_ms must be >= 1000 (timer resolution is 1s)");
            }
            if (u.pool.idle_timeout_sec < 1) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.idle_timeout_sec must be >= 1");
            }
            if (u.pool.max_lifetime_sec < 0) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.max_lifetime_sec must be >= 0 (0 = unlimited)");
            }
            if (u.pool.max_requests_per_conn < 0) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.max_requests_per_conn must be >= 0 (0 = unlimited)");
            }

            // Proxy config validation.
            //
            // route_prefix is the only field that's skipped when empty —
            // the manual HttpServer::Proxy() API intentionally leaves it
            // empty and passes the pattern as a code argument, so there's
            // nothing to parse here. All the other proxy settings
            // (methods, response_timeout_ms, retry) are read by the manual
            // API at registration time and need to be validated up-front
            // so bad values fail fast at config load instead of surfacing
            // later as a logged "Proxy: registration error" that silently
            // drops the route.
            if (!u.proxy.route_prefix.empty()) {
                // Validate route_prefix is a well-formed route pattern.
                // Catches double slashes, duplicate param names, catch-all
                // not last, etc. — these would otherwise crash at startup
                // when RegisterProxyRoutes calls RouteAsync.
                try {
                    auto segments = ROUTE_TRIE::ParsePattern(u.proxy.route_prefix);
                    ROUTE_TRIE::ValidatePattern(u.proxy.route_prefix, segments);
                } catch (const std::invalid_argument& e) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): proxy.route_prefix is invalid: " + e.what());
                }
            }

            // 0 = disabled (no response deadline). Otherwise minimum
            // 1000ms: deadline checks run on the dispatcher's timer scan
            // which has 1-second resolution. Sub-second positive values
            // can't be honored accurately — reject them.
            if (u.proxy.response_timeout_ms != 0 &&
                u.proxy.response_timeout_ms < 1000) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): proxy.response_timeout_ms must be 0 (disabled) "
                    "or >= 1000 (timer scan resolution is 1s)");
            }
            if (u.proxy.retry.max_retries < 0 || u.proxy.retry.max_retries > 10) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): proxy.retry.max_retries must be >= 0 and <= 10");
            }
            // Validate method names — reject unknowns and duplicates.
            // Duplicates would cause RouteAsync to throw at startup.
            {
                static const std::unordered_set<std::string> valid_methods = {
                    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"
                };
                std::unordered_set<std::string> seen_methods;
                for (const auto& m : u.proxy.methods) {
                    if (valid_methods.find(m) == valid_methods.end()) {
                        throw std::invalid_argument(
                            idx + " ('" + u.name +
                            "'): proxy.methods contains invalid method: " + m);
                    }
                    if (!seen_methods.insert(m).second) {
                        throw std::invalid_argument(
                            idx + " ('" + u.name +
                            "'): proxy.methods contains duplicate method: " + m);
                    }
                }
            }

            // Upstream TLS validation
            if (u.tls.enabled) {
                if (u.tls.min_version != "1.2" && u.tls.min_version != "1.3") {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): tls.min_version must be '1.2' or '1.3', got '" +
                        u.tls.min_version + "'");
                }
                // When verify_peer is true, sni_hostname must be set so
                // SSL_set1_host() can verify the certificate's CN/SAN.
                // Without it, only CA trust is checked — any trusted cert passes.
                if (u.tls.verify_peer && u.tls.sni_hostname.empty()) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): tls.sni_hostname is required when verify_peer is true "
                        "(upstream host is an IPv4 address, which cannot be verified "
                        "against certificate CN/SAN)");
                }
                // CA file validation — only when TLS + verify_peer is enabled.
                // When verify_peer=false, the runtime skips CA loading, so a
                // stale ca_file path should not block startup/reload.
                if (u.tls.verify_peer && !u.tls.ca_file.empty()) {
                    struct stat st{};
                    if (stat(u.tls.ca_file.c_str(), &st) != 0) {
                        if (errno == EACCES) {
                            // Can't traverse path — skip check, runtime handles it
                        } else {
                            throw std::invalid_argument(
                                idx + " ('" + u.name +
                                "'): tls.ca_file not found: '" + u.tls.ca_file +
                                "' (" + std::strerror(errno) + ")");
                        }
                    } else if (!S_ISREG(st.st_mode)) {
                        throw std::invalid_argument(
                            idx + " ('" + u.name +
                            "'): tls.ca_file is not a regular file: '" +
                            u.tls.ca_file + "'");
                    }
                }
            }  // if (u.tls.enabled)
        }
    }
}

ServerConfig ConfigLoader::Default() {
    return ServerConfig{};
}

std::string ConfigLoader::ToJson(const ServerConfig& config) {
    nlohmann::json j;
    j["bind_host"]          = config.bind_host;
    j["bind_port"]          = config.bind_port;
    j["max_connections"]    = config.max_connections;
    j["idle_timeout_sec"]   = config.idle_timeout_sec;
    j["worker_threads"]     = config.worker_threads;
    j["max_header_size"]    = config.max_header_size;
    j["max_body_size"]      = config.max_body_size;
    j["max_ws_message_size"]= config.max_ws_message_size;
    j["request_timeout_sec"]= config.request_timeout_sec;
    j["shutdown_drain_timeout_sec"] = config.shutdown_drain_timeout_sec;
    j["tls"]["enabled"]     = config.tls.enabled;
    j["tls"]["cert_file"]   = config.tls.cert_file;
    j["tls"]["key_file"]    = config.tls.key_file;
    j["tls"]["min_version"] = config.tls.min_version;
    j["log"]["level"]       = config.log.level;
    j["log"]["file"]        = config.log.file;
    j["log"]["max_file_size"] = config.log.max_file_size;
    j["log"]["max_files"]   = config.log.max_files;
    j["http2"]["enabled"]                = config.http2.enabled;
    j["http2"]["max_concurrent_streams"] = config.http2.max_concurrent_streams;
    j["http2"]["initial_window_size"]    = config.http2.initial_window_size;
    j["http2"]["max_frame_size"]         = config.http2.max_frame_size;
    j["http2"]["max_header_list_size"]   = config.http2.max_header_list_size;

    j["upstreams"] = nlohmann::json::array();
    for (const auto& u : config.upstreams) {
        nlohmann::json uj;
        uj["name"] = u.name;
        uj["host"] = u.host;
        uj["port"] = u.port;
        uj["tls"]["enabled"]      = u.tls.enabled;
        uj["tls"]["ca_file"]      = u.tls.ca_file;
        uj["tls"]["verify_peer"]  = u.tls.verify_peer;
        uj["tls"]["sni_hostname"] = u.tls.sni_hostname;
        uj["tls"]["min_version"]  = u.tls.min_version;
        uj["pool"]["max_connections"]      = u.pool.max_connections;
        uj["pool"]["max_idle_connections"] = u.pool.max_idle_connections;
        uj["pool"]["connect_timeout_ms"]   = u.pool.connect_timeout_ms;
        uj["pool"]["idle_timeout_sec"]     = u.pool.idle_timeout_sec;
        uj["pool"]["max_lifetime_sec"]     = u.pool.max_lifetime_sec;
        uj["pool"]["max_requests_per_conn"]= u.pool.max_requests_per_conn;
        // Always serialize proxy settings — an upstream may have non-default
        // proxy config (methods, retry, header_rewrite, timeout) even when
        // route_prefix is empty (exposed via programmatic Proxy() API).
        // Skipping this block on empty route_prefix would silently reset
        // those settings on a ToJson() / LoadFromString() round-trip.
        if (u.proxy != ProxyConfig{}) {
            nlohmann::json pj;
            pj["route_prefix"] = u.proxy.route_prefix;
            pj["strip_prefix"] = u.proxy.strip_prefix;
            pj["response_timeout_ms"] = u.proxy.response_timeout_ms;
            pj["methods"] = u.proxy.methods;

            nlohmann::json hrj;
            hrj["set_x_forwarded_for"] = u.proxy.header_rewrite.set_x_forwarded_for;
            hrj["set_x_forwarded_proto"] = u.proxy.header_rewrite.set_x_forwarded_proto;
            hrj["set_via_header"] = u.proxy.header_rewrite.set_via_header;
            hrj["rewrite_host"] = u.proxy.header_rewrite.rewrite_host;
            pj["header_rewrite"] = hrj;

            nlohmann::json rj;
            rj["max_retries"] = u.proxy.retry.max_retries;
            rj["retry_on_connect_failure"] = u.proxy.retry.retry_on_connect_failure;
            rj["retry_on_5xx"] = u.proxy.retry.retry_on_5xx;
            rj["retry_on_timeout"] = u.proxy.retry.retry_on_timeout;
            rj["retry_on_disconnect"] = u.proxy.retry.retry_on_disconnect;
            rj["retry_non_idempotent"] = u.proxy.retry.retry_non_idempotent;
            pj["retry"] = rj;

            uj["proxy"] = pj;
        }
        j["upstreams"].push_back(uj);
    }

    return j.dump(4);
}
