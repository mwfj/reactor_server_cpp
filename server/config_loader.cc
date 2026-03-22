#include "config/config_loader.h"
#include "nlohmann/json.hpp"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <stdexcept>
#include <algorithm>

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
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        config.tls.enabled = (s == "1" || s == "true" || s == "yes");
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
}

void ConfigLoader::Validate(const ServerConfig& config) {
    if (config.bind_port < 1 || config.bind_port > 65535) {
        throw std::invalid_argument(
            "Invalid bind_port: " + std::to_string(config.bind_port) +
            " (must be 1-65535)");
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

    if (config.request_timeout_sec < 0) {
        throw std::invalid_argument(
            "Invalid request_timeout_sec: " + std::to_string(config.request_timeout_sec) +
            " (must be >= 0, 0 = disabled)");
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
        if (config.tls.min_version != "1.2" && config.tls.min_version != "1.3") {
            throw std::invalid_argument(
                "Invalid tls.min_version: '" + config.tls.min_version +
                "' (must be '1.2' or '1.3')");
        }
    }
}

ServerConfig ConfigLoader::Default() {
    return ServerConfig{};
}
