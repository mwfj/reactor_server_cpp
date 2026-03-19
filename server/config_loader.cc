#include "config/config_loader.h"
#include "nlohmann/json.hpp"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <stdexcept>

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
    if (j.contains("bind_host") && j["bind_host"].is_string()) {
        config.bind_host = j["bind_host"].get<std::string>();
    }
    if (j.contains("bind_port") && j["bind_port"].is_number_integer()) {
        config.bind_port = j["bind_port"].get<int>();
    }
    if (j.contains("max_connections") && j["max_connections"].is_number_integer()) {
        config.max_connections = j["max_connections"].get<int>();
    }
    if (j.contains("idle_timeout_sec") && j["idle_timeout_sec"].is_number_integer()) {
        config.idle_timeout_sec = j["idle_timeout_sec"].get<int>();
    }
    if (j.contains("worker_threads") && j["worker_threads"].is_number_integer()) {
        config.worker_threads = j["worker_threads"].get<int>();
    }
    if (j.contains("max_header_size") && j["max_header_size"].is_number_unsigned()) {
        config.max_header_size = j["max_header_size"].get<size_t>();
    }
    if (j.contains("max_body_size") && j["max_body_size"].is_number_unsigned()) {
        config.max_body_size = j["max_body_size"].get<size_t>();
    }
    if (j.contains("max_ws_message_size") && j["max_ws_message_size"].is_number_unsigned()) {
        config.max_ws_message_size = j["max_ws_message_size"].get<size_t>();
    }
    if (j.contains("request_timeout_sec") && j["request_timeout_sec"].is_number_integer()) {
        config.request_timeout_sec = j["request_timeout_sec"].get<int>();
    }

    // TLS section
    if (j.contains("tls") && j["tls"].is_object()) {
        auto& tls = j["tls"];
        if (tls.contains("enabled") && tls["enabled"].is_boolean()) {
            config.tls.enabled = tls["enabled"].get<bool>();
        }
        if (tls.contains("cert_file") && tls["cert_file"].is_string()) {
            config.tls.cert_file = tls["cert_file"].get<std::string>();
        }
        if (tls.contains("key_file") && tls["key_file"].is_string()) {
            config.tls.key_file = tls["key_file"].get<std::string>();
        }
        if (tls.contains("min_version") && tls["min_version"].is_string()) {
            config.tls.min_version = tls["min_version"].get<std::string>();
        }
    }

    // Log section
    if (j.contains("log") && j["log"].is_object()) {
        auto& log = j["log"];
        if (log.contains("level") && log["level"].is_string()) {
            config.log.level = log["level"].get<std::string>();
        }
        if (log.contains("file") && log["file"].is_string()) {
            config.log.file = log["file"].get<std::string>();
        }
        if (log.contains("max_file_size") && log["max_file_size"].is_number_integer()) {
            config.log.max_file_size = log["max_file_size"].get<size_t>();
        }
        if (log.contains("max_files") && log["max_files"].is_number_integer()) {
            config.log.max_files = log["max_files"].get<int>();
        }
    }

    return config;
}

void ConfigLoader::ApplyEnvOverrides(ServerConfig& config) {
    const char* val = nullptr;

    val = std::getenv("REACTOR_BIND_HOST");
    if (val) config.bind_host = val;

    val = std::getenv("REACTOR_BIND_PORT");
    if (val) config.bind_port = std::stoi(val);

    val = std::getenv("REACTOR_TLS_ENABLED");
    if (val) {
        std::string s(val);
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
    if (val) config.max_connections = std::stoi(val);

    val = std::getenv("REACTOR_IDLE_TIMEOUT");
    if (val) config.idle_timeout_sec = std::stoi(val);

    val = std::getenv("REACTOR_WORKER_THREADS");
    if (val) config.worker_threads = std::stoi(val);

    val = std::getenv("REACTOR_REQUEST_TIMEOUT");
    if (val) config.request_timeout_sec = std::stoi(val);
}

void ConfigLoader::Validate(const ServerConfig& config) {
    if (config.bind_port < 1 || config.bind_port > 65535) {
        throw std::invalid_argument(
            "Invalid bind_port: " + std::to_string(config.bind_port) +
            " (must be 1-65535)");
    }

    if (config.max_connections < 1) {
        throw std::invalid_argument(
            "Invalid max_connections: " + std::to_string(config.max_connections) +
            " (must be >= 1)");
    }

    if (config.worker_threads < 1) {
        throw std::invalid_argument(
            "Invalid worker_threads: " + std::to_string(config.worker_threads) +
            " (must be >= 1)");
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
    }
}

ServerConfig ConfigLoader::Default() {
    return ServerConfig{};
}
