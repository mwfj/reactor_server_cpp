#pragma once

#include "config/server_config.h"
#include <string>
#include <stdexcept>

class ConfigLoader {
public:
    // Load configuration from a JSON file.
    // Throws std::runtime_error if the file cannot be read.
    static ServerConfig LoadFromFile(const std::string& path);

    // Load configuration from a JSON string.
    // Throws std::runtime_error on parse errors.
    static ServerConfig LoadFromString(const std::string& json_str);

    // Apply environment variable overrides to the configuration.
    // Recognized env vars:
    //   REACTOR_BIND_HOST, REACTOR_BIND_PORT,
    //   REACTOR_TLS_ENABLED, REACTOR_TLS_CERT, REACTOR_TLS_KEY,
    //   REACTOR_LOG_LEVEL, REACTOR_LOG_FILE,
    //   REACTOR_MAX_CONNECTIONS, REACTOR_IDLE_TIMEOUT,
    //   REACTOR_WORKER_THREADS, REACTOR_REQUEST_TIMEOUT
    static void ApplyEnvOverrides(ServerConfig& config);

    // Validate the configuration.
    // Throws std::invalid_argument if validation fails.
    static void Validate(const ServerConfig& config);

    // Return a ServerConfig with all default values.
    static ServerConfig Default();
};
