#include "log/logger.h"

#include <vector>
#include <mutex>

namespace logging {

static std::shared_ptr<spdlog::logger> g_logger;
static std::mutex g_logger_mtx;

// Stored config for Reopen() reconstruction
static bool g_console_enabled = true;
static std::string g_logger_name = "reactor";
static spdlog::level::level_enum g_log_level = spdlog::level::info;
static std::string g_log_file;
static size_t g_max_size = 10485760;
static int g_max_files = 3;

static constexpr const char* LOG_PATTERN = "[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] %v";

// Build sinks vector from current config. Caller must hold g_logger_mtx.
static std::vector<spdlog::sink_ptr> BuildSinks(spdlog::level::level_enum level) {
    std::vector<spdlog::sink_ptr> sinks;

    if (g_console_enabled) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(level);
        sinks.push_back(console_sink);
    }

    if (!g_log_file.empty()) {
        spdlog::sink_ptr file_sink;
        if (g_max_files <= 1) {
            // Non-rotating sink: compatible with external logrotate.
            // logrotate renames the file, SIGHUP triggers Reopen() which
            // creates a fresh sink at the original path. No .1/.2 conflicts.
            file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                g_log_file, /*truncate=*/false);
        } else {
            // spdlog built-in size-based rotation with .1, .2, ... suffixes.
            // Do NOT combine with external logrotate (naming conflict).
            file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                g_log_file, g_max_size, g_max_files);
        }
        file_sink->set_level(level);
        sinks.push_back(file_sink);
    }

    return sinks;
}

void Init(const std::string& name,
          spdlog::level::level_enum level,
          const std::string& log_file,
          size_t max_size,
          int max_files) {
    std::lock_guard<std::mutex> lock(g_logger_mtx);

    // Store config for Reopen() reconstruction
    g_logger_name = name;
    g_log_level = level;
    g_log_file = log_file;
    g_max_size = max_size;
    g_max_files = max_files;

    auto sinks = BuildSinks(level);

    // Create logger with all sinks
    g_logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
    g_logger->set_level(level);
    g_logger->set_pattern(LOG_PATTERN);

    // Register as default logger
    spdlog::set_default_logger(g_logger);
}

std::shared_ptr<spdlog::logger> Get() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (g_logger) {
        return g_logger;
    }
    return spdlog::default_logger();
}

void Shutdown() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (g_logger) {
        g_logger->flush();
    }
    spdlog::shutdown();
    g_logger.reset();

    // Reset all config to defaults so Reopen()/Init() after Shutdown()
    // starts from a clean slate. Prevents stale g_console_enabled from
    // leaking across test runs if a test crashes before cleanup.
    g_console_enabled = true;
    g_logger_name = "reactor";
    g_log_level = spdlog::level::info;
    g_log_file.clear();
    g_max_size = 10485760;
    g_max_files = 3;
}

spdlog::level::level_enum ParseLevel(const std::string& level) {
    if (level == "trace")    return spdlog::level::trace;
    if (level == "debug")    return spdlog::level::debug;
    if (level == "info")     return spdlog::level::info;
    if (level == "warn")     return spdlog::level::warn;
    if (level == "error")    return spdlog::level::err;
    if (level == "critical") return spdlog::level::critical;
    return spdlog::level::info;
}

void SetConsoleEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    g_console_enabled = enabled;
}

bool Reopen() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (!g_logger || g_log_file.empty()) return true;  // no-op is success

    try {
        g_logger->flush();

        auto sinks = BuildSinks(g_log_level);

        auto new_logger = std::make_shared<spdlog::logger>(
            g_logger_name, sinks.begin(), sinks.end());
        new_logger->set_level(g_log_level);
        new_logger->set_pattern(LOG_PATTERN);

        // Swap under lock. Callers that already hold a shared_ptr from a prior
        // Get() will finish their in-flight log call on the old logger; the next
        // Get() picks up the new one. This brief overlap is acceptable.
        spdlog::set_default_logger(new_logger);
        g_logger = new_logger;
        return true;
    } catch (const std::exception& e) {
        // Keep old logger active — never fail open
        g_logger->error("Failed to reopen log file: {}", e.what());
        return false;
    }
}

} // namespace logging
