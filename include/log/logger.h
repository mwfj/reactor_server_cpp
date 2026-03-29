#pragma once

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/basic_file_sink.h"

#include <string>
#include <memory>

namespace logging {

// Initialize the logging system.
// @param name     Logger name (appears in log output)
// @param level    Minimum log level (default: info)
// @param log_file Optional log file path for rotating file sink
// @param max_size Maximum size of each log file in bytes (default: 10MB)
// @param max_files Maximum number of rotated log files (default: 3)
void Init(const std::string& name = "reactor",
          spdlog::level::level_enum level = spdlog::level::info,
          const std::string& log_file = "",
          size_t max_size = 10485760,
          int max_files = 3);

// Get the global logger instance.
// If Init() has not been called, returns spdlog's default logger.
std::shared_ptr<spdlog::logger> Get();

// Parse a log level string to spdlog enum.
// Accepts: "trace", "debug", "info", "warn", "error", "critical".
// Returns spdlog::level::info for unrecognized strings.
spdlog::level::level_enum ParseLevel(const std::string& level);

// Set whether Init() creates a console (stdout) sink. Sticky: survives
// subsequent Init() calls. Daemon mode sets this to false before Init()
// so that HttpServer's re-Init() inherits the preference.
void SetConsoleEnabled(bool enabled);

// Close and reopen file sinks for log rotation (SIGHUP handler).
// Reconstructs the logger with fresh file handles while preserving
// console preference and log level. Thread-safe. No-op if no file
// sink is configured or Init() has not been called.
// Returns true on success, false on failure (old logger kept active).
bool Reopen();

// Change the log level at runtime without reconstructing the logger.
// Thread-safe. No-op if Init() has not been called.
void SetLevel(spdlog::level::level_enum level);

// Update the stored file sink config (file path, max size, max files).
// Takes effect on next Reopen(). Thread-safe. Does NOT reopen immediately.
void UpdateFileConfig(const std::string& file, size_t max_size, int max_files);

// Flush all sinks and shut down the logging system.
void Shutdown();

} // namespace logging
