#pragma once

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/basic_file_sink.h"

#include <string>
#include <memory>

namespace logging {

// Initialize the logging system.
// @param name     Logger name (appears in log output)
// @param level    Minimum log level (default: info)
// @param log_file Log file path. Empty string = console only.
//                 When max_files > 1: date-based naming is used:
//                   {dir}/{prefix}-{YYYY-MM-DD}[-{seq}].log
//                 When max_files <= 1: the path is used as-is (no date suffix),
//                   compatible with external logrotate + SIGHUP → Reopen().
// @param max_size Approximate maximum size per log file in bytes (default: 10MB).
//                 Checked periodically by CheckRotation(), not on every write.
//                 Files may briefly exceed this between checks.
// @param max_files Maximum total log files to keep (default: 3).
//                 Oldest files (across all dates) are pruned when exceeded.
//                 Set to 1 for external logrotate compatibility (no auto-rotation).
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

// Atomically update file config AND reopen under a single lock.
// Prevents CheckRotation from observing partial state between update and reopen.
// On failure, rolls back config globals to the previous values.
// Returns true on success, false on failure (old logger kept active).
bool UpdateAndReopen(const std::string& file, size_t max_size, int max_files);

// Check if the current log file exceeds max_file_size or the date has
// rolled over, and rotate if needed. Called periodically from the
// Dispatcher timer handler. Thread-safe. No-op if no file sink is configured.
void CheckRotation();

// Ensure the directory exists (creates it with 0755 if missing).
// Throws std::runtime_error on failure.
void EnsureLogDir(const std::string& dir);

// Write a visual start/stop marker to the log sinks at info level.
// Format: "================================ {text} ================================"
// Uses a temporary logger to bypass g_logger's level without modifying it,
// so concurrent Get() callers never see a leaked lower level.
void WriteMarker(const std::string& text);

// Flush all sinks and shut down the logging system.
void Shutdown();

} // namespace logging
