#include "log/logger.h"

#include <vector>
#include <mutex>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <chrono>
#include <algorithm>

namespace logging {

static std::shared_ptr<spdlog::logger> g_logger;
static std::mutex g_logger_mtx;

// Stored config for Reopen() reconstruction
static bool g_console_enabled = true;
static std::string g_logger_name = "reactor";
static spdlog::level::level_enum g_log_level = spdlog::level::info;
static std::string g_log_file;       // Original path from Init() (e.g., "logs/reactor.log")
static size_t g_max_size = 10485760;
static int g_max_files = 3;

// Decomposed log path components
static std::string g_log_dir;        // Directory (e.g., "logs")
static std::string g_log_prefix;     // Filename prefix (e.g., "reactor")
static std::string g_log_extension;  // Extension including dot (e.g., ".log")
static std::string g_current_file_path;  // Currently open file path with date+seq

static constexpr const char* LOG_PATTERN = "[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] %v";
static constexpr size_t DATE_BUF_SIZE = 16;

// ── Path decomposition helpers ──────────────────────────────────────

// Decompose "logs/reactor.log" -> dir="logs", prefix="reactor", ext=".log"
static void ParseLogPath(const std::string& path,
                          std::string& dir, std::string& prefix, std::string& ext) {
    auto last_slash = path.rfind('/');
    std::string filename;
    if (last_slash != std::string::npos) {
        dir = path.substr(0, last_slash);
        filename = path.substr(last_slash + 1);
    } else {
        dir = ".";
        filename = path;
    }

    auto last_dot = filename.rfind('.');
    if (last_dot != std::string::npos && last_dot > 0) {
        prefix = filename.substr(0, last_dot);
        ext = filename.substr(last_dot);
    } else {
        prefix = filename;
        ext = "";
    }
}

static std::string TodayDateString() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    char buf[DATE_BUF_SIZE];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return std::string(buf);
}

// Build a file path from components.
// seq=0 -> "logs/reactor-2026-03-30.log"
// seq=1 -> "logs/reactor-2026-03-30-1.log"
static std::string BuildFilePath(const std::string& dir, const std::string& prefix,
                                  const std::string& date, int seq,
                                  const std::string& ext) {
    std::string path = dir + "/" + prefix + "-" + date;
    if (seq > 0) {
        path += "-" + std::to_string(seq);
    }
    path += ext;
    return path;
}

// Scan directory for files matching {prefix}-{date}*{ext}.
// Returns a sorted vector of {seq, full_path} pairs.
static std::vector<std::pair<int, std::string>>
ScanDateFiles(const std::string& dir, const std::string& prefix,
              const std::string& date, const std::string& ext) {
    std::vector<std::pair<int, std::string>> files;
    std::string base_pattern = prefix + "-" + date;

    DIR* d = opendir(dir.c_str());
    if (!d) return files;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name(entry->d_name);

        if (name.find(base_pattern) != 0) continue;

        if (!ext.empty()) {
            if (name.size() < ext.size()) continue;
            if (name.substr(name.size() - ext.size()) != ext) continue;
        }

        std::string middle = name.substr(base_pattern.size(),
            name.size() - base_pattern.size() - ext.size());

        int seq = 0;
        if (middle.empty()) {
            seq = 0;
        } else if (middle[0] == '-') {
            try { seq = std::stoi(middle.substr(1)); } catch (...) { continue; }
        } else {
            continue;
        }

        files.emplace_back(seq, dir + "/" + name);
    }
    closedir(d);

    std::sort(files.begin(), files.end());
    return files;
}

// Resolve the log file path for today. Returns the latest non-full file,
// or the next sequence number if all existing files are full.
static std::string ResolveLogPath(const std::string& dir, const std::string& prefix,
                                   const std::string& ext, size_t max_size) {
    std::string today = TodayDateString();
    auto files = ScanDateFiles(dir, prefix, today, ext);

    if (files.empty()) {
        return BuildFilePath(dir, prefix, today, 0, ext);
    }

    // Check if the highest-seq file is still under the size limit
    int highest_seq = files.back().first;
    const std::string& candidate = files.back().second;
    struct stat st{};
    if (stat(candidate.c_str(), &st) == 0 &&
        static_cast<size_t>(st.st_size) < max_size) {
        return candidate;
    }

    return BuildFilePath(dir, prefix, today, highest_seq + 1, ext);
}

// ── File pruning ────────────────────────────────────────────────────

// Prune old log files for today's date if count exceeds g_max_files.
// Caller must hold g_logger_mtx.
static void PruneOldFiles() {
    if (g_max_files <= 0 || g_log_dir.empty() || g_log_prefix.empty()) return;

    std::string today = TodayDateString();
    auto files = ScanDateFiles(g_log_dir, g_log_prefix, today, g_log_extension);

    // Delete oldest files (lowest seq) if count exceeds max_files
    int excess = static_cast<int>(files.size()) - g_max_files;
    for (int i = 0; i < excess; ++i) {
        if (files[static_cast<size_t>(i)].second != g_current_file_path) {
            std::remove(files[static_cast<size_t>(i)].second.c_str());
        }
    }
}

// ── Sink construction ───────────────────────────────────────────────

// Build sinks vector from current config. Caller must hold g_logger_mtx.
static std::vector<spdlog::sink_ptr> BuildSinks(spdlog::level::level_enum level) {
    std::vector<spdlog::sink_ptr> sinks;

    if (g_console_enabled) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(level);
        sinks.push_back(console_sink);
    }

    if (!g_log_file.empty()) {
        g_current_file_path = ResolveLogPath(g_log_dir, g_log_prefix,
                                              g_log_extension, g_max_size);
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
            g_current_file_path, /*truncate=*/false);
        file_sink->set_level(level);
        sinks.push_back(file_sink);
        PruneOldFiles();
    }

    return sinks;
}

// Flush, rebuild sinks, and swap the global logger. Caller must hold g_logger_mtx.
static void RebuildLogger() {
    if (g_logger) g_logger->flush();

    auto sinks = BuildSinks(g_log_level);
    auto new_logger = std::make_shared<spdlog::logger>(
        g_logger_name, sinks.begin(), sinks.end());
    new_logger->set_level(g_log_level);
    new_logger->set_pattern(LOG_PATTERN);
    new_logger->flush_on(spdlog::level::info);

    spdlog::set_default_logger(new_logger);
    g_logger = new_logger;
}

// ── Public API ──────────────────────────────────────────────────────

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

    // Decompose log path for date-based naming
    if (!g_log_file.empty()) {
        ParseLogPath(g_log_file, g_log_dir, g_log_prefix, g_log_extension);
    } else {
        g_log_dir.clear();
        g_log_prefix.clear();
        g_log_extension.clear();
        g_current_file_path.clear();
    }

    auto sinks = BuildSinks(level);

    // Create logger with all sinks
    g_logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
    g_logger->set_level(level);
    g_logger->set_pattern(LOG_PATTERN);
    g_logger->flush_on(spdlog::level::info);

    // Register as default logger
    spdlog::set_default_logger(g_logger);
}

std::shared_ptr<spdlog::logger> Get() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (g_logger) {
        return g_logger;
    }
    auto fallback = spdlog::default_logger();
    if (fallback) return fallback;
    // After Shutdown(), spdlog's default logger is null. Create a minimal
    // stderr fallback so callers never dereference null. Not registered with
    // spdlog — immune to future Shutdown() calls.
    static auto stderr_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    static auto stderr_fallback = std::make_shared<spdlog::logger>("fallback", stderr_sink);
    return stderr_fallback;
}

void Shutdown() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (g_logger) {
        g_logger->flush();
    }
    spdlog::shutdown();
    g_logger.reset();

    // Reset all config to defaults so Reopen()/Init() after Shutdown()
    // starts from a clean slate.
    g_console_enabled = true;
    g_logger_name = "reactor";
    g_log_level = spdlog::level::info;
    g_log_file.clear();
    g_max_size = 10485760;
    g_max_files = 3;
    g_log_dir.clear();
    g_log_prefix.clear();
    g_log_extension.clear();
    g_current_file_path.clear();
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
        RebuildLogger();
        return true;
    } catch (const std::exception& e) {
        // Keep old logger active — never fail open
        g_logger->error("Failed to reopen log file: {}", e.what());
        return false;
    }
}

void CheckRotation() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (!g_logger || g_log_file.empty() || g_current_file_path.empty()) return;

    struct stat st{};
    if (stat(g_current_file_path.c_str(), &st) != 0) return;
    if (static_cast<size_t>(st.st_size) < g_max_size) return;

    // Size limit exceeded — rotate to next file
    try {
        RebuildLogger();
    } catch (const std::exception& e) {
        g_logger->error("Failed to rotate log file: {}", e.what());
    }
}

void EnsureLogDir(const std::string& dir) {
    if (dir.empty()) return;
    // Create intermediate directories
    std::string path;
    for (size_t i = 0; i < dir.size(); ++i) {
        path += dir[i];
        if (dir[i] == '/' && path.size() > 1) {
            mkdir(path.c_str(), 0755);  // ignore errors for intermediate dirs
        }
    }
    // Final directory
    struct stat st{};
    if (stat(dir.c_str(), &st) == 0) {
        if (S_ISDIR(st.st_mode)) return;
        throw std::runtime_error("Log path exists but is not a directory: " + dir);
    }
    if (mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
        throw std::runtime_error("Failed to create log directory '" + dir + "': " +
                                  std::strerror(errno));
    }
}

void WriteMarker(const std::string& text) {
    auto logger = Get();
    if (!logger) return;
    logger->info("================================ {} ================================", text);
}

} // namespace logging
