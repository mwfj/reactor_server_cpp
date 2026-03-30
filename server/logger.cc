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
static std::string g_current_log_date;  // Date string ("YYYY-MM-DD") of the current log file

static constexpr const char* LOG_PATTERN = "[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] %v";
static constexpr size_t DATE_BUF_SIZE = 16;

// ── Path decomposition helpers ──────────────────────────────────────

// Decompose "logs/reactor.log" -> dir="logs", prefix="reactor", ext=".log"
static void ParseLogPath(const std::string& path,
                          std::string& dir, std::string& prefix, std::string& ext) {
    auto last_slash = path.rfind('/');
    std::string filename;
    if (last_slash != std::string::npos) {
        dir = (last_slash == 0) ? "/" : path.substr(0, last_slash);
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

// Join directory and filename, avoiding "//" when dir is "/" (POSIX: leading
// "//" is implementation-defined and may resolve differently from "/").
static std::string JoinPath(const std::string& dir, const std::string& name) {
    if (dir.empty()) return name;
    if (dir.back() == '/') return dir + name;
    return dir + "/" + name;
}

// Build a file path from components.
// seq=0 -> "logs/reactor-2026-03-30.log"
// seq=1 -> "logs/reactor-2026-03-30-1.log"
static std::string BuildFilePath(const std::string& dir, const std::string& prefix,
                                  const std::string& date, int seq,
                                  const std::string& ext) {
    std::string filename = prefix + "-" + date;
    if (seq > 0) {
        filename += "-" + std::to_string(seq);
    }
    filename += ext;
    return JoinPath(dir, filename);
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
            try {
                size_t pos = 0;
                seq = std::stoi(middle.substr(1), &pos);
                if (pos != middle.size() - 1) continue;  // trailing garbage
            } catch (...) { continue; }
        } else {
            continue;
        }

        files.emplace_back(seq, JoinPath(dir, name));
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

// Prune old log files across ALL dates if total count exceeds g_max_files.
// Parses (date, seq) from each filename for correct chronological sorting.
// Caller must hold g_logger_mtx.
static void PruneOldFiles() {
    if (g_max_files <= 0 || g_log_dir.empty() || g_log_prefix.empty()) return;

    std::string name_prefix = g_log_prefix + "-";

    // {date, seq, path} — date string sorts chronologically, seq is numeric
    struct LogFileEntry {
        std::string date;
        int seq;
        std::string path;
        bool operator<(const LogFileEntry& o) const {
            if (date != o.date) return date < o.date;
            return seq < o.seq;
        }
    };

    std::vector<LogFileEntry> files;
    DIR* d = opendir(g_log_dir.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name(entry->d_name);
        if (name.find(name_prefix) != 0) continue;
        if (!g_log_extension.empty()) {
            if (name.size() < g_log_extension.size()) continue;
            if (name.substr(name.size() - g_log_extension.size()) != g_log_extension) continue;
        }
        // Extract middle part between prefix and extension: "YYYY-MM-DD" or "YYYY-MM-DD-N"
        std::string middle = name.substr(name_prefix.size(),
            name.size() - name_prefix.size() - g_log_extension.size());

        // Parse date (first 10 chars must be YYYY-MM-DD format)
        if (middle.size() < 10) continue;
        std::string date = middle.substr(0, 10);
        // Validate date shape: digits at 0-3, dash at 4, digits at 5-6, dash at 7, digits at 8-9
        if (date[4] != '-' || date[7] != '-') continue;
        bool valid_date = true;
        for (int di : {0,1,2,3,5,6,8,9}) {
            if (!std::isdigit(static_cast<unsigned char>(date[di]))) { valid_date = false; break; }
        }
        if (!valid_date) continue;
        int seq = 0;
        if (middle.size() > 10) {
            if (middle[10] != '-') continue;  // unexpected format
            try {
                size_t pos = 0;
                seq = std::stoi(middle.substr(11), &pos);
                if (pos != middle.size() - 11) continue;  // trailing garbage
            } catch (...) { continue; }
        }
        files.push_back({date, seq, JoinPath(g_log_dir, name)});
    }
    closedir(d);

    std::sort(files.begin(), files.end());

    // Delete oldest files if total count exceeds max_files.
    // Skip the current file — compensate by deleting the next oldest instead.
    int to_delete = static_cast<int>(files.size()) - g_max_files;
    size_t idx = 0;
    while (to_delete > 0 && idx < files.size()) {
        if (files[idx].path != g_current_file_path) {
            std::remove(files[idx].path.c_str());
            --to_delete;
        }
        ++idx;
    }
}

// ── Sink construction ───────────────────────────────────────────────

// Build sinks vector from current config, resolve date-based path, and
// prune old log files. Caller must hold g_logger_mtx.
static std::vector<spdlog::sink_ptr> BuildSinksAndPrune(spdlog::level::level_enum level) {
    std::vector<spdlog::sink_ptr> sinks;

    if (g_console_enabled) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(level);
        sinks.push_back(console_sink);
    }

    if (!g_log_file.empty()) {
        // Resolve the target path into locals first. Only commit to globals
        // after the file sink is successfully opened — prevents stale state
        // if the open throws (permissions, disk full, etc.).
        std::string new_path;
        std::string new_date;
        if (g_max_files <= 1) {
            // Non-rotating mode: use the original path as-is, compatible with
            // external logrotate.
            new_path = g_log_file;
        } else {
            // Date-based rotation mode: resolve today's date-based path
            new_date = TodayDateString();
            new_path = ResolveLogPath(g_log_dir, g_log_prefix,
                                      g_log_extension, g_max_size);
        }
        // This can throw (e.g., permission denied) — globals are still intact.
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
            new_path, /*truncate=*/false);
        // Sink opened successfully — now commit to globals.
        g_current_file_path = std::move(new_path);
        g_current_log_date = std::move(new_date);
        file_sink->set_level(level);
        sinks.push_back(file_sink);
        if (g_max_files > 1) {
            PruneOldFiles();
        }
    }

    return sinks;
}

// Flush, rebuild sinks, and swap the global logger. Caller must hold g_logger_mtx.
static void RebuildLogger() {
    if (g_logger) g_logger->flush();

    auto sinks = BuildSinksAndPrune(g_log_level);
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

    // Work with new config in locals first. Only commit to globals after
    // all failable operations (EnsureLogDir, sink creation) succeed.
    // This prevents a failed re-init from corrupting the live config.
    std::string new_dir, new_prefix, new_ext;
    if (!log_file.empty()) {
        ParseLogPath(log_file, new_dir, new_prefix, new_ext);
        if (!new_dir.empty() && new_dir != ".") {
            EnsureLogDir(new_dir);  // can throw
        }
    }

    // Temporarily install new config for BuildSinksAndPrune (it reads globals)
    auto saved_name = g_logger_name;
    auto saved_level = g_log_level;
    auto saved_file = g_log_file;
    auto saved_size = g_max_size;
    auto saved_files = g_max_files;
    auto saved_dir = g_log_dir;
    auto saved_prefix = g_log_prefix;
    auto saved_ext = g_log_extension;

    g_logger_name = name;
    g_log_level = level;
    g_log_file = log_file;
    g_max_size = max_size;
    g_max_files = max_files;
    g_log_dir = std::move(new_dir);
    g_log_prefix = std::move(new_prefix);
    g_log_extension = std::move(new_ext);
    if (log_file.empty()) {
        g_current_file_path.clear();
        g_current_log_date.clear();
    }

    try {
        auto sinks = BuildSinksAndPrune(level);

        // Create logger with all sinks
        auto new_logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
        new_logger->set_level(level);
        new_logger->set_pattern(LOG_PATTERN);
        new_logger->flush_on(spdlog::level::info);

        // All succeeded — commit
        g_logger = new_logger;
        spdlog::set_default_logger(new_logger);
    } catch (...) {
        // Restore previous config so Reopen/CheckRotation use the live config
        g_logger_name = std::move(saved_name);
        g_log_level = saved_level;
        g_log_file = std::move(saved_file);
        g_max_size = saved_size;
        g_max_files = saved_files;
        g_log_dir = std::move(saved_dir);
        g_log_prefix = std::move(saved_prefix);
        g_log_extension = std::move(saved_ext);
        throw;  // re-throw so caller knows Init failed
    }
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
    g_current_log_date.clear();
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
    // Use try_lock to avoid contention when multiple dispatchers call this
    // concurrently on their timer ticks. If another thread is already
    // checking, skip — it will handle rotation if needed.
    std::unique_lock<std::mutex> lock(g_logger_mtx, std::try_to_lock);
    if (!lock.owns_lock()) return;
    if (!g_logger || g_log_file.empty() || g_current_file_path.empty()) return;

    // Non-rotating mode (max_files <= 1): external logrotate handles rotation
    // via rename + SIGHUP → Reopen(). No automatic size/date rotation.
    if (g_max_files <= 1) return;

    bool needs_rotate = false;

    // Check date rollover: if today's date differs from the tracked log
    // date, rotate to a new day's file regardless of size.
    std::string today = TodayDateString();
    if (today != g_current_log_date) {
        needs_rotate = true;
    }

    // Check size limit using stat (no flush — avoids I/O on every timer tick).
    // Buffered debug/trace writes may not be reflected yet, so rotation could
    // be delayed by one timer cycle. Acceptable for a 10MB default threshold.
    if (!needs_rotate) {
        struct stat st{};
        if (stat(g_current_file_path.c_str(), &st) != 0) return;
        if (static_cast<size_t>(st.st_size) >= g_max_size) {
            needs_rotate = true;
        }
    }

    if (!needs_rotate) return;

    // Flush before rotation so buffered data goes to the old file.
    g_logger->flush();

    try {
        RebuildLogger();
    } catch (const std::exception& e) {
        g_logger->error("Failed to rotate log file: {}", e.what());
    }
}

void EnsureLogDir(const std::string& dir) {
    if (dir.empty()) return;
    // Strip trailing slashes to normalize the path
    std::string normalized = dir;
    while (normalized.size() > 1 && normalized.back() == '/') {
        normalized.pop_back();
    }
    // Create intermediate directories
    std::string path;
    for (size_t i = 0; i < normalized.size(); ++i) {
        path += normalized[i];
        if (normalized[i] == '/' && path.size() > 1) {
            mkdir(path.c_str(), 0755);  // ignore errors for intermediate dirs
        }
    }
    // Final directory
    struct stat st{};
    if (stat(normalized.c_str(), &st) == 0) {
        if (S_ISDIR(st.st_mode)) return;
        throw std::runtime_error("Log path exists but is not a directory: " + normalized);
    }
    if (mkdir(normalized.c_str(), 0755) != 0 && errno != EEXIST) {
        throw std::runtime_error("Failed to create log directory '" + normalized + "': " +
                                  std::strerror(errno));
    }
}

void WriteMarker(const std::string& text) {
    auto logger = Get();
    if (!logger) return;
    // Use critical level so markers are visible regardless of configured
    // log level (only filtered by level::off which disables all output).
    logger->critical("================================ {} ================================", text);
}

} // namespace logging
