#include "cli/cli_parser.h"
#include "cli/daemonizer.h"
#include "cli/signal_handler.h"
#include "cli/pid_file.h"
#include "cli/version.h"
#include "config/config_loader.h"
#include "config/server_config.h"
#include "http/http_server.h"
// <chrono>, <iostream>, <thread>, <signal.h>, <unistd.h> provided by
// common.h (via http_server.h -> net_server.h)
#include "http/http_request.h"
#include "http/http_response.h"
#include "log/logger.h"

// <cstdio> provided by common.h (via http_server.h)
#include <cstdlib>
#include <exception>
#if !defined(_WIN32)
#include <syslog.h>
#endif

static constexpr int EXIT_OK          = 0;
static constexpr int EXIT_ERROR       = 1;
static constexpr int EXIT_USAGE_ERROR = 2;
static constexpr size_t HEALTH_BUF_SIZE = 256;

// ── Apply CLI flag overrides to config ───────────────────────────
static void ApplyCliOverrides(ServerConfig& config, const CliOptions& options) {
    if (options.port >= 0)            config.bind_port = options.port;
    if (!options.host.empty())        config.bind_host = options.host;
    if (!options.log_level.empty())   config.log.level = options.log_level;
    if (options.workers >= 0)         config.worker_threads = options.workers;
}

// ── Load and resolve config ──────────────────────────────────────
// Returns EXIT_OK on success, EXIT_ERROR on failure.
// @param loaded_file  Set to true if config was loaded from a file, false if
//                     defaults were used (no file on disk, implicit path).
static int LoadConfig(ServerConfig& config, const CliOptions& options,
                      bool& loaded_file) {
    loaded_file = false;
    try {
        if (access(options.config_path.c_str(), F_OK) == 0) {
            config = ConfigLoader::LoadFromFile(options.config_path);
            loaded_file = true;
        } else if (!options.config_path_explicit && errno == ENOENT) {
            config = ConfigLoader::Default();
        } else {
            std::cerr << "Error: " << options.config_path << ": "
                      << std::strerror(errno) << "\n";
            return EXIT_ERROR;
        }
        ConfigLoader::ApplyEnvOverrides(config);
        ApplyCliOverrides(config, options);
    } catch (const std::exception& e) {
        std::cerr << "Error loading configuration: " << e.what() << "\n";
        return EXIT_ERROR;
    }
    try {
        ConfigLoader::Validate(config);
    } catch (const std::invalid_argument& e) {
        std::cerr << "Configuration error: " << e.what() << "\n";
        return EXIT_ERROR;
    }
    return EXIT_OK;
}

// ── Handle stop/status commands ──────────────────────────────────
// CheckRunning returns: >0 = running (known PID), 0 = locked but PID unreadable, -1 = not running
static int HandleStatus(const CliOptions& options) {
    pid_t pid = PidFile::CheckRunning(options.pid_file);
    if (pid > 0) {
        std::cout << REACTOR_SERVER_NAME << " is running\n"
                  << "  PID:        " << pid << "\n"
                  << "  PID file:   " << options.pid_file << "\n";
        return EXIT_OK;
    }
    if (pid == 0) {
        std::cerr << REACTOR_SERVER_NAME
                  << " is running (PID file locked but PID unreadable)\n";
        return EXIT_ERROR;
    }
    std::cout << REACTOR_SERVER_NAME << " is not running\n";
    return EXIT_ERROR;
}

static int SendSignalToServer(const CliOptions& options, int sig,
                              const char* sig_name) {
    pid_t pid = PidFile::CheckRunning(options.pid_file);
    if (pid < 0) {
        std::cout << REACTOR_SERVER_NAME << " is not running\n";
        return EXIT_ERROR;
    }
    if (pid == 0) {
        std::cerr << REACTOR_SERVER_NAME
                  << " is running but PID is unreadable — cannot send signal\n";
        return EXIT_ERROR;
    }
    if (kill(pid, sig) == 0) {
        std::cout << "Sent " << sig_name << " to " << REACTOR_SERVER_NAME
                  << " (PID " << pid << ")\n";
        return EXIT_OK;
    }
    std::cerr << "Failed to send signal to PID " << pid
              << ": " << std::strerror(errno) << "\n";
    return EXIT_ERROR;
}

static int HandleStop(const CliOptions& options) {
    return SendSignalToServer(options, SIGTERM, "SIGTERM");
}

static int HandleReload(const CliOptions& options) {
    int rc = SendSignalToServer(options, SIGHUP, "SIGHUP");
    if (rc == EXIT_OK) {
        std::cout << "Note: SIGHUP triggers config reload in daemon mode, "
                  << "but shuts down foreground servers.\n"
                  << "      If the server was launched with nohup, SIGHUP may "
                  << "be silently ignored.\n";
    }
    return rc;
}

// ── Health endpoint handler ──────────────────────────────────────
static std::function<void(const HttpRequest&, HttpResponse&)>
MakeHealthHandler(HttpServer* server) {
    return [server](const HttpRequest& /*req*/, HttpResponse& res) {
        auto stats = server->GetStats();
        char buf[HEALTH_BUF_SIZE];
        std::snprintf(buf, sizeof(buf),
            R"({"status":"ok","pid":%d,"uptime_seconds":%lld})",
            static_cast<int>(getpid()),
            static_cast<long long>(stats.uptime_seconds));
        res.Status(200).Json(buf);
    };
}

// ── Stats endpoint handler ──────────────────────────────────────
static std::function<void(const HttpRequest&, HttpResponse&)>
MakeStatsHandler(HttpServer* server, const ServerConfig& config) {
    // Capture config by value so /stats always reflects the startup-time
    // configuration for restart-required fields (bind_host, bind_port, etc.).
    // This avoids a data race: ReloadConfig() mutates the caller's ServerConfig
    // on the main thread while dispatcher threads serve /stats requests.
    //
    // Safety: bind_host is validated as a numeric IPv4 address by
    // ConfigLoader::Validate() before reaching here, so no JSON escaping
    // is needed for the %s substitution.
    return [server, config](const HttpRequest& /*req*/, HttpResponse& res) {
        auto stats = server->GetStats();

        // Build JSON manually — avoid pulling in nlohmann/json for a simple response.
        // Config section shows only operational parameters — no file paths, no TLS details.
        static constexpr size_t STATS_BUF_SIZE = 1024;
        char buf[STATS_BUF_SIZE];
        int written = std::snprintf(buf, sizeof(buf),
            R"({"uptime_seconds":%lld,)"
            R"("connections":{"active":%lld,"active_http1":%lld,"active_http2":%lld,)"
            R"("active_h2_streams":%lld,"total_accepted":%lld},)"
            R"("requests":{"total":%lld,"active":%lld},)"
            R"("config":{"bind_host":"%s","bind_port":%d,"worker_threads":%d,)"
            R"("max_connections":%d,"idle_timeout_sec":%d,"request_timeout_sec":%d,)"
            R"("tls_enabled":%s,"http2_enabled":%s}})",
            static_cast<long long>(stats.uptime_seconds),
            static_cast<long long>(stats.active_connections),
            static_cast<long long>(stats.active_http1_connections),
            static_cast<long long>(stats.active_http2_connections),
            static_cast<long long>(stats.active_h2_streams),
            static_cast<long long>(stats.total_accepted),
            static_cast<long long>(stats.total_requests),
            static_cast<long long>(stats.active_requests),
            config.bind_host.c_str(), config.bind_port, stats.worker_threads,
            stats.max_connections, stats.idle_timeout_sec,
            stats.request_timeout_sec,
            config.tls.enabled ? "true" : "false",
            config.http2.enabled ? "true" : "false");
        if (written < 0 || static_cast<size_t>(written) >= sizeof(buf)) {
            logging::Get()->error("Stats JSON buffer overflow (written={})", written);
            res.Status(500).Json(R"({"error":"stats buffer overflow"})");
            return;
        }
        res.Status(200).Json(buf);
    };
}

// Forward declaration — defined below, after RequireAbsolutePath.
static int ValidateDaemonConfig(const ServerConfig& config,
                                const CliOptions& options);

// ── Config reload helper (SIGHUP in daemon mode) ────────────────
// Re-reads config file, validates, applies reload-safe fields.
// Returns true on success, false on error (current config kept).
static bool ReloadConfig(const std::string& config_path,
                         const CliOptions& options,
                         HttpServer& server,
                         ServerConfig& current_config,
                         bool& config_loaded_from_file) {
    // Always reopen log files on SIGHUP, even if config load fails — logrotate
    // sends SIGHUP with unchanged config to force FD reopen after file rename.
    // Without this, a temporarily missing config file blocks log rotation.
    auto reopen_existing_logs = [&]() {
        if (logging::Reopen()) {
            logging::Get()->info("Log files reopened");
        } else {
            logging::Get()->warn("Log file reopen failed, continuing with old file");
        }
    };

    ServerConfig new_config;
    bool loaded_from_file = false;
    try {
        // If the config file exists, load it. If not:
        // - If startup never had a file (defaults + env only): use current_config
        //   as base + re-apply env/CLI. This supports the documented "no config
        //   file" deployment mode.
        // - If startup DID load a file and it's now missing: that's a broken
        //   deploy — fail the reload so the operator notices.
        if (access(config_path.c_str(), F_OK) == 0) {
            new_config = ConfigLoader::LoadFromFile(config_path);
            loaded_from_file = true;
        } else if (!config_loaded_from_file && !options.config_path_explicit
                   && errno == ENOENT) {
            // Start from defaults, not current_config — env vars may have been
            // added/removed since startup. Re-applying env + CLI on top of
            // defaults matches the original startup sequence.
            new_config = ConfigLoader::Default();
            logging::Get()->info("No config file (startup used defaults), "
                                 "reloading from defaults + env/CLI overrides");
        } else {
            logging::Get()->error("Config reload failed: {}: {}",
                                  config_path, std::strerror(errno));
            reopen_existing_logs();
            return false;
        }
        ConfigLoader::ApplyEnvOverrides(new_config);
        ApplyCliOverrides(new_config, options);
    } catch (const std::exception& e) {
        logging::Get()->error("Config reload failed ({}): {}",
                              config_path, e.what());
        reopen_existing_logs();  // still reopen for logrotate
        return false;
    }

    // Daemon-specific validation: only check reload-relevant paths.
    // TLS paths are restart-only (ignored on reload), so don't validate them
    // here — ValidateDaemonConfig checks TLS too and would reject changes to
    // restart-only fields. PID file comes from CLI, not config, so it's stable.
    if (options.daemonize) {
        if (new_config.log.file.empty()) {
            logging::Get()->error("Config reload rejected: daemon mode requires a log file");
            reopen_existing_logs();
            return false;
        }
        if (new_config.log.file[0] != '/') {
            logging::Get()->error("Config reload rejected: log file path must be absolute ({})",
                                  new_config.log.file);
            reopen_existing_logs();
            return false;
        }
    }

    // Log restart-required field changes at warn level
    if (new_config.bind_host != current_config.bind_host)
        logging::Get()->warn("bind_host changed ({} -> {}) — requires restart, ignored",
                             current_config.bind_host, new_config.bind_host);
    if (new_config.bind_port != current_config.bind_port)
        logging::Get()->warn("bind_port changed ({} -> {}) — requires restart, ignored",
                             current_config.bind_port, new_config.bind_port);
    if (new_config.worker_threads != current_config.worker_threads)
        logging::Get()->warn("worker_threads changed ({} -> {}) — requires restart, ignored",
                             current_config.worker_threads, new_config.worker_threads);
    if (new_config.tls.enabled != current_config.tls.enabled ||
        new_config.tls.cert_file != current_config.tls.cert_file ||
        new_config.tls.key_file != current_config.tls.key_file ||
        new_config.tls.min_version != current_config.tls.min_version)
        logging::Get()->warn("tls.* changed — requires restart, ignored");
    if (new_config.http2.enabled != current_config.http2.enabled)
        logging::Get()->warn("http2.enabled changed — requires restart, ignored");

    // Validate log directory BEFORE applying any changes — if this fails,
    // nothing is mutated (no partial state).
    if (!new_config.log.file.empty()) {
        try {
            auto slash_pos = new_config.log.file.rfind('/');
            // Only create directory if the path has a directory component.
            // Basename-only paths like "reactor.log" have no slash — they're
            // valid in foreground mode and need no directory creation.
            if (slash_pos != std::string::npos && slash_pos > 0) {
                std::string dir = new_config.log.file.substr(0, slash_pos);
                logging::EnsureLogDir(dir);
            }
        } catch (const std::exception& e) {
            logging::Get()->error("Failed to create log directory: {}", e.what());
            reopen_existing_logs();
            return false;
        }
    }

    // Validate log fields explicitly BEFORE the full Validate call.
    // ConfigLoader::Validate stops at the first error — if a restart-only
    // field is bad AND a log field is bad, the restart-only error is thrown
    // first and the log error is missed (downgraded to a warning).
    {
        // log.level validation
        spdlog::level::level_enum parsed = logging::ParseLevel(new_config.log.level);
        if (parsed == spdlog::level::info && new_config.log.level != "info") {
            logging::Get()->error("Config reload rejected: invalid log.level '{}'",
                                  new_config.log.level);
            reopen_existing_logs();
            return false;
        }
        // log.max_file_size / log.max_files validation (when file logging is on)
        if (!new_config.log.file.empty()) {
            if (new_config.log.max_file_size == 0) {
                logging::Get()->error("Config reload rejected: log.max_file_size must be > 0");
                reopen_existing_logs();
                return false;
            }
            if (new_config.log.max_files < 1) {
                logging::Get()->error("Config reload rejected: log.max_files must be >= 1");
                reopen_existing_logs();
                return false;
            }
        }
    }
    // Warn about restart-required field issues (not applied during reload).
    try {
        ConfigLoader::Validate(new_config);
    } catch (const std::invalid_argument& e) {
        logging::Get()->warn("Config has restart-required field issues that will "
                             "fail on next restart: {}", e.what());
    }
    if (options.daemonize) {
        int drc = ValidateDaemonConfig(new_config, options);
        if (drc != EXIT_OK) {
            logging::Get()->warn("Config has daemon path issues that will "
                                 "fail on next daemon restart");
        }
    }

    // Apply log changes FIRST — if reopen fails on a changed path, nothing
    // else is mutated. This prevents partial reload where server limits are
    // applied but the log destination is wrong.
    if (logging::UpdateAndReopen(new_config.log.file, new_config.log.max_file_size,
                                 new_config.log.max_files)) {
        logging::Get()->info("Log files reopened");
    } else {
        if (new_config.log.file != current_config.log.file) {
            // Log path change failed — no server limits were applied yet.
            logging::Get()->error("Log file reopen failed for new path: {}",
                                  new_config.log.file);
            return false;
        } else {
            // Same path, rotation settings changed but reopen failed — preserve
            // old rotation settings so current_config matches the live logger.
            new_config.log.max_file_size = current_config.log.max_file_size;
            new_config.log.max_files = current_config.log.max_files;
            logging::Get()->warn("Log file reopen failed, continuing with old file");
        }
    }
    if (new_config.log.level != current_config.log.level) {
        logging::SetLevel(logging::ParseLevel(new_config.log.level));
        logging::Get()->info("Log level changed to {}", new_config.log.level);
    }

    // Apply server limits AFTER log changes succeed — ensures no partial reload.
    if (!server.Reload(new_config)) {
        logging::Get()->error("HttpServer::Reload() rejected the config");
        // Roll back log changes — restore the old logger config so the
        // process stays consistent (log state matches current_config).
        if (!logging::UpdateAndReopen(current_config.log.file,
                                      current_config.log.max_file_size,
                                      current_config.log.max_files)) {
            // Rollback failed — the old log path is no longer usable.
            // The process keeps logging to the new file/rotation policy.
            // Update current_config to match the live logger state so
            // subsequent reloads don't try to roll back to a dead path.
            logging::Get()->warn(
                "Logger rollback failed — keeping new log destination. "
                "current_config updated to match live logger state.");
            current_config.log.file = new_config.log.file;
            current_config.log.max_file_size = new_config.log.max_file_size;
            current_config.log.max_files = new_config.log.max_files;
        }
        if (new_config.log.level != current_config.log.level) {
            logging::SetLevel(logging::ParseLevel(current_config.log.level));
        }
        return false;
    }

    // Full reload committed (logger + server). Now safe to prune old
    // log files — UpdateAndReopen deferred pruning so a failed Reload()
    // wouldn't cause irreversible log loss.
    logging::PruneLogFiles();

    // Log reload-safe changes at info level.
    if (new_config.idle_timeout_sec != current_config.idle_timeout_sec)
        logging::Get()->info("idle_timeout_sec: {} -> {} (immediate)",
                             current_config.idle_timeout_sec, new_config.idle_timeout_sec);
    if (new_config.request_timeout_sec != current_config.request_timeout_sec)
        logging::Get()->info("request_timeout_sec: {} -> {} (new connections)",
                             current_config.request_timeout_sec, new_config.request_timeout_sec);
    if (new_config.max_connections != current_config.max_connections)
        logging::Get()->info("max_connections: {} -> {} (immediate)",
                             current_config.max_connections, new_config.max_connections);
    if (new_config.max_body_size != current_config.max_body_size)
        logging::Get()->info("max_body_size: {} -> {} (new connections)",
                             current_config.max_body_size, new_config.max_body_size);
    if (new_config.max_header_size != current_config.max_header_size)
        logging::Get()->info("max_header_size: {} -> {} (new connections)",
                             current_config.max_header_size, new_config.max_header_size);
    if (new_config.max_ws_message_size != current_config.max_ws_message_size)
        logging::Get()->info("max_ws_message_size: {} -> {} (new connections)",
                             current_config.max_ws_message_size, new_config.max_ws_message_size);

    // Update current_config with new values, but preserve restart-required
    // fields at their actual running values. Without this, the next reload's
    // diff comparison would be against phantom state (e.g., bind_port shows
    // 9090 even though the server is still listening on 8080).
    auto saved_host = current_config.bind_host;
    auto saved_port = current_config.bind_port;
    auto saved_tls = current_config.tls;
    auto saved_workers = current_config.worker_threads;
    auto saved_h2_enabled = current_config.http2.enabled;

    current_config = new_config;

    current_config.bind_host = saved_host;
    current_config.bind_port = saved_port;
    current_config.tls = saved_tls;
    current_config.worker_threads = saved_workers;
    current_config.http2.enabled = saved_h2_enabled;

    // Commit file-backed state only after full success — a failed reload
    // must not flip this flag or future reloads lose the defaults+env fallback.
    if (loaded_from_file) {
        config_loaded_from_file = true;
    }
    return true;
}

// ── Daemon path helper: reject relative paths (CWD changes to "/") ──
static bool RequireAbsolutePath(const std::string& path, const char* description) {
    if (!path.empty() && path[0] != '/') {
        std::cerr << "Error: daemon mode requires an absolute "
                  << description << " path\n";
        return false;
    }
    return true;
}

// ── Validate daemon-specific constraints ─────────────────────────
// Shared between HandleStart (runtime) and validate -d (dry-run).
// Returns EXIT_OK on success, EXIT_ERROR on failure.
static int ValidateDaemonConfig(const ServerConfig& config,
                                const CliOptions& options) {
    if (config.log.file.empty()) {
        std::cerr << "Error: daemon mode requires a log file "
                  << "(set log.file in config or REACTOR_LOG_FILE env var)\n";
        return EXIT_ERROR;
    }
    if (!RequireAbsolutePath(config.log.file, "log file") ||
        !RequireAbsolutePath(options.pid_file, "PID file")) {
        return EXIT_ERROR;
    }
    if (config.tls.enabled) {
        if (!RequireAbsolutePath(config.tls.cert_file, "TLS cert file") ||
            !RequireAbsolutePath(config.tls.key_file, "TLS key file")) {
            return EXIT_ERROR;
        }
    }
    return EXIT_OK;
}

// ── Handle start command ─────────────────────────────────────────
static int HandleStart(const CliOptions& options) {
    ServerConfig config;
    bool config_loaded_from_file = false;
    int rc = LoadConfig(config, options, config_loaded_from_file);
    if (rc != EXIT_OK) return rc;

    // ── Daemon pre-validation ───────────────────────────────
    // Must run before any filesystem side effects (EnsureLogDir).
    if (options.daemonize) {
        rc = ValidateDaemonConfig(config, options);
        if (rc != EXIT_OK) return rc;
    }
    // Note: logging::Init() calls EnsureLogDir internally when log.file
    // has a directory component, so no explicit mkdir is needed here.

    // Resolve config path to absolute BEFORE daemonizing (chdir changes to "/").
    // Prefer $PWD (shell's logical cwd) to preserve symlinked deployment dirs.
    // Verify $PWD actually points to the same directory as getcwd() (same
    // device+inode) — stale/overridden $PWD from wrappers or service managers
    // would pin reloads to the wrong file.
    std::string resolved_config_path = options.config_path;
    if (options.daemonize && !options.config_path.empty() &&
        options.config_path[0] != '/') {
        char cwd_buf[PATH_MAX];
        const char* base_dir = nullptr;
        const char* pwd = std::getenv("PWD");
        if (pwd && pwd[0] == '/' && getcwd(cwd_buf, sizeof(cwd_buf))) {
            // Verify $PWD is the same directory as real cwd (stat device+inode)
            struct stat pwd_st, cwd_st;
            if (stat(pwd, &pwd_st) == 0 && stat(cwd_buf, &cwd_st) == 0 &&
                pwd_st.st_dev == cwd_st.st_dev && pwd_st.st_ino == cwd_st.st_ino) {
                base_dir = pwd;  // $PWD is valid and matches — use logical path
            }
        }
        if (!base_dir && getcwd(cwd_buf, sizeof(cwd_buf))) {
            base_dir = cwd_buf;
        }
        if (base_dir) {
            resolved_config_path = std::string(base_dir) + "/" + options.config_path;
        } else {
            // Both $PWD and getcwd() failed — config path stays relative.
            // After daemonization (chdir "/"), relative paths resolve to
            // /config/server.json which is wrong. Fail fast.
            std::cerr << "Error: cannot resolve working directory for daemon "
                      << "config path: " << options.config_path << "\n";
            return EXIT_ERROR;
        }
    }

    // ── Daemonize (if requested) ────────────────────────────
    // MUST happen: after config validation, before PidFile/signals/logging
#if !defined(_WIN32)
    if (options.daemonize) {
        Daemonizer::Daemonize();
        // We are now the grandchild daemon process.
        // stdin/stdout/stderr -> /dev/null, CWD -> "/", new session.

        // Early logging init so PidFile/SignalHandler failures are logged
        // to the file sink (stderr is /dev/null after fork). HttpServer's
        // constructor will re-Init() which is safe — it replaces the logger.
        logging::SetConsoleEnabled(false);
        try {
            logging::Init("reactor", logging::ParseLevel(config.log.level),
                          config.log.file, config.log.max_file_size, config.log.max_files);
        } catch (const std::exception& e) {
            // stderr is /dev/null, but try syslog as last resort for debugging
            syslog(LOG_ERR, "%s: failed to initialize logging: %s",
                   REACTOR_SERVER_NAME, e.what());
            Daemonizer::NotifyFailed();
            _exit(EXIT_ERROR);
        } catch (...) {
            syslog(LOG_ERR, "%s: failed to initialize logging (unknown error)",
                   REACTOR_SERVER_NAME);
            Daemonizer::NotifyFailed();
            _exit(EXIT_ERROR);
        }
    }
#else
    if (options.daemonize) {
        std::cerr << "Error: daemon mode is not supported on this platform\n";
        return EXIT_ERROR;
    }
#endif

    // Helper: notify daemon parent of failure before returning an error.
    // No-op in foreground mode (NotifyFailed checks the pipe fd).
    auto daemon_fail = [&]() {
#if !defined(_WIN32)
        if (options.daemonize) Daemonizer::NotifyFailed();
#endif
    };

    // ── PID file ────────────────────────────────────────────
    if (!PidFile::Acquire(options.pid_file)) {
        if (options.daemonize) {
            logging::Get()->error("Failed to acquire PID file: {}", options.pid_file);
        } else {
            std::cerr << "Error: failed to acquire PID file: " << options.pid_file
                      << " (server may already be running)\n";
        }
        daemon_fail();
        return EXIT_ERROR;
    }
    std::atexit(PidFile::Release);

    // ── Signal handler ──────────────────────────────────────
    try {
        SignalHandler::Install(options.daemonize);
    } catch (const std::runtime_error& e) {
        if (options.daemonize) {
            logging::Get()->error("Signal handler setup failed: {}", e.what());
        } else {
            std::cerr << "Error setting up signal handler: " << e.what() << "\n";
        }
        daemon_fail();
        return EXIT_ERROR;
    }

    // ── Server construction ─────────────────────────────────
    int exit_code = EXIT_OK;
    std::unique_ptr<HttpServer> server;
    try {
        server = std::make_unique<HttpServer>(config);
    } catch (const std::exception& e) {
        logging::Get()->error("Fatal error: {}", e.what());
        daemon_fail();
        SignalHandler::Cleanup(CleanupMode::FOR_EXIT);
        logging::Shutdown();
        return EXIT_ERROR;
    }

    logging::Get()->info("{} version {} starting", REACTOR_SERVER_NAME,
                         REACTOR_SERVER_VERSION);
    logging::Get()->info("  Listen:  {}:{}", config.bind_host, config.bind_port);
    logging::Get()->info("  TLS:     {}",
        config.tls.enabled
            ? "enabled (" + config.tls.min_version + "+)"
            : "disabled");
    logging::Get()->info("  Workers: {}", config.worker_threads);
    logging::Get()->info("  PID:     {} ({})", getpid(), options.pid_file);
    if (options.daemonize) {
        logging::Get()->info("  Mode:    daemon");
    }

    if (options.health_endpoint) {
        server->Get("/health", MakeHealthHandler(server.get()));
        logging::Get()->info("  Health:  /health");
    }
    // /stats requires health_endpoint for backwards compatibility:
    // --no-health-endpoint disables both endpoints.
    // --no-stats-endpoint independently disables only /stats.
    if (options.stats_endpoint && options.health_endpoint) {
        server->Get("/stats", MakeStatsHandler(server.get(), config));
        logging::Get()->info("  Stats:   /stats");
    }

    // ── Wire readiness callback — fires after bind/listen, before event loop ──
    server->SetReadyCallback([&options]() {
        logging::Get()->info("{} ready, accepting connections", REACTOR_SERVER_NAME);
        logging::WriteMarker("SERVER START");
#if !defined(_WIN32)
        if (options.daemonize) Daemonizer::NotifyReady();
#endif
    });

    // ── Server thread ───────────────────────────────────────
    std::exception_ptr server_error;
    std::atomic<bool> server_failed{false};
    std::thread server_thread([&server, &server_error, &server_failed
#if !defined(_WIN32)
                                , &options
#endif
                               ]() {
        try {
            server->Start();
            // Start() returned normally — the server was stopped from within
            // (e.g., a request handler called HttpServer::Stop()). Signal the
            // main thread so it exits WaitForSignal() instead of hanging.
            if (!SignalHandler::ShutdownRequested()) {
                SignalHandler::MarkShutdownRequested();
                kill(getpid(), SIGTERM);
            }
        } catch (...) {
            server_error = std::current_exception();
#if !defined(_WIN32)
            // If Start() throws before the ready callback fires (init failure),
            // notify the daemon parent of failure so it doesn't hang.
            if (options.daemonize) Daemonizer::NotifyFailed();
#endif
            // Always surface the failure — even if shutdown was already
            // requested. A teardown exception is a real error that
            // systemd/supervisors should see (non-zero exit).
            server_failed.store(true, std::memory_order_release);
            if (!SignalHandler::ShutdownRequested()) {
                kill(getpid(), SIGTERM);
            }
        }
    });

    // ── Signal loop ─────────────────────────────────────────
    while (true) {
        SignalResult sig = SignalHandler::WaitForSignal();
        if (sig == SignalResult::SHUTDOWN) break;
        // Belt-and-suspenders rotation check (primary is Dispatcher::TimerHandler)
        logging::CheckRotation();
        // SIGHUP received
        if (options.daemonize) {
            // Daemon mode: reload configuration.
            // Gate on server readiness to prevent racing with Start() building
            // socket_dispatchers_. HttpServer::Reload() also checks internally.
            if (!server->IsReady()) {
                logging::Get()->warn("Received SIGHUP before server is ready, ignoring");
                continue;
            }
            logging::Get()->info("Received SIGHUP, reloading configuration");
            if (ReloadConfig(resolved_config_path, options, *server, config,
                            config_loaded_from_file)) {
                logging::Get()->info("Configuration reloaded successfully");
            } else {
                logging::Get()->warn("Configuration reload failed, keeping current config");
            }
        } else {
            // Foreground mode: treat SIGHUP as shutdown (terminal hangup).
            // Must mark shutdown so the server thread's catch block recognizes
            // this as an expected stop, not a server failure.
            logging::Get()->info("Received SIGHUP (terminal hangup), shutting down");
            SignalHandler::MarkShutdownRequested();
            break;
        }
    }

    // ── Shutdown ────────────────────────────────────────────
    logging::WriteMarker("SERVER STOP");
    logging::Get()->info("{} shutting down...", REACTOR_SERVER_NAME);
    server->Stop();

    server_thread.join();

    if (server_failed.load(std::memory_order_acquire) && server_error) {
        try {
            std::rethrow_exception(server_error);
        } catch (const std::exception& e) {
            logging::Get()->error("Server error: {}", e.what());
            exit_code = EXIT_ERROR;
        }
    }

    logging::Get()->info("{} stopped", REACTOR_SERVER_NAME);
    server.reset();

    SignalHandler::Cleanup(CleanupMode::FOR_EXIT);
    logging::Shutdown();
    return exit_code;
}

// ── main ─────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    CliOptions options;
    try {
        options = CliParser::Parse(argc, argv);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return EXIT_USAGE_ERROR;
    }

    switch (options.command) {
        case CliCommand::NONE:
        case CliCommand::HELP:
            CliParser::PrintUsage(argv[0]);
            return EXIT_OK;

        case CliCommand::VERSION:
            if (options.version_verbose)
                CliParser::PrintVersionVerbose();
            else
                CliParser::PrintVersion();
            return EXIT_OK;

        case CliCommand::STATUS:
            return HandleStatus(options);

        case CliCommand::STOP:
            return HandleStop(options);

        case CliCommand::RELOAD:
            return HandleReload(options);

        case CliCommand::VALIDATE: {
            ServerConfig config;
            bool unused_flag;
            int rc = LoadConfig(config, options, unused_flag);
            if (rc != EXIT_OK) return rc;
            if (options.daemonize) {
#if defined(_WIN32)
                std::cerr << "Error: daemon mode is not supported on this platform\n";
                return EXIT_ERROR;
#else
                rc = ValidateDaemonConfig(config, options);
                if (rc != EXIT_OK) return rc;
#endif
            }
            std::cout << "Configuration is valid.\n";
            return EXIT_OK;
        }

        case CliCommand::CONFIG: {
            ServerConfig config;
            bool unused_flag;
            int rc = LoadConfig(config, options, unused_flag);
            if (rc != EXIT_OK) return rc;
            std::cout << ConfigLoader::ToJson(config) << "\n";
            return EXIT_OK;
        }

        case CliCommand::START:
            return HandleStart(options);
    }

    return EXIT_ERROR;
}
