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

#include <cstdio>
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
static int LoadConfig(ServerConfig& config, const CliOptions& options) {
    try {
        if (access(options.config_path.c_str(), F_OK) == 0) {
            config = ConfigLoader::LoadFromFile(options.config_path);
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
    return SendSignalToServer(options, SIGHUP, "SIGHUP");
}

// ── Health endpoint handler ──────────────────────────────────────
static std::function<void(const HttpRequest&, HttpResponse&)>
MakeHealthHandler(std::chrono::steady_clock::time_point start_time) {
    return [start_time](const HttpRequest& /*req*/, HttpResponse& res) {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            now - start_time).count();

        char buf[HEALTH_BUF_SIZE];
        std::snprintf(buf, sizeof(buf),
            R"({"status":"ok","pid":%d,"uptime_seconds":%lld})",
            static_cast<int>(getpid()), static_cast<long long>(uptime));
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
                         ServerConfig& current_config) {
    ServerConfig new_config;
    try {
        // On reload, always require the config file — never fall back to
        // defaults. At startup, a missing implicit config is fine (server starts
        // with defaults), but on reload, silently replacing live settings with
        // defaults would be surprising and destructive. If the file disappeared
        // (deploy, rename mistake), the operator should notice via the error log.
        new_config = ConfigLoader::LoadFromFile(config_path);
        ConfigLoader::ApplyEnvOverrides(new_config);
        ApplyCliOverrides(new_config, options);
    } catch (const std::exception& e) {
        logging::Get()->error("Config reload failed ({}): {}",
                              config_path, e.what());
        return false;
    }
    // NOTE: Full ConfigLoader::Validate() is NOT called here — it would reject
    // restart-only fields (bind_port, tls.*, etc.) that Reload() ignores anyway.
    // HttpServer::Reload() validates only reload-safe fields internally.

    // Daemon-specific validation: reject relative/empty log paths that would
    // break after chdir("/"). Same checks as startup (ValidateDaemonConfig).
    if (options.daemonize) {
        int drc = ValidateDaemonConfig(new_config, options);
        if (drc != EXIT_OK) {
            logging::Get()->error("Config reload rejected: daemon path validation failed");
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

    // Apply HttpServer reload BEFORE logger changes — if Reload() rejects the
    // config (e.g., invalid H2 settings), we must not mutate the logger state.
    if (!server.Reload(new_config)) {
        logging::Get()->error("HttpServer::Reload() rejected the config");
        return false;
    }

    // Apply log changes: always reopen (logrotate sends SIGHUP with unchanged
    // config to force descriptor reopen after file rename).
    logging::UpdateFileConfig(new_config.log.file, new_config.log.max_file_size,
                              new_config.log.max_files);
    if (logging::Reopen()) {
        logging::Get()->info("Log files reopened");
    } else {
        // Roll back stored sink config so subsequent SIGHUPs don't retry
        // the broken file/sink parameters.
        logging::UpdateFileConfig(current_config.log.file,
                                  current_config.log.max_file_size,
                                  current_config.log.max_files);
        if (new_config.log.file != current_config.log.file) {
            logging::Get()->error("Log file reopen failed for new path: {}",
                                  new_config.log.file);
            // Roll back the already-applied server limits to match current_config
            server.Reload(current_config);
            return false;
        }
        logging::Get()->warn("Log file reopen failed, continuing with old file");
    }
    if (new_config.log.level != current_config.log.level) {
        logging::SetLevel(logging::ParseLevel(new_config.log.level));
        logging::Get()->info("Log level changed to {}", new_config.log.level);
    }

    // Log reload-safe changes at info level.
    // idle_timeout and max_connections take effect immediately for all connections.
    // Size limits and request_timeout are cached per-connection — only new
    // connections pick up the updated values.
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
    int rc = LoadConfig(config, options);
    if (rc != EXIT_OK) return rc;

    // ── Daemon pre-validation ───────────────────────────────
    if (options.daemonize) {
        rc = ValidateDaemonConfig(config, options);
        if (rc != EXIT_OK) return rc;
    }

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
        SignalHandler::Cleanup();
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
        auto start_time = std::chrono::steady_clock::now();
        server->Get("/health", MakeHealthHandler(start_time));
        server->Get("/stats", MakeStatsHandler(server.get(), config));
        logging::Get()->info("  Health:  /health");
        logging::Get()->info("  Stats:   /stats");
    }

    // ── Wire readiness callback to fire after init, before event loop ──
    // Used by daemon mode to signal parent, and by the signal loop to gate
    // reloads until socket_dispatchers_ is fully built (prevents races).
    std::atomic<bool> server_ready{false};
#if !defined(_WIN32)
    if (options.daemonize) {
        server->SetReadyCallback([&server_ready]() {
            server_ready.store(true, std::memory_order_release);
            Daemonizer::NotifyReady();
        });
    } else {
        server->SetReadyCallback([&server_ready]() {
            server_ready.store(true, std::memory_order_release);
        });
    }
#else
    server->SetReadyCallback([&server_ready]() {
        server_ready.store(true, std::memory_order_release);
    });
#endif

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
        } catch (...) {
            server_error = std::current_exception();
#if !defined(_WIN32)
            // If Start() throws before the ready callback fires (init failure),
            // notify the daemon parent of failure so it doesn't hang.
            if (options.daemonize) Daemonizer::NotifyFailed();
#endif
            if (!SignalHandler::ShutdownRequested()) {
                server_failed.store(true, std::memory_order_release);
                kill(getpid(), SIGTERM);
            }
        }
    });

    // ── Signal loop ─────────────────────────────────────────
    logging::Get()->info("{} ready, accepting connections", REACTOR_SERVER_NAME);
    while (true) {
        SignalResult sig = SignalHandler::WaitForSignal();
        if (sig == SignalResult::SHUTDOWN) break;
        // SIGHUP received
        if (options.daemonize) {
            // Daemon mode: reload configuration.
            // Gate on server_ready to prevent racing with Start() building
            // socket_dispatchers_ — SetConnectionTimeout/SetTimerInterval
            // walk the vector without synchronization.
            if (!server_ready.load(std::memory_order_acquire)) {
                logging::Get()->warn("Received SIGHUP before server is ready, ignoring");
                continue;
            }
            logging::Get()->info("Received SIGHUP, reloading configuration");
            if (ReloadConfig(resolved_config_path, options, *server, config)) {
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

    SignalHandler::Cleanup();
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
            int rc = LoadConfig(config, options);
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
            int rc = LoadConfig(config, options);
            if (rc != EXIT_OK) return rc;
            std::cout << ConfigLoader::ToJson(config) << "\n";
            return EXIT_OK;
        }

        case CliCommand::START:
            return HandleStart(options);
    }

    return EXIT_ERROR;
}
