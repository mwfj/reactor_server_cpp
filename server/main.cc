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

static int HandleStop(const CliOptions& options) {
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
    if (kill(pid, SIGTERM) == 0) {
        std::cout << "Sent SIGTERM to " << REACTOR_SERVER_NAME
                  << " (PID " << pid << ")\n";
        return EXIT_OK;
    }
    std::cerr << "Failed to send signal to PID " << pid
              << ": " << std::strerror(errno) << "\n";
    return EXIT_ERROR;
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
    // Must run before any filesystem side effects (EnsureLogDir).
    if (options.daemonize) {
        rc = ValidateDaemonConfig(config, options);
        if (rc != EXIT_OK) return rc;
    }
    // Note: logging::Init() calls EnsureLogDir internally when log.file
    // has a directory component, so no explicit mkdir is needed here.

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
        logging::Get()->info("  Health:  /health");
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
    while (true) {
        SignalResult sig = SignalHandler::WaitForSignal();
        if (sig == SignalResult::SHUTDOWN) break;
        // Belt-and-suspenders rotation check (primary is Dispatcher::TimerHandler)
        logging::CheckRotation();
        // SIGHUP received
        if (options.daemonize) {
            // Daemon mode: reopen log files for rotation
            logging::Get()->info("Received SIGHUP, reopening log files");
            if (logging::Reopen()) {
                logging::Get()->info("Log files reopened");
            } else {
                logging::Get()->warn("Log file reopen failed, continuing with old file");
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
