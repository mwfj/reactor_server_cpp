#include "cli/cli_parser.h"
#include "cli/signal_handler.h"
#include "cli/pid_file.h"
#include "cli/version.h"
#include "config/config_loader.h"
#include "config/server_config.h"
#include "http/http_server.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "log/logger.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <thread>
#include <signal.h>
#include <unistd.h>

static constexpr int EXIT_OK          = 0;
static constexpr int EXIT_ERROR       = 1;
static constexpr int EXIT_USAGE_ERROR = 2;

// ── Apply CLI flag overrides to config ───────────────────────────
static void ApplyCliOverrides(ServerConfig& config, const CliOptions& options) {
    if (options.port >= 0)            config.bind_port = options.port;
    if (!options.host.empty())        config.bind_host = options.host;
    if (!options.log_level.empty())   config.log.level = options.log_level;
    if (options.workers >= 0)         config.worker_threads = options.workers;
}

// ── Handle -s stop|status commands ───────────────────────────────
// CheckRunning returns: >0 = running (known PID), 0 = running (PID unreadable), -1 = not running
static int HandleSignalCommand(const CliOptions& options) {
    pid_t pid = PidFile::CheckRunning(options.pid_file);

    if (options.signal_action == "status") {
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

    if (options.signal_action == "stop") {
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

    return EXIT_ERROR;
}

// ── Health endpoint handler ──────────────────────────────────────
static std::function<void(const HttpRequest&, HttpResponse&)>
MakeHealthHandler(std::chrono::steady_clock::time_point start_time) {
    return [start_time](const HttpRequest& /*req*/, HttpResponse& res) {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            now - start_time).count();

        char buf[256];
        std::snprintf(buf, sizeof(buf),
            R"({"status":"ok","pid":%d,"uptime_seconds":%lld})",
            static_cast<int>(getpid()), static_cast<long long>(uptime));
        res.Status(200).Json(buf);
    };
}

// ── main ─────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    CliOptions options;
    try {
        options = CliParser::Parse(argc, argv);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << "\n"
                  << "Try '" << REACTOR_SERVER_NAME << " --help' for usage.\n";
        return EXIT_USAGE_ERROR;
    }

    // Handle info commands (no config needed)
    if (options.help) {
        CliParser::PrintUsage(argv[0]);
        return EXIT_OK;
    }
    if (options.version) {
        CliParser::PrintVersion();
        return EXIT_OK;
    }
    if (options.version_verbose) {
        CliParser::PrintVersionVerbose();
        return EXIT_OK;
    }

    // Handle signal commands (stop/status)
    if (!options.signal_action.empty()) {
        return HandleSignalCommand(options);
    }

    // Load and resolve config (precedence: defaults < file < env < CLI)
    ServerConfig config;
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

    // Config inspection commands
    if (options.test_config) {
        try {
            ConfigLoader::Validate(config);
            std::cout << "Configuration is valid.\n";
            return EXIT_OK;
        } catch (const std::invalid_argument& e) {
            std::cerr << "Configuration error: " << e.what() << "\n";
            return EXIT_ERROR;
        }
    }
    try {
        ConfigLoader::Validate(config);
    } catch (const std::invalid_argument& e) {
        std::cerr << "Configuration error: " << e.what() << "\n";
        return EXIT_ERROR;
    }

    if (options.dump_effective_config) {
        std::cout << ConfigLoader::ToJson(config) << "\n";
        return EXIT_OK;
    }

    // PID file
    if (!PidFile::Acquire(options.pid_file)) {
        return EXIT_ERROR;
    }
    std::atexit(PidFile::Release);

    // Block SIGTERM/SIGINT/SIGPIPE before spawning any threads.
    // All threads inherit the blocked mask; only sigwait() receives them.
    try {
        SignalHandler::Install();
    } catch (const std::runtime_error& e) {
        std::cerr << "Error setting up signal handler: " << e.what() << "\n";
        return EXIT_ERROR;
    }

    // Construct server
    int exit_code = EXIT_OK;
    std::unique_ptr<HttpServer> server;
    try {
        server = std::make_unique<HttpServer>(config);
    } catch (const std::exception& e) {
        logging::Get()->error("Fatal error: {}", e.what());
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

    if (options.health_endpoint) {
        auto start_time = std::chrono::steady_clock::now();
        server->Get("/health", MakeHealthHandler(start_time));
        logging::Get()->info("  Health:  /health");
    }

    // Server runs in its own thread; main thread waits for signals via sigwait.
    //
    // Normal shutdown: sigwait returns (external SIGTERM/SIGINT) → main calls
    // Stop() → Start() returns → server thread exits normally.
    //
    // Startup failure: Start() throws → server thread checks if a shutdown
    // signal already happened (ShutdownRequested). If not, it's a real failure:
    // set server_failed and send SIGTERM to unblock main's sigwait.
    // If yes, the exception was caused by Stop() racing Start() — clean exit.
    std::exception_ptr server_error;
    std::atomic<bool> server_failed{false};
    std::thread server_thread([&server, &server_error, &server_failed]() {
        try {
            server->Start();
        } catch (...) {
            server_error = std::current_exception();
            if (!SignalHandler::ShutdownRequested()) {
                // Real startup/runtime failure (not caused by Stop()).
                // Wake main's sigwait so it doesn't hang.
                server_failed.store(true, std::memory_order_release);
                kill(getpid(), SIGTERM);
            }
            // else: exception was caused by Stop() racing Start() — clean exit.
            // Main already returned from sigwait (it called Stop()), so no
            // wakeup needed and no pending SIGTERM to worry about.
        }
    });

    logging::Get()->info("{} ready, accepting connections", REACTOR_SERVER_NAME);
    SignalHandler::WaitForSignal(nullptr);

    // After sigwait returns, call Stop() to unblock Start().
    // Safe even if Start() already exited — Stop() is idempotent on
    // a server that's no longer in its event loop.
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
