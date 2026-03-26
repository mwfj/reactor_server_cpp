#include "cli/cli_parser.h"
#include "cli/version.h"
#include "log/logger.h"

#include <getopt.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

// ── Validation helpers (file-scope) ──────────────────────────────

static int ParsePort(const char* str) {
    errno = 0;
    char* end = nullptr;
    long val = std::strtol(str, &end, 10);
    if (end == str || *end != '\0' || errno == ERANGE || val < 1 || val > 65535) {
        throw std::runtime_error(
            std::string("Invalid port: '") + str + "' (must be 1-65535)");
    }
    return static_cast<int>(val);
}

static int ParseNonNegativeInt(const char* str, const char* flag_name) {
    errno = 0;
    char* end = nullptr;
    long val = std::strtol(str, &end, 10);
    if (end == str || *end != '\0' || errno == ERANGE ||
        val < 0 || val > INT_MAX) {
        throw std::runtime_error(
            std::string("Invalid value for ") + flag_name +
            ": '" + str + "' (must be a non-negative integer)");
    }
    return static_cast<int>(val);
}

static std::string ValidateLogLevel(const char* str) {
    std::string level_str(str);
    spdlog::level::level_enum parsed = logging::ParseLevel(level_str);
    if (parsed != spdlog::level::info || level_str == "info") {
        return level_str;
    }
    throw std::runtime_error(
        std::string("Invalid log level: '") + str +
        "' (must be trace, debug, info, warn, error, or critical)");
}

// ── Command parsing ──────────────────────────────────────────────

static CliCommand ParseCommand(const char* str) {
    if (std::strcmp(str, "start") == 0)    return CliCommand::START;
    if (std::strcmp(str, "stop") == 0)     return CliCommand::STOP;
    if (std::strcmp(str, "status") == 0)   return CliCommand::STATUS;
    if (std::strcmp(str, "validate") == 0) return CliCommand::VALIDATE;
    if (std::strcmp(str, "config") == 0)   return CliCommand::CONFIG;
    if (std::strcmp(str, "version") == 0)  return CliCommand::VERSION;
    if (std::strcmp(str, "help") == 0)     return CliCommand::HELP;
    return CliCommand::NONE;
}

// ── getopt_long option table ─────────────────────────────────────

static constexpr int OPT_NO_HEALTH = 256;

static const struct option long_options[] = {
    {"config",             required_argument, nullptr, 'c'},
    {"port",               required_argument, nullptr, 'p'},
    {"host",               required_argument, nullptr, 'H'},
    {"log-level",          required_argument, nullptr, 'l'},
    {"workers",            required_argument, nullptr, 'w'},
    {"pid-file",           required_argument, nullptr, 'P'},
    {"no-health-endpoint", no_argument,       nullptr, OPT_NO_HEALTH},
    {"version",            no_argument,       nullptr, 'v'},
    {"version-verbose",    no_argument,       nullptr, 'V'},
    {"help",               no_argument,       nullptr, 'h'},
    {nullptr, 0, nullptr, 0}
};

static const char* short_options = "c:p:H:l:w:P:vVh";

// ── CliParser implementation ─────────────────────────────────────

CliOptions CliParser::Parse(int argc, char* argv[]) {
    CliOptions options;

    // Reset getopt global state (important for testability).
    // BSD/macOS getopt_long also requires optreset = 1 for repeated parsing.
    optind = 1;
    opterr = 1;
#if defined(__APPLE__) || defined(__FreeBSD__)
    optreset = 1;
#endif

    // If no arguments at all, command is NONE (prints usage).
    if (argc < 2) {
        return options;
    }

    // Check for global shortcuts -v, -V, -h before command parsing.
    // These work without a command: `./reactor_server -v`
    if (argv[1][0] == '-') {
        // No command given — parse flags only.
        // Only -v, -V, -h are valid without a command.
        int opt;
        while ((opt = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
            switch (opt) {
                case 'v':
                    options.command = CliCommand::VERSION;
                    return options;
                case 'V':
                    options.command = CliCommand::VERSION;
                    options.version_verbose = true;
                    return options;
                case 'h':
                    options.command = CliCommand::HELP;
                    return options;
                default:
                    throw std::runtime_error(
                        std::string("A command is required. Try '") +
                        REACTOR_SERVER_NAME + " help' for usage.");
            }
        }
        return options;
    }

    // First positional argument is the command.
    options.command = ParseCommand(argv[1]);
    if (options.command == CliCommand::NONE) {
        throw std::runtime_error(
            std::string("Unknown command: '") + argv[1] +
            "'. Try '" + REACTOR_SERVER_NAME + " help' for usage.");
    }

    // Commands that take no options — return immediately.
    if (options.command == CliCommand::VERSION ||
        options.command == CliCommand::HELP) {
        // Check for -V after "version" command
        if (options.command == CliCommand::VERSION && argc > 2) {
            for (int i = 2; i < argc; ++i) {
                if (std::strcmp(argv[i], "-V") == 0 ||
                    std::strcmp(argv[i], "--version-verbose") == 0) {
                    options.version_verbose = true;
                }
            }
        }
        return options;
    }

    // Parse remaining options after the command.
    // Skip argv[0] (program) and argv[1] (command) by setting optind = 2.
    optind = 2;
#if defined(__APPLE__) || defined(__FreeBSD__)
    optreset = 1;
#endif

    int opt;
    while ((opt = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (opt) {
            case 'c':
                options.config_path = optarg;
                options.config_path_explicit = true;
                break;
            case 'p':
                options.port = ParsePort(optarg);
                break;
            case 'H':
                options.host = optarg;
                break;
            case 'l':
                options.log_level = ValidateLogLevel(optarg);
                break;
            case 'w':
                options.workers = ParseNonNegativeInt(optarg, "--workers");
                break;
            case 'P':
                options.pid_file = optarg;
                break;
            case OPT_NO_HEALTH:
                options.health_endpoint = false;
                break;
            case 'v':
                options.command = CliCommand::VERSION;
                return options;
            case 'V':
                options.command = CliCommand::VERSION;
                options.version_verbose = true;
                return options;
            case 'h':
                options.command = CliCommand::HELP;
                return options;
            case '?':
                throw std::runtime_error("Invalid option (see above)");
            default:
                throw std::runtime_error("Unexpected option parsing error");
        }
    }

    // Check for unexpected positional arguments after the command
    if (optind < argc) {
        throw std::runtime_error(
            std::string("Unexpected argument: '") + argv[optind] + "'");
    }

    return options;
}

void CliParser::PrintUsage(const char* program_name) {
    std::cout
        << "Usage: " << program_name << " <command> [options]\n"
        << "\n"
        << "A high-performance C++17 HTTP/WebSocket/TLS server.\n"
        << "\n"
        << "Commands:\n"
        << "  start       Start the server (foreground)\n"
        << "  stop        Stop a running server\n"
        << "  status      Check server status\n"
        << "  validate    Validate configuration\n"
        << "  config      Show effective configuration\n"
        << "  version     Show version information\n"
        << "  help        Show this help\n"
        << "\n"
        << "Start options:\n"
        << "  -c, --config <file>         Config file (default: config/server.json)\n"
        << "  -p, --port <port>           Override bind port (1-65535)\n"
        << "  -H, --host <address>        Override bind address (numeric IPv4 only)\n"
        << "  -l, --log-level <level>     Override log level\n"
        << "                              (trace, debug, info, warn, error, critical)\n"
        << "  -w, --workers <N>           Override worker thread count (0 = auto)\n"
        << "  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)\n"
        << "  --no-health-endpoint       Disable the /health endpoint\n"
        << "\n"
        << "Stop/status options:\n"
        << "  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)\n"
        << "\n"
        << "Validate/config options:\n"
        << "  -c, --config <file>         Config file\n"
        << "  -p, --port <port>           Override bind port\n"
        << "  -H, --host <address>        Override bind address\n"
        << "  -l, --log-level <level>     Override log level\n"
        << "  -w, --workers <N>           Override worker threads\n"
        << "\n"
        << "Global options:\n"
        << "  -v, --version               Same as 'version'\n"
        << "  -V, --version-verbose       Verbose version with build details\n"
        << "  -h, --help                  Same as 'help'\n"
        << "\n"
        << "Config override precedence: defaults < config file < env vars < CLI flags\n"
        << "\n"
        << "Environment variables:\n"
        << "  REACTOR_BIND_HOST, REACTOR_BIND_PORT, REACTOR_TLS_ENABLED,\n"
        << "  REACTOR_TLS_CERT, REACTOR_TLS_KEY, REACTOR_LOG_LEVEL,\n"
        << "  REACTOR_LOG_FILE, REACTOR_MAX_CONNECTIONS, REACTOR_IDLE_TIMEOUT,\n"
        << "  REACTOR_WORKER_THREADS, REACTOR_REQUEST_TIMEOUT\n"
        << "\n"
        << "Examples:\n"
        << "  " << program_name << " start\n"
        << "  " << program_name << " start -p 9090 -l debug\n"
        << "  " << program_name << " start -c config/server.json\n"
        << "  " << program_name << " stop\n"
        << "  " << program_name << " status\n"
        << "  " << program_name << " validate -c config/server.json\n"
        << "  " << program_name << " config -p 9090 -l debug\n";
}

void CliParser::PrintVersion() {
    std::cout << REACTOR_SERVER_NAME << " version " << REACTOR_SERVER_VERSION << "\n";
}

void CliParser::PrintVersionVerbose() {
    std::cout << REACTOR_SERVER_NAME << " version " << REACTOR_SERVER_VERSION << "\n"
              << "  Compiler:  " << __VERSION__ << " (C++17)\n"
              << "  OpenSSL:   " << OpenSSL_version(OPENSSL_VERSION) << "\n"
              << "  Platform:  " << REACTOR_PLATFORM << "\n"
              << "  Features:  HTTP/1.1, WebSocket (RFC 6455), TLS/SSL\n";
}
