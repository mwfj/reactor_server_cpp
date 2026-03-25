#include "cli/cli_parser.h"
#include "cli/version.h"
#include "log/logger.h"

#include <getopt.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

// ── Validation helpers (file-scope) ──────────────────────────────

static int ParsePort(const char* str) {
    char* end = nullptr;
    long val = std::strtol(str, &end, 10);
    if (end == str || *end != '\0' || val < 1 || val > 65535) {
        throw std::runtime_error(
            std::string("Invalid port: '") + str + "' (must be 1-65535)");
    }
    return static_cast<int>(val);
}

static int ParsePositiveInt(const char* str, const char* flag_name) {
    char* end = nullptr;
    long val = std::strtol(str, &end, 10);
    if (end == str || *end != '\0' || val <= 0) {
        throw std::runtime_error(
            std::string("Invalid value for ") + flag_name +
            ": '" + str + "' (must be a positive integer)");
    }
    return static_cast<int>(val);
}

// Validates against the same set recognized by logging::ParseLevel().
// Delegates to ParseLevel and rejects strings that map to the default fallback.
static std::string ValidateLogLevel(const char* str) {
    std::string level_str(str);
    spdlog::level::level_enum parsed = logging::ParseLevel(level_str);
    // ParseLevel returns info for unrecognized strings. If the input isn't
    // literally "info" but parsed to info, it's unrecognized.
    if (parsed != spdlog::level::info || level_str == "info") {
        return level_str;
    }
    throw std::runtime_error(
        std::string("Invalid log level: '") + str +
        "' (must be trace, debug, info, warn, error, or critical)");
}

static std::string ValidateSignalAction(const char* str) {
    if (std::strcmp(str, "stop") == 0 ||
        std::strcmp(str, "status") == 0) {
        return str;
    }
    throw std::runtime_error(
        std::string("Unknown signal action: '") + str +
        "' (must be 'stop' or 'status')");
}

// ── getopt_long option table ─────────────────────────────────────

// Long-only option IDs (must not collide with ASCII short options)
static constexpr int OPT_DUMP_CONFIG     = 256;
static constexpr int OPT_NO_HEALTH       = 257;

static const struct option long_options[] = {
    // Server control
    {"config",                required_argument, nullptr, 'c'},
    {"test-config",           no_argument,       nullptr, 't'},
    {"signal",                required_argument, nullptr, 's'},
    {"dump-effective-config", no_argument,       nullptr, OPT_DUMP_CONFIG},

    // Runtime overrides
    {"port",                  required_argument, nullptr, 'p'},
    {"host",                  required_argument, nullptr, 'H'},
    {"log-level",             required_argument, nullptr, 'l'},
    {"workers",               required_argument, nullptr, 'w'},

    // Process management
    {"pid-file",              required_argument, nullptr, 'P'},

    // Health endpoint
    {"no-health-endpoint",    no_argument,       nullptr, OPT_NO_HEALTH},

    // Info
    {"version",               no_argument,       nullptr, 'v'},
    {"version-verbose",       no_argument,       nullptr, 'V'},
    {"help",                  no_argument,       nullptr, 'h'},

    {nullptr, 0, nullptr, 0}
};

static const char* short_options = "c:ts:p:H:l:w:P:vVh";

// ── CliParser implementation ─────────────────────────────────────

CliOptions CliParser::Parse(int argc, char* argv[]) {
    CliOptions options;

    // Reset getopt global state (important for testability)
    optind = 1;
    opterr = 1;

    int opt;
    while ((opt = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (opt) {
            case 'c':
                options.config_path = optarg;
                break;
            case 't':
                options.test_config = true;
                break;
            case 's':
                options.signal_action = ValidateSignalAction(optarg);
                break;
            case OPT_DUMP_CONFIG:
                options.dump_effective_config = true;
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
                options.workers = ParsePositiveInt(optarg, "--workers");
                break;
            case 'P':
                options.pid_file = optarg;
                break;
            case OPT_NO_HEALTH:
                options.health_endpoint = false;
                break;
            case 'v':
                options.version = true;
                break;
            case 'V':
                options.version_verbose = true;
                break;
            case 'h':
                options.help = true;
                break;
            case '?':
                // getopt_long already printed an error message
                throw std::runtime_error("Invalid option (see above)");
            default:
                throw std::runtime_error("Unexpected option parsing error");
        }
    }

    // Check for unexpected positional arguments
    if (optind < argc) {
        throw std::runtime_error(
            std::string("Unexpected argument: '") + argv[optind] + "'");
    }

    return options;
}

void CliParser::PrintUsage(const char* program_name) {
    std::cout
        << "Usage: " << program_name << " [options]\n"
        << "\n"
        << "A high-performance C++17 HTTP/WebSocket/TLS server.\n"
        << "\n"
        << "Server Control:\n"
        << "  -c, --config <file>         Config file path (default: config/server.json)\n"
        << "  -t, --test-config           Validate config and exit\n"
        << "  -s, --signal <action>       Send signal to running instance (stop, status)\n"
        << "  --dump-effective-config     Show resolved config and exit\n"
        << "\n"
        << "Runtime Overrides:\n"
        << "  -p, --port <port>           Override bind port (1-65535)\n"
        << "  -H, --host <address>        Override bind address (numeric IPv4 only)\n"
        << "  -l, --log-level <level>     Override log level\n"
        << "                              (trace, debug, info, warn, error, critical)\n"
        << "  -w, --workers <N>           Override worker thread count\n"
        << "\n"
        << "Process Management:\n"
        << "  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)\n"
        << "  --no-health-endpoint       Disable the /health endpoint\n"
        << "\n"
        << "Info:\n"
        << "  -v, --version               Print version and exit\n"
        << "  -V, --version-verbose       Print version with build details and exit\n"
        << "  -h, --help                  Print this help and exit\n"
        << "\n"
        << "Config override precedence: defaults < config file < env vars < CLI flags\n"
        << "\n"
        << "Environment variables:\n"
        << "  REACTOR_BIND_HOST, REACTOR_BIND_PORT, REACTOR_TLS_ENABLED,\n"
        << "  REACTOR_TLS_CERT, REACTOR_TLS_KEY, REACTOR_LOG_LEVEL,\n"
        << "  REACTOR_LOG_FILE, REACTOR_MAX_CONNECTIONS, REACTOR_IDLE_TIMEOUT,\n"
        << "  REACTOR_WORKER_THREADS, REACTOR_REQUEST_TIMEOUT\n";
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
