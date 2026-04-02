#pragma once

// Lightweight CLI header — only needs <string> (not in common.h).
// Intentionally avoids pulling common.h to keep the CLI interface minimal.
#include <string>

inline constexpr const char* DEFAULT_CONFIG_PATH = "config/server.json";

// Subcommands recognized by the CLI.
enum class CliCommand {
    NONE,       // no command given → print usage
    START,      // start the server
    STOP,       // stop a running server
    RELOAD,     // reload configuration (send SIGHUP)
    STATUS,     // check if server is running
    VALIDATE,   // validate configuration
    CONFIG,     // dump effective configuration
    VERSION,    // print version
    HELP,       // print usage
};

struct CliOptions {
    CliCommand command = CliCommand::NONE;

    // Config
    std::string config_path = DEFAULT_CONFIG_PATH;
    bool config_path_explicit = false;  // true if user passed -c/--config

    // Runtime overrides (sentinel values = not specified by user)
    int port = -1;
    std::string host;
    std::string log_level;
    int workers = -1;

    // Process management
    std::string pid_file = "/tmp/reactor_server.pid";
    bool pid_file_explicit = false;  // true if user passed -P/--pid-file

    // Health/stats endpoints
    bool health_endpoint = true;
    bool stats_endpoint = true;

    // Daemon mode
    bool daemonize = false;

    // -V flag (verbose version)
    bool version_verbose = false;
};

class CliParser {
public:
    // Parse command-line arguments into CliOptions.
    // First positional argument is the command (start, stop, status, etc.).
    // Throws std::runtime_error on invalid arguments.
    static CliOptions Parse(int argc, char* argv[]);

    // Print usage/help to stdout.
    static void PrintUsage(const char* program_name);

    // Print short version to stdout.
    static void PrintVersion();

    // Print verbose version (compiler, OpenSSL, platform, features) to stdout.
    static void PrintVersionVerbose();
};
