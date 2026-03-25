#pragma once

#include <string>

inline constexpr const char* DEFAULT_CONFIG_PATH = "config/server.json";

struct CliOptions {
    // Config
    std::string config_path = DEFAULT_CONFIG_PATH;
    bool test_config = false;
    bool dump_effective_config = false;

    // Signal command ("", "stop", "status")
    std::string signal_action;

    // Runtime overrides (sentinel values = not specified by user)
    int port = -1;
    std::string host;
    std::string log_level;
    int workers = -1;

    // Process management
    std::string pid_file = "/tmp/reactor_server.pid";

    // Info flags
    bool version = false;
    bool version_verbose = false;
    bool help = false;

    // Health endpoint
    bool health_endpoint = true;
};

class CliParser {
public:
    // Parse command-line arguments into CliOptions.
    // Throws std::runtime_error on invalid arguments.
    static CliOptions Parse(int argc, char* argv[]);

    // Print usage/help to stdout.
    static void PrintUsage(const char* program_name);

    // Print short version to stdout.
    static void PrintVersion();

    // Print verbose version (compiler, OpenSSL, platform, features) to stdout.
    static void PrintVersionVerbose();
};
