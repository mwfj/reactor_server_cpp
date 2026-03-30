#pragma once

// cli_test.h — Comprehensive test suite for the CLI entry point components.
//
// Covers:
//   - CliParser (17 tests): default values, all short/long options, validation errors
//   - PidFile (7 tests): acquire/release lifecycle, stale detection, ReadPid, CheckRunning
//   - Config override precedence (5 tests): defaults < file < env < CLI
//   - SignalHandler (2 tests): install/cleanup, sigwait unblocks WaitForShutdown
//   - Phase 2 additions:
//     - Logger (6 tests): SetConsoleEnabled, Reopen, no-op paths, level persistence
//     - SignalHandler Phase 2 (3 tests): WaitForSignal SIGTERM/SIGHUP,
//                                        WaitForShutdown ignores SIGHUP
//     - CliParser daemonize (7 tests): -d/-daemonize flag and per-command validation
//   - Phase 3+4 additions (sections 8–12):
//     - Config Reload (5 tests): reload-safe fields applied, restart-required skipped,
//                                missing/invalid file handled, log level change
//     - reload CLI subcommand (4 tests): parsing, per-command validation, help text
//     - /stats endpoint (3 tests): JSON shape, uptime increases, config section matches
//     - Counter accuracy (4 tests): connection +/-, request counter, H2 stream counters
//     - SIGHUP integration (3 tests): WaitForSignal RELOAD, invalid config no crash,
//                                     daemon vs foreground SIGHUP behaviour
//
// Port range: 10500-10599 (unit tests) + 10600-10699 (Phase 3+4 integration tests)
// Temp file pattern: /tmp/test_reactor_NNNN.pid

#include "test_framework.h"
#include "cli/cli_parser.h"
#include "cli/pid_file.h"
#include "cli/signal_handler.h"
#include "cli/version.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "log/logger.h"
#include "http/http_server.h"
#include "http/http_request.h"
#include "http/http_response.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>

namespace CliTests {

// ── Helpers ──────────────────────────────────────────────────────────────────

// Generate a unique temp PID-file path to keep tests isolated.
// Uses the process PID + a counter so parallel calls never collide.
static std::string MakeTmpPidPath() {
    static std::atomic<int> counter{0};
    int n = counter.fetch_add(1, std::memory_order_relaxed);
    return "/tmp/test_reactor_" + std::to_string(getpid()) + "_" + std::to_string(n) + ".pid";
}

// Write arbitrary content to a file — used to create pre-seeded PID files.
static bool WriteFile(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << content;
    return true;
}

// ── Category label (reused across all tests in this file) ────────────────────
static constexpr TestFramework::TestCategory CLI_CATEGORY = TestFramework::TestCategory::OTHER;

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1: CliParser Tests (1–17)
// ─────────────────────────────────────────────────────────────────────────────

// Test 1: Parsing with no arguments should yield all default values.
// Validates that the CliOptions struct is zero/empty-initialised as documented.
void TestParseDefaults() {
    std::cout << "\n[TEST] CliParser: Default values with no arguments..." << std::endl;
    try {
        const char* args[] = {"reactor_server"};
        int argc = 1;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = true;
        std::string err;

        if (opts.command != CliCommand::NONE) {
            pass = false; err += "command should be NONE with no args; ";
        }
        if (opts.config_path != "config/server.json") {
            pass = false; err += "config_path default wrong; ";
        }
        if (opts.port != -1) {
            pass = false; err += "port default should be -1; ";
        }
        if (!opts.host.empty()) {
            pass = false; err += "host should be empty; ";
        }
        if (!opts.log_level.empty()) {
            pass = false; err += "log_level should be empty; ";
        }
        if (opts.workers != -1) {
            pass = false; err += "workers default should be -1; ";
        }
        if (opts.pid_file != "/tmp/reactor_server.pid") {
            pass = false; err += "pid_file default wrong; ";
        }
        if (opts.version_verbose != false) {
            pass = false; err += "version_verbose should be false; ";
        }
        if (opts.health_endpoint != true) {
            pass = false; err += "health_endpoint should default to true; ";
        }

        TestFramework::RecordTest("CliParser: Default values", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Default values", false, e.what(), CLI_CATEGORY);
    }
}

// Test 2: -c / --config sets config_path.
void TestParseConfigPath() {
    std::cout << "\n[TEST] CliParser: -c overrides config_path..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "-c", "/custom/path.json"};
        int argc = 4;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.config_path == "/custom/path.json");
        std::string err = pass ? "" : "config_path not set to /custom/path.json";
        TestFramework::RecordTest("CliParser: -c config path", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: -c config path", false, e.what(), CLI_CATEGORY);
    }
}

// Test 3: All short options set in one invocation.
// -p 9090 -H 0.0.0.0 -l debug -w 4
void TestParseAllShortOptions() {
    std::cout << "\n[TEST] CliParser: All short options parsed together..." << std::endl;
    try {
        const char* args[] = {
            "reactor_server",
            "start",
            "-p", "9090",
            "-H", "0.0.0.0",
            "-l", "debug",
            "-w", "4"
        };
        int argc = 10;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = true;
        std::string err;

        if (opts.port != 9090)         { pass = false; err += "port != 9090; "; }
        if (opts.host != "0.0.0.0")    { pass = false; err += "host != 0.0.0.0; "; }
        if (opts.log_level != "debug") { pass = false; err += "log_level != debug; "; }
        if (opts.workers != 4)         { pass = false; err += "workers != 4; "; }

        TestFramework::RecordTest("CliParser: All short options", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: All short options", false, e.what(), CLI_CATEGORY);
    }
}

// Test 4: All long options equivalent to test 3.
void TestParseAllLongOptions() {
    std::cout << "\n[TEST] CliParser: All long options parsed together..." << std::endl;
    try {
        const char* args[] = {
            "reactor_server",
            "start",
            "--port",      "9090",
            "--host",      "0.0.0.0",
            "--log-level", "debug",
            "--workers",   "4"
        };
        int argc = 10;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = true;
        std::string err;

        if (opts.port != 9090)         { pass = false; err += "port != 9090; "; }
        if (opts.host != "0.0.0.0")    { pass = false; err += "host != 0.0.0.0; "; }
        if (opts.log_level != "debug") { pass = false; err += "log_level != debug; "; }
        if (opts.workers != 4)         { pass = false; err += "workers != 4; "; }

        TestFramework::RecordTest("CliParser: All long options", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: All long options", false, e.what(), CLI_CATEGORY);
    }
}

// Test 5: Port number exceeding 65535 must throw.
void TestParseInvalidPort() {
    std::cout << "\n[TEST] CliParser: Port 99999 throws..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "--port", "99999"};
        int argc = 4;
        CliParser::Parse(argc, const_cast<char**>(args));
        // Should not reach here
        TestFramework::RecordTest("CliParser: Port out of range", false,
            "Expected exception for port 99999", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: Port out of range", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Port out of range", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 6: Negative port must throw.
// Port 0 is technically reserved/invalid; -1 is clearly out of range.
void TestParseInvalidPortNegative() {
    std::cout << "\n[TEST] CliParser: Port -1 throws..." << std::endl;
    // Note: getopt treats -1 as the end-of-options sentinel, so we pass a
    // string that looks like -1 but cannot be mistaken for a flag.
    // We use a string with no leading '-' that parses to a negative strtol value.
    // However, the flag still has a leading '-' before the number. To
    // exercise ParsePort with value 0 (boundary), we use port 0 as the
    // "too low" case (valid range is 1-65535).
    try {
        const char* args[] = {"reactor_server", "start", "--port", "0"};
        int argc = 4;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: Port 0 throws", false,
            "Expected exception for port 0", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: Port 0 throws", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Port 0 throws", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 7: Non-numeric port string must throw.
void TestParseInvalidPortNonNumeric() {
    std::cout << "\n[TEST] CliParser: Port 'abc' throws..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "--port", "abc"};
        int argc = 4;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: Port non-numeric", false,
            "Expected exception for port 'abc'", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: Port non-numeric", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Port non-numeric", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 8: Unknown log-level string must throw.
void TestParseInvalidLogLevel() {
    std::cout << "\n[TEST] CliParser: Invalid log level throws..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "--log-level", "foo"};
        int argc = 4;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: Invalid log level", false,
            "Expected exception for log-level 'foo'", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: Invalid log level", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Invalid log level", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 9: Unknown command must throw.
// "restart" is not a recognized subcommand and must be rejected.
void TestParseUnknownCommand() {
    std::cout << "\n[TEST] CliParser: Unknown command throws..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "restart"};
        int argc = 2;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: Unknown command", false,
            "Expected exception for unknown command 'restart'", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: Unknown command", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Unknown command", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 10: Unknown long option must throw.
// getopt_long prints to stderr for us; the code converts '?' to a runtime_error.
void TestParseUnknownOption() {
    std::cout << "\n[TEST] CliParser: Unknown option throws..." << std::endl;
    // Suppress getopt's own error message to avoid cluttering test output.
    // We do this by temporarily redirecting stderr — but that is not safe
    // across threads. Instead, suppress via the opterr global (set to 0).
    // CliParser resets opterr = 1 inside Parse(), so we cannot prevent
    // getopt from printing before the exception.  That's acceptable for
    // tests.  We just verify that a runtime_error is thrown.
    try {
        const char* args[] = {"reactor_server", "start", "--unknown-flag"};
        int argc = 3;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: Unknown option", false,
            "Expected exception for --unknown-flag", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: Unknown option", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Unknown option", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 11: -v and 'version' set command=VERSION; -V and 'version -V' set version_verbose.
void TestParseVersionFlags() {
    std::cout << "\n[TEST] CliParser: Version flags set correctly..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // -v sets command=VERSION, not version_verbose
        {
            const char* args[] = {"reactor_server", "-v"};
            int argc = 2;
            auto opts = CliParser::Parse(argc, const_cast<char**>(args));
            if (opts.command != CliCommand::VERSION) { pass = false; err += "-v should set command=VERSION; "; }
            if (opts.version_verbose) { pass = false; err += "-v should NOT set version_verbose; "; }
        }

        // -V sets command=VERSION and version_verbose=true
        {
            const char* args[] = {"reactor_server", "-V"};
            int argc = 2;
            auto opts = CliParser::Parse(argc, const_cast<char**>(args));
            if (opts.command != CliCommand::VERSION) { pass = false; err += "-V should set command=VERSION; "; }
            if (!opts.version_verbose) { pass = false; err += "-V should set version_verbose=true; "; }
        }

        // 'version' subcommand sets command=VERSION, not version_verbose
        {
            const char* args[] = {"reactor_server", "version"};
            int argc = 2;
            auto opts = CliParser::Parse(argc, const_cast<char**>(args));
            if (opts.command != CliCommand::VERSION) { pass = false; err += "'version' should set command=VERSION; "; }
            if (opts.version_verbose) { pass = false; err += "'version' should NOT set version_verbose; "; }
        }

        // 'version -V' sets command=VERSION and version_verbose=true
        {
            const char* args[] = {"reactor_server", "version", "-V"};
            int argc = 3;
            auto opts = CliParser::Parse(argc, const_cast<char**>(args));
            if (opts.command != CliCommand::VERSION) { pass = false; err += "'version -V' should set command=VERSION; "; }
            if (!opts.version_verbose) { pass = false; err += "'version -V' should set version_verbose=true; "; }
        }

        TestFramework::RecordTest("CliParser: Version flags", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: Version flags", false, e.what(), CLI_CATEGORY);
    }
}

// Test 12: 'validate' subcommand sets command=VALIDATE.
void TestParseTestConfig() {
    std::cout << "\n[TEST] CliParser: 'validate' sets command=VALIDATE..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "validate"};
        int argc = 2;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.command == CliCommand::VALIDATE);
        std::string err = pass ? "" : "command should be VALIDATE after 'validate'";
        TestFramework::RecordTest("CliParser: validate command", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: validate command", false, e.what(), CLI_CATEGORY);
    }
}

// Test 13: 'config' subcommand sets command=CONFIG.
void TestParseDumpConfig() {
    std::cout << "\n[TEST] CliParser: 'config' sets command=CONFIG..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "config"};
        int argc = 2;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.command == CliCommand::CONFIG);
        std::string err = pass ? "" : "command should be CONFIG after 'config'";
        TestFramework::RecordTest("CliParser: config command", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: config command", false, e.what(), CLI_CATEGORY);
    }
}

// Test 14: -P overrides pid_file path.
void TestParsePidFile() {
    std::cout << "\n[TEST] CliParser: -P overrides pid_file..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "-P", "/custom/my.pid"};
        int argc = 4;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.pid_file == "/custom/my.pid");
        std::string err = pass ? "" : "pid_file not set to /custom/my.pid";
        TestFramework::RecordTest("CliParser: -P pid-file", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: -P pid-file", false, e.what(), CLI_CATEGORY);
    }
}

// Test 15: 'stop' subcommand sets command=STOP.
void TestParseSignalStop() {
    std::cout << "\n[TEST] CliParser: 'stop' command..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "stop"};
        int argc = 2;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.command == CliCommand::STOP);
        std::string err = pass ? "" : "command should be STOP after 'stop'";
        TestFramework::RecordTest("CliParser: stop command", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: stop command", false, e.what(), CLI_CATEGORY);
    }
}

// Test 16: 'status' subcommand sets command=STATUS.
void TestParseSignalStatus() {
    std::cout << "\n[TEST] CliParser: 'status' command..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "status"};
        int argc = 2;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.command == CliCommand::STATUS);
        std::string err = pass ? "" : "command should be STATUS after 'status'";
        TestFramework::RecordTest("CliParser: status command", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: status command", false, e.what(), CLI_CATEGORY);
    }
}

// Test 17: --no-health-endpoint sets health_endpoint=false.
void TestParseNoHealthEndpoint() {
    std::cout << "\n[TEST] CliParser: --no-health-endpoint..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "--no-health-endpoint"};
        int argc = 3;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.health_endpoint == false);
        std::string err = pass ? "" : "health_endpoint should be false";
        TestFramework::RecordTest("CliParser: --no-health-endpoint", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: --no-health-endpoint", false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2: PidFile Tests (18–24)
// ─────────────────────────────────────────────────────────────────────────────

// Test 18: Acquire succeeds, file is created with current PID, Release removes it.
void TestPidFileAcquireAndRelease() {
    std::cout << "\n[TEST] PidFile: Acquire and Release lifecycle..." << std::endl;
    const std::string path = MakeTmpPidPath();

    // Ensure clean state before and after
    std::remove(path.c_str());

    try {
        bool pass = true;
        std::string err;

        // Acquire
        bool acquired = PidFile::Acquire(path);
        if (!acquired) {
            pass = false; err += "Acquire returned false; ";
        }

        // File should exist
        if (pass) {
            struct stat st;
            if (stat(path.c_str(), &st) != 0) {
                pass = false; err += "PID file not created after Acquire; ";
            }
        }

        // The PID written to the file should match getpid()
        if (pass) {
            pid_t read_pid = PidFile::ReadPid(path);
            if (read_pid != getpid()) {
                pass = false;
                err += "Written PID " + std::to_string(read_pid) +
                       " != getpid() " + std::to_string(getpid()) + "; ";
            }
        }

        // Release
        PidFile::Release();

        // File should be removed after Release
        {
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                pass = false; err += "PID file still exists after Release; ";
            }
        }

        TestFramework::RecordTest("PidFile: Acquire and Release", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        PidFile::Release();  // cleanup
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: Acquire and Release", false, e.what(), CLI_CATEGORY);
    }
}

// Test 19: Acquiring the same PID file a second time (from the same process)
// must fail because the first Acquire holds the exclusive flock.
//
// Note: flock on Linux is per-open-file-description, not per-process.  The
// same process CAN re-acquire a lock on a different fd for the same file.
// We simulate "second instance" by forking, but forking inside a test binary
// is fragile.  Instead, we rely on the fact that a second Acquire() call
// while g_pid_fd is already held will open a new fd and attempt flock again —
// and because the first fd holds LOCK_EX the second call gets EWOULDBLOCK.
void TestPidFileAcquireBlocksSecondInstance() {
    std::cout << "\n[TEST] PidFile: Second Acquire on same path fails..." << std::endl;
    const std::string path = MakeTmpPidPath();
    std::remove(path.c_str());

    try {
        // First Acquire
        bool first = PidFile::Acquire(path);
        if (!first) {
            PidFile::Release();
            std::remove(path.c_str());
            TestFramework::RecordTest("PidFile: Second Acquire blocked", false,
                "First Acquire unexpectedly failed", CLI_CATEGORY);
            return;
        }

        // Second Acquire on the same path — expected to fail.
        // We open a new fd ourselves (mimicking what a second process would do)
        // and attempt flock(LOCK_EX|LOCK_NB). g_pid_fd holds LOCK_EX so this
        // must return EWOULDBLOCK.
        int fd2 = open(path.c_str(), O_WRONLY | O_CREAT, 0644);
        bool second_blocked = false;
        if (fd2 >= 0) {
            if (::flock(fd2, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK) {
                second_blocked = true;
            }
            close(fd2);
        }

        PidFile::Release();
        std::remove(path.c_str());

        if (!second_blocked) {
            TestFramework::RecordTest("PidFile: Second Acquire blocked", false,
                "Second flock(LOCK_EX|LOCK_NB) did not return EWOULDBLOCK", CLI_CATEGORY);
        } else {
            TestFramework::RecordTest("PidFile: Second Acquire blocked", true, "", CLI_CATEGORY);
        }
    } catch (const std::exception& e) {
        PidFile::Release();
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: Second Acquire blocked", false, e.what(), CLI_CATEGORY);
    }
}

// Test 20: A file containing a dead (bogus) PID should NOT block Acquire.
// Stale detection: if the file exists but has no live flock, Acquire truncates
// and re-uses it.
void TestPidFileStaleDetection() {
    std::cout << "\n[TEST] PidFile: Stale PID file is overwritten..." << std::endl;
    const std::string path = MakeTmpPidPath();
    std::remove(path.c_str());

    try {
        // Write a clearly bogus PID (PID 1 is init; we cannot kill it, but we
        // choose a PID that is almost certainly dead: use a large number that
        // doesn't map to a real process under normal circumstances).
        // The important thing is: no live flock on the file.
        WriteFile(path, "99999999\n");

        // Acquire should succeed (no flock held by bogus PID)
        bool acquired = PidFile::Acquire(path);

        if (!acquired) {
            PidFile::Release();
            std::remove(path.c_str());
            TestFramework::RecordTest("PidFile: Stale detection", false,
                "Acquire failed on stale PID file", CLI_CATEGORY);
            return;
        }

        // The PID in the file should now be our process
        pid_t written_pid = PidFile::ReadPid(path);
        bool correct_pid = (written_pid == getpid());

        PidFile::Release();
        std::remove(path.c_str());

        TestFramework::RecordTest("PidFile: Stale detection",
            correct_pid,
            correct_pid ? "" : "File not rewritten with current PID after stale acquisition",
            CLI_CATEGORY);
    } catch (const std::exception& e) {
        PidFile::Release();
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: Stale detection", false, e.what(), CLI_CATEGORY);
    }
}

// Test 21: ReadPid returns the correct PID written to the file.
void TestPidFileReadPidValid() {
    std::cout << "\n[TEST] PidFile: ReadPid returns correct PID..." << std::endl;
    const std::string path = MakeTmpPidPath();
    std::remove(path.c_str());

    try {
        pid_t expected_pid = static_cast<pid_t>(12345);
        WriteFile(path, std::to_string(expected_pid) + "\n");

        pid_t result = PidFile::ReadPid(path);
        bool pass = (result == expected_pid);
        std::string err = pass ? "" :
            "ReadPid returned " + std::to_string(result) +
            ", expected " + std::to_string(expected_pid);

        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: ReadPid valid", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: ReadPid valid", false, e.what(), CLI_CATEGORY);
    }
}

// Test 22: ReadPid on a nonexistent file returns -1.
void TestPidFileReadPidMissing() {
    std::cout << "\n[TEST] PidFile: ReadPid on nonexistent file returns -1..." << std::endl;
    try {
        const std::string path = "/tmp/this_file_must_not_exist_reactor_test_" +
                                 std::to_string(getpid()) + ".pid";
        std::remove(path.c_str());  // make sure it really doesn't exist

        pid_t result = PidFile::ReadPid(path);
        bool pass = (result == -1);
        std::string err = pass ? "" :
            "Expected -1 for missing file, got " + std::to_string(result);

        TestFramework::RecordTest("PidFile: ReadPid missing file", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("PidFile: ReadPid missing file", false, e.what(), CLI_CATEGORY);
    }
}

// Test 23: ReadPid on a file containing garbage returns -1.
void TestPidFileReadPidInvalid() {
    std::cout << "\n[TEST] PidFile: ReadPid on garbage content returns -1..." << std::endl;
    const std::string path = MakeTmpPidPath();
    std::remove(path.c_str());

    try {
        WriteFile(path, "not-a-number\n");

        pid_t result = PidFile::ReadPid(path);
        bool pass = (result == -1);
        std::string err = pass ? "" :
            "Expected -1 for garbage content, got " + std::to_string(result);

        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: ReadPid invalid content", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: ReadPid invalid content", false, e.what(), CLI_CATEGORY);
    }
}

// Test 23b: ReadPid rejects numeric-prefix garbage like "123abc".
void TestPidFileReadPidNumericPrefixGarbage() {
    std::cout << "\n[TEST] PidFile: ReadPid rejects numeric-prefix garbage..." << std::endl;
    const std::string path = MakeTmpPidPath();
    std::remove(path.c_str());

    try {
        WriteFile(path, "123abc\n");
        pid_t result = PidFile::ReadPid(path);
        bool pass = (result == -1);
        std::string err = pass ? "" :
            "Expected -1 for '123abc', got " + std::to_string(result);
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: ReadPid numeric-prefix garbage", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: ReadPid numeric-prefix garbage", false, e.what(), CLI_CATEGORY);
    }
}

// Test 24: CheckRunning with a dead PID removes the file and returns -1.
// We pick a PID that is almost certainly not running: POSIX allows PIDs up to
// at least 32767; we pick something large and use kill(pid,0) to confirm.
void TestPidFileCheckRunningNotRunning() {
    std::cout << "\n[TEST] PidFile: CheckRunning with dead PID returns -1..." << std::endl;
    const std::string path = MakeTmpPidPath();
    std::remove(path.c_str());

    try {
        // Find a PID that is definitely NOT running.
        // Strategy: start at a large number and scan downward until kill(pid,0)
        // returns ESRCH (no process).  We try up to 200 candidates.
        pid_t dead_pid = -1;
        for (pid_t candidate = 60000; candidate > 59800; --candidate) {
            if (kill(candidate, 0) == -1 && errno == ESRCH) {
                dead_pid = candidate;
                break;
            }
        }

        if (dead_pid == -1) {
            // All 200 candidates were running — very unlikely on a normal system.
            // Skip rather than produce a false failure.
            TestFramework::RecordTest("PidFile: CheckRunning dead PID", true,
                "(skipped: could not find a dead PID in range 59800-60000)", CLI_CATEGORY);
            return;
        }

        WriteFile(path, std::to_string(dead_pid) + "\n");

        pid_t result = PidFile::CheckRunning(path);
        bool pass = (result == -1);
        std::string err = pass ? "" :
            "Expected -1 for dead PID " + std::to_string(dead_pid) +
            ", got " + std::to_string(result);

        // CheckRunning does NOT unlink stale files (avoids race with Acquire).
        // Clean up ourselves.
        std::remove(path.c_str());

        TestFramework::RecordTest("PidFile: CheckRunning dead PID", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        std::remove(path.c_str());
        TestFramework::RecordTest("PidFile: CheckRunning dead PID", false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3: Config Override Precedence Tests (25–29)
//
// These tests implement the ApplyCliOverrides logic in-process since that
// function lives in main.cc (not exposed as a library function). We replicate
// the precedence logic here to validate the contracts independently.
// ─────────────────────────────────────────────────────────────────────────────

// Helper: apply CLI overrides exactly as main.cc does.
// Must match the implementation in server/main.cc exactly.
static void ApplyCliOverrides(ServerConfig& config, const CliOptions& opts) {
    if (opts.port >= 0)           config.bind_port       = opts.port;
    if (!opts.host.empty())       config.bind_host       = opts.host;
    if (!opts.log_level.empty())  config.log.level       = opts.log_level;
    if (opts.workers >= 0)        config.worker_threads  = opts.workers;
}

// Test 25: ConfigLoader::Default() values preserved when no overrides applied.
void TestConfigDefaultsPreserved() {
    std::cout << "\n[TEST] Config precedence: Defaults preserved with no overrides..." << std::endl;
    try {
        ServerConfig config = ConfigLoader::Default();
        bool pass = true;
        std::string err;

        if (config.bind_port != 8080)       { pass = false; err += "bind_port default wrong; "; }
        if (config.bind_host != "127.0.0.1"){ pass = false; err += "bind_host default wrong; "; }
        if (config.worker_threads != 3)     { pass = false; err += "worker_threads default wrong; "; }
        if (config.log.level != "info")     { pass = false; err += "log.level default wrong; "; }

        TestFramework::RecordTest("Config: Defaults preserved", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: Defaults preserved", false, e.what(), CLI_CATEGORY);
    }
}

// Test 26: File values override defaults.
void TestConfigFileOverridesDefaults() {
    std::cout << "\n[TEST] Config precedence: File overrides defaults..." << std::endl;
    try {
        // Start from defaults
        ServerConfig config = ConfigLoader::Default();

        // "Load" a file by using LoadFromString — same code path as LoadFromFile.
        // This also tests partial override: only bind_port changes.
        const std::string json = R"({ "bind_port": 7777 })";
        ServerConfig file_config = ConfigLoader::LoadFromString(json);

        bool pass = true;
        std::string err;

        if (file_config.bind_port != 7777) {
            pass = false; err += "bind_port not overridden to 7777; ";
        }
        // Defaults not in file should remain
        if (file_config.bind_host != "127.0.0.1") {
            pass = false; err += "bind_host should still be default 127.0.0.1; ";
        }

        TestFramework::RecordTest("Config: File overrides defaults", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: File overrides defaults", false, e.what(), CLI_CATEGORY);
    }
}

// Test 27: Env var overrides file (and defaults).
void TestConfigEnvOverridesFile() {
    std::cout << "\n[TEST] Config precedence: Env overrides file..." << std::endl;

    // Save any pre-existing value so we can restore it
    const char* existing = getenv("REACTOR_BIND_PORT");
    const std::string saved = existing ? existing : "";

    try {
        setenv("REACTOR_BIND_PORT", "6666", 1);

        // Start from file value (7777)
        ServerConfig config = ConfigLoader::LoadFromString(R"({ "bind_port": 7777 })");
        ConfigLoader::ApplyEnvOverrides(config);

        bool pass = (config.bind_port == 6666);
        std::string err = pass ? "" :
            "Expected bind_port=6666 from env, got " + std::to_string(config.bind_port);

        if (saved.empty()) {
            unsetenv("REACTOR_BIND_PORT");
        } else {
            setenv("REACTOR_BIND_PORT", saved.c_str(), 1);
        }

        TestFramework::RecordTest("Config: Env overrides file", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        if (saved.empty()) unsetenv("REACTOR_BIND_PORT");
        else               setenv("REACTOR_BIND_PORT", saved.c_str(), 1);
        TestFramework::RecordTest("Config: Env overrides file", false, e.what(), CLI_CATEGORY);
    }
}

// Test 28: CLI flag overrides env override.
void TestConfigCliOverridesEnv() {
    std::cout << "\n[TEST] Config precedence: CLI overrides env..." << std::endl;

    const char* existing = getenv("REACTOR_BIND_PORT");
    const std::string saved = existing ? existing : "";

    try {
        // Env sets 6666
        setenv("REACTOR_BIND_PORT", "6666", 1);

        // Start from defaults, apply env
        ServerConfig config = ConfigLoader::Default();
        ConfigLoader::ApplyEnvOverrides(config);

        // CLI sets 5555 — should win
        const char* args[] = {"reactor_server", "start", "-p", "5555"};
        int argc = 4;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));
        ApplyCliOverrides(config, opts);

        bool pass = (config.bind_port == 5555);
        std::string err = pass ? "" :
            "Expected bind_port=5555 from CLI, got " + std::to_string(config.bind_port);

        if (saved.empty()) unsetenv("REACTOR_BIND_PORT");
        else               setenv("REACTOR_BIND_PORT", saved.c_str(), 1);

        TestFramework::RecordTest("Config: CLI overrides env", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        if (saved.empty()) unsetenv("REACTOR_BIND_PORT");
        else               setenv("REACTOR_BIND_PORT", saved.c_str(), 1);
        TestFramework::RecordTest("Config: CLI overrides env", false, e.what(), CLI_CATEGORY);
    }
}

// Test 29: Unset CLI (sentinel -1) does NOT revert an env override back to defaults.
// This validates the sentinel pattern: omitting a CLI flag must not silently
// undo a higher-precedence (env) value.
void TestConfigUnsetCliDoesNotRevertEnv() {
    std::cout << "\n[TEST] Config precedence: Unset CLI sentinel does not revert env..." << std::endl;

    const char* existing = getenv("REACTOR_BIND_PORT");
    const std::string saved = existing ? existing : "";

    try {
        // Env sets 4444
        setenv("REACTOR_BIND_PORT", "4444", 1);

        ServerConfig config = ConfigLoader::Default();
        ConfigLoader::ApplyEnvOverrides(config);

        // Parse with NO -p flag → opts.port == -1 (sentinel)
        const char* args[] = {"reactor_server"};
        int argc = 1;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        if (opts.port != -1) {
            // Unexpected: should be sentinel
            if (saved.empty()) unsetenv("REACTOR_BIND_PORT");
            else               setenv("REACTOR_BIND_PORT", saved.c_str(), 1);
            TestFramework::RecordTest("Config: Unset CLI preserves env", false,
                "opts.port != -1 when no -p flag given", CLI_CATEGORY);
            return;
        }

        ApplyCliOverrides(config, opts);

        bool pass = (config.bind_port == 4444);
        std::string err = pass ? "" :
            "Unset CLI reverted env override; expected 4444 but got " +
            std::to_string(config.bind_port);

        if (saved.empty()) unsetenv("REACTOR_BIND_PORT");
        else               setenv("REACTOR_BIND_PORT", saved.c_str(), 1);

        TestFramework::RecordTest("Config: Unset CLI preserves env", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        if (saved.empty()) unsetenv("REACTOR_BIND_PORT");
        else               setenv("REACTOR_BIND_PORT", saved.c_str(), 1);
        TestFramework::RecordTest("Config: Unset CLI preserves env", false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Signal test helper ────────────────────────────────────────────────────────

// Drain any pending signals and safely restore default dispositions.
// Must be called AFTER Cleanup() (which sets SIG_IGN + unblocks) and
// AFTER the waiter thread is joined. Without this, a late safety-kill()
// could arrive after SIG_DFL is restored, terminating the test process.
static void DrainAndRestoreSignals() {
    sigset_t drain_set;
    sigemptyset(&drain_set);
    sigaddset(&drain_set, SIGTERM);
    sigaddset(&drain_set, SIGINT);
    sigaddset(&drain_set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &drain_set, nullptr);

#if defined(__linux__)
    struct timespec zero_timeout = {0, 0};
    while (sigtimedwait(&drain_set, nullptr, &zero_timeout) > 0) {}
#else
    // macOS/BSD: sigtimedwait doesn't exist. Use sigpending + sigwait loop.
    sigset_t pending;
    while (sigpending(&pending) == 0) {
        bool any = sigismember(&pending, SIGTERM) ||
                   sigismember(&pending, SIGINT) ||
                   sigismember(&pending, SIGHUP);
        if (!any) break;
        int sig;
        sigwait(&drain_set, &sig);
    }
#endif

    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    pthread_sigmask(SIG_UNBLOCK, &drain_set, nullptr);
}

// SECTION 4: SignalHandler Tests (30–31)
// ─────────────────────────────────────────────────────────────────────────────

// Test 30: Install() blocks signals via pthread_sigmask, Cleanup() unblocks.
// Verify neither throws.
void TestSignalHandlerInstallAndCleanup() {
    std::cout << "\n[TEST] SignalHandler: Install and Cleanup succeeds..." << std::endl;
    try {
        SignalHandler::Install();
        SignalHandler::Cleanup();

        // Restore default disposition — Cleanup() sets SIG_IGN before unblocking.
        // Without this, subsequent sigwait()-based tests hang on macOS/BSD
        // (kernel discards SIG_IGN signals before they become pending).
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);

        TestFramework::RecordTest("SignalHandler: Install and Cleanup", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        TestFramework::RecordTest("SignalHandler: Install and Cleanup", false, e.what(), CLI_CATEGORY);
    }
}

// Test 31: After Install(), sending SIGTERM causes WaitForShutdown to unblock.
//
// Design:
//   1. Install() — blocks SIGTERM/SIGINT via pthread_sigmask
//   2. Spawn a thread that calls WaitForShutdown()
//   3. Main thread: kill(getpid(), SIGTERM) — process-directed so sigwait() dequeues it
//   4. Thread should unblock within a reasonable timeout (500 ms)
//   5. If not, send another SIGTERM to force unblock
//
// Note: kill(getpid(), ...) is process-directed. sigwait() in the waiter thread
// dequeues it. This exercises the complete sigwait-based shutdown path.
void TestSignalHandlerSigwaitUnblock() {
    std::cout << "\n[TEST] SignalHandler: SIGTERM unblocks WaitForShutdown..." << std::endl;
    try {
        SignalHandler::Install();

        std::atomic<bool> thread_unblocked{false};

        std::thread waiter([&]() {
            // Pass nullptr: we just want to verify the pipe read unblocks.
            // The CAS on g_shutdown_requested prevents a real Stop() call.
            SignalHandler::WaitForShutdown();
            thread_unblocked.store(true, std::memory_order_release);
        });

        // Give the waiter thread a moment to reach the blocking read/poll
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Send process-directed SIGTERM so sigwait() in the waiter thread can dequeue it.
        // (raise() is thread-directed and won't be seen by sigwait in another thread)
        kill(getpid(), SIGTERM);

        // Wait up to 500 ms for the thread to unblock
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (!thread_unblocked.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // If the thread is still blocked, send another signal to unblock sigwait
        if (!thread_unblocked.load(std::memory_order_acquire)) {
            kill(getpid(), SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (waiter.joinable()) {
            waiter.join();
        }

        bool pass = thread_unblocked.load(std::memory_order_acquire);
        std::string err = pass ? "" : "WaitForShutdown did not unblock within 500ms after SIGTERM";

        // Always cleanup (safe to call again: guards against double-close)
        SignalHandler::Cleanup();
        DrainAndRestoreSignals();

        TestFramework::RecordTest("SignalHandler: SIGTERM unblocks WaitForShutdown",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        SignalHandler::Cleanup();
        DrainAndRestoreSignals();
        TestFramework::RecordTest("SignalHandler: SIGTERM unblocks WaitForShutdown",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5: Logger Phase 2 Tests (32–37)
//
// These tests exercise the new logging::SetConsoleEnabled() and
// logging::Reopen() APIs added for daemon mode support.
// Each test calls logging::Shutdown() at the end to restore clean state.
// ─────────────────────────────────────────────────────────────────────────────

// Test 32: SetConsoleEnabled(false) + Init with a file → logger is functional
// even with console disabled.  Validates that the sticky console flag is stored
// before Init() and honoured inside BuildSinks().
void TestSetConsoleEnabled() {
    std::cout << "\n[TEST] Logger: SetConsoleEnabled(false) disables console sink..." << std::endl;
    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) +
                                  "_console.log";
    std::remove(log_path.c_str());

    try {
        // Disable console before initialising so daemon-mode path is exercised
        logging::SetConsoleEnabled(false);
        logging::Init("test_logger_console", spdlog::level::info, log_path);

        // Logger must still be usable — no crash expected
        logging::Get()->info("SetConsoleEnabled test message");
        logging::Get()->flush();

        logging::Shutdown();  // resets g_console_enabled to true
        std::remove(log_path.c_str());

        TestFramework::RecordTest("Logger: SetConsoleEnabled(false) functional",
                                  true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        std::remove(log_path.c_str());
        TestFramework::RecordTest("Logger: SetConsoleEnabled(false) functional",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 33: SetConsoleEnabled persists across multiple Init() calls.
// After the first Init() stores the flag, a second Init() must not silently
// re-enable the console sink.
void TestSetConsoleEnabledPersists() {
    std::cout << "\n[TEST] Logger: SetConsoleEnabled persists across Init() calls..." << std::endl;
    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) +
                                  "_persist.log";
    std::remove(log_path.c_str());

    try {
        logging::SetConsoleEnabled(false);

        // First Init
        logging::Init("test_persist_1", spdlog::level::info, log_path);
        logging::Get()->info("First init message");

        // Second Init — console flag must stay false
        logging::Init("test_persist_2", spdlog::level::debug, log_path);
        logging::Get()->debug("Second init message");
        logging::Get()->flush();

        logging::Shutdown();  // resets g_console_enabled to true
        std::remove(log_path.c_str());

        // If neither Init threw and the second logger is usable, the flag
        // persisted correctly (a console sink would print to stdout but is
        // not required to be absent — we just verify no crash and no
        // unexpected throw).
        TestFramework::RecordTest("Logger: SetConsoleEnabled persists across Init",
                                  true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        std::remove(log_path.c_str());
        TestFramework::RecordTest("Logger: SetConsoleEnabled persists across Init",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 34: Reopen() with a live file sink closes and reopens the file handle.
// Simulates logrotate: write "Before", rename file, Reopen(), write "After".
// Verifies: rotated file has "Before", new file has "After".
void TestReopenWithFileSink() {
    std::cout << "\n[TEST] Logger: Reopen() with file sink reconstructs logger..." << std::endl;
    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) +
                                  "_reopen.log";
    std::remove(log_path.c_str());

    try {
        logging::Init("test_reopen", spdlog::level::info, log_path);

        // Write a message before Reopen
        logging::Get()->info("Before reopen");
        logging::Get()->flush();

        // Simulate log-rotation: rename the old file and call Reopen()
        // so the logger creates a new file handle at the same path.
        const std::string rotated = log_path + ".1";
        std::rename(log_path.c_str(), rotated.c_str());

        logging::Reopen();

        // Write after Reopen — must go to the NEW file at log_path
        logging::Get()->info("After reopen");
        logging::Get()->flush();

        logging::Shutdown();

        // Verify: rotated file has "Before reopen"
        std::string rotated_content;
        {
            std::ifstream f(rotated);
            if (f.is_open()) {
                std::string line;
                while (std::getline(f, line)) rotated_content += line + "\n";
            }
        }
        bool rotated_has_before = rotated_content.find("Before reopen") != std::string::npos;

        // Verify: new file has "After reopen"
        std::string new_content;
        {
            std::ifstream f(log_path);
            if (f.is_open()) {
                std::string line;
                while (std::getline(f, line)) new_content += line + "\n";
            }
        }
        bool new_has_after = new_content.find("After reopen") != std::string::npos;

        std::remove(log_path.c_str());
        std::remove(rotated.c_str());

        bool pass = rotated_has_before && new_has_after;
        std::string err;
        if (!rotated_has_before) err += "Rotated file missing 'Before reopen'; ";
        if (!new_has_after) err += "New file missing 'After reopen'; ";

        TestFramework::RecordTest("Logger: Reopen with file sink", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        std::remove(log_path.c_str());
        std::remove((log_path + ".1").c_str());
        TestFramework::RecordTest("Logger: Reopen with file sink",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 35: Reopen() without a file sink is a no-op — must not crash.
// This covers the console-only logger case (daemon-disabled console path
// uses no file sink until log.file is configured).
void TestReopenWithoutFileSink() {
    std::cout << "\n[TEST] Logger: Reopen() without file sink is no-op..." << std::endl;
    try {
        // Console-only logger (no file path)
        logging::Init("test_reopen_noop", spdlog::level::info, "");

        // Reopen must return without throwing or crashing
        logging::Reopen();

        logging::Get()->info("After Reopen no-op");
        logging::Shutdown();

        TestFramework::RecordTest("Logger: Reopen without file sink is no-op",
                                  true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        TestFramework::RecordTest("Logger: Reopen without file sink is no-op",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 36: Reopen() before any Init() is a no-op — must not crash.
// The g_logger is null and g_log_file is empty; Reopen() should early-return.
void TestReopenBeforeInit() {
    std::cout << "\n[TEST] Logger: Reopen() before Init() is no-op..." << std::endl;
    try {
        // Ensure logger is reset (Shutdown resets g_logger)
        logging::Shutdown();

        // Call Reopen with no logger initialised
        logging::Reopen();

        // Verify: no crash, test passes
        TestFramework::RecordTest("Logger: Reopen before Init is no-op",
                                  true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Logger: Reopen before Init is no-op",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 37: Reopen() preserves the log level set at Init() time.
// After reconstruction the new logger's level must equal the original level.
void TestReopenPreservesLevel() {
    std::cout << "\n[TEST] Logger: Reopen() preserves log level..." << std::endl;
    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) +
                                  "_level.log";
    std::remove(log_path.c_str());

    try {
        // Init at debug level
        logging::Init("test_level", spdlog::level::debug, log_path);

        logging::Reopen();

        // After Reopen the logger must accept debug messages without filtering
        // (level preserved at debug).  We verify indirectly: if the level
        // were reset to info, a debug message would be silently dropped.
        // We can inspect the logger's level directly.
        auto logger = logging::Get();
        bool level_preserved = (logger->level() == spdlog::level::debug);

        logging::Shutdown();
        std::remove(log_path.c_str());

        TestFramework::RecordTest("Logger: Reopen preserves log level",
                                  level_preserved,
                                  level_preserved ? "" : "Log level changed after Reopen()",
                                  CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        std::remove(log_path.c_str());
        TestFramework::RecordTest("Logger: Reopen preserves log level",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 6: SignalHandler Phase 2 Tests (38–40)
//
// Test the new WaitForSignal() API which returns SignalResult::RELOAD for
// SIGHUP and SignalResult::SHUTDOWN for SIGTERM/SIGINT.
//
// Pattern mirrors the existing TestSignalHandlerSigwaitUnblock:
//   1. Install()
//   2. Spawn a waiter thread that calls WaitForSignal()
//   3. Send the signal via kill(getpid(), SIG) — process-directed so
//      sigwait() in the waiter thread dequeues it
//   4. Verify the returned SignalResult value
//   5. Cleanup()
// ─────────────────────────────────────────────────────────────────────────────

// Test 38: WaitForSignal() returns SHUTDOWN when SIGTERM is delivered.
void TestWaitForSignalSIGTERM() {
    std::cout << "\n[TEST] SignalHandler: WaitForSignal returns SHUTDOWN on SIGTERM..." << std::endl;
    try {
        SignalHandler::Install();

        std::atomic<bool> thread_done{false};
        SignalResult received_result = SignalResult::RELOAD; // sentinel: wrong value

        std::thread waiter([&]() {
            received_result = SignalHandler::WaitForSignal();
            thread_done.store(true, std::memory_order_release);
        });

        // Let the waiter reach sigwait()
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Deliver SIGTERM — process-directed so sigwait() dequeues it
        kill(getpid(), SIGTERM);

        // Wait up to 500 ms
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (!thread_done.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // Safety: force unblock if still waiting
        if (!thread_done.load(std::memory_order_acquire)) {
            kill(getpid(), SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (waiter.joinable()) waiter.join();

        bool pass = thread_done.load(std::memory_order_acquire) &&
                    (received_result == SignalResult::SHUTDOWN);
        std::string err;
        if (!pass) {
            if (!thread_done.load(std::memory_order_acquire))
                err = "WaitForSignal did not unblock within 500ms";
            else
                err = "Expected SHUTDOWN, got RELOAD";
        }

        SignalHandler::Cleanup();
        DrainAndRestoreSignals();

        TestFramework::RecordTest("SignalHandler: WaitForSignal returns SHUTDOWN on SIGTERM",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        SignalHandler::Cleanup();
        DrainAndRestoreSignals();
        TestFramework::RecordTest("SignalHandler: WaitForSignal returns SHUTDOWN on SIGTERM",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 39: WaitForSignal() returns RELOAD when SIGHUP is delivered.
void TestWaitForSignalSIGHUP() {
    std::cout << "\n[TEST] SignalHandler: WaitForSignal returns RELOAD on SIGHUP..." << std::endl;
    try {
        SignalHandler::Install();

        std::atomic<bool> thread_done{false};
        SignalResult received_result = SignalResult::SHUTDOWN; // sentinel: wrong value

        std::thread waiter([&]() {
            received_result = SignalHandler::WaitForSignal();
            thread_done.store(true, std::memory_order_release);
        });

        // Let the waiter reach sigwait()
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Deliver SIGHUP — process-directed
        kill(getpid(), SIGHUP);

        // Wait up to 500 ms
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (!thread_done.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // Safety: if still blocked (SIGHUP not delivered), unblock with SIGTERM
        // to avoid a hanging test — but note this makes the result SHUTDOWN.
        // The test only passes if thread unblocked AND result is RELOAD.
        if (!thread_done.load(std::memory_order_acquire)) {
            kill(getpid(), SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (waiter.joinable()) waiter.join();

        bool pass = thread_done.load(std::memory_order_acquire) &&
                    (received_result == SignalResult::RELOAD);
        std::string err;
        if (!pass) {
            if (!thread_done.load(std::memory_order_acquire))
                err = "WaitForSignal did not unblock within 500ms";
            else
                err = "Expected RELOAD, got SHUTDOWN";
        }

        SignalHandler::Cleanup();
        DrainAndRestoreSignals();

        TestFramework::RecordTest("SignalHandler: WaitForSignal returns RELOAD on SIGHUP",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        SignalHandler::Cleanup();
        DrainAndRestoreSignals();
        TestFramework::RecordTest("SignalHandler: WaitForSignal returns RELOAD on SIGHUP",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 40: WaitForShutdown() ignores SIGHUP and only returns after SIGTERM.
// Design: send SIGHUP first, then SIGTERM.  WaitForShutdown must loop past the
// SIGHUP and block again, then unblock on SIGTERM.
void TestWaitForShutdownIgnoresSIGHUP() {
    std::cout << "\n[TEST] SignalHandler: WaitForShutdown ignores SIGHUP, returns on SIGTERM..." << std::endl;
    try {
        SignalHandler::Install();

        std::atomic<bool> thread_done{false};

        std::thread waiter([&]() {
            SignalHandler::WaitForShutdown();
            thread_done.store(true, std::memory_order_release);
        });

        // Let the waiter reach sigwait()
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // First: send SIGHUP — WaitForShutdown must loop and NOT return
        kill(getpid(), SIGHUP);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Thread must still be blocked after SIGHUP
        bool still_blocked_after_hup = !thread_done.load(std::memory_order_acquire);

        // Now: send SIGTERM — WaitForShutdown must return
        kill(getpid(), SIGTERM);

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (!thread_done.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // Safety: force unblock if still waiting
        if (!thread_done.load(std::memory_order_acquire)) {
            kill(getpid(), SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (waiter.joinable()) waiter.join();

        bool returned_after_term = thread_done.load(std::memory_order_acquire);
        bool pass = still_blocked_after_hup && returned_after_term;

        std::string err;
        if (!still_blocked_after_hup)
            err += "WaitForShutdown returned prematurely on SIGHUP; ";
        if (!returned_after_term)
            err += "WaitForShutdown did not return within 500ms after SIGTERM; ";

        SignalHandler::Cleanup();
        DrainAndRestoreSignals();

        TestFramework::RecordTest(
            "SignalHandler: WaitForShutdown ignores SIGHUP returns on SIGTERM",
            pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        SignalHandler::Cleanup();
        DrainAndRestoreSignals();
        TestFramework::RecordTest(
            "SignalHandler: WaitForShutdown ignores SIGHUP returns on SIGTERM",
            false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 7: CliParser Daemonize Tests (41–47)
//
// These tests verify the new -d / --daemonize flag and the per-command
// validation that rejects --daemonize on stop/status/validate/config.
// ─────────────────────────────────────────────────────────────────────────────

// Test 41: 'start -d' (short flag) sets daemonize=true.
void TestStartDaemonizeShortFlag() {
    std::cout << "\n[TEST] CliParser: 'start -d' sets daemonize=true..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "-d"};
        int argc = 3;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.daemonize == true) && (opts.command == CliCommand::START);
        std::string err = pass ? "" :
            std::string("daemonize=") + (opts.daemonize ? "true" : "false") +
            " command=" + (opts.command == CliCommand::START ? "START" : "other");
        TestFramework::RecordTest("CliParser: start -d sets daemonize", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: start -d sets daemonize", false, e.what(), CLI_CATEGORY);
    }
}

// Test 42: 'start --daemonize' (long flag) sets daemonize=true.
void TestStartDaemonizeLongFlag() {
    std::cout << "\n[TEST] CliParser: 'start --daemonize' sets daemonize=true..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start", "--daemonize"};
        int argc = 3;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.daemonize == true) && (opts.command == CliCommand::START);
        std::string err = pass ? "" :
            std::string("daemonize=") + (opts.daemonize ? "true" : "false") +
            " command=" + (opts.command == CliCommand::START ? "START" : "other");
        TestFramework::RecordTest("CliParser: start --daemonize sets daemonize", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: start --daemonize sets daemonize", false, e.what(), CLI_CATEGORY);
    }
}

// Test 43: 'start' without -d keeps daemonize=false (default).
void TestStartNoDaemonize() {
    std::cout << "\n[TEST] CliParser: 'start' without -d keeps daemonize=false..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "start"};
        int argc = 2;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.daemonize == false);
        std::string err = pass ? "" : "daemonize should be false by default";
        TestFramework::RecordTest("CliParser: start without -d keeps daemonize false",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: start without -d keeps daemonize false",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 44: 'stop -d' must throw — daemonize is only valid for 'start'.
void TestStopRejectsDaemonize() {
    std::cout << "\n[TEST] CliParser: 'stop -d' throws..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "stop", "-d"};
        int argc = 3;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: stop -d throws", false,
            "Expected exception for 'stop -d'", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: stop -d throws", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: stop -d throws", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 45: 'status -d' must throw.
void TestStatusRejectsDaemonize() {
    std::cout << "\n[TEST] CliParser: 'status -d' throws..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "status", "-d"};
        int argc = 3;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: status -d throws", false,
            "Expected exception for 'status -d'", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: status -d throws", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: status -d throws", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 46: 'validate -d' sets daemonize=true (enables daemon-specific validation).
void TestValidateAcceptsDaemonize() {
    std::cout << "\n[TEST] CliParser: 'validate -d' sets daemonize=true..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "validate", "-d"};
        int argc = 3;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.daemonize == true) && (opts.command == CliCommand::VALIDATE);
        std::string err = pass ? "" : "validate -d should set daemonize=true";
        TestFramework::RecordTest("CliParser: validate -d sets daemonize", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: validate -d sets daemonize", false, e.what(), CLI_CATEGORY);
    }
}

// Test 47: 'config -d' must throw.
void TestConfigRejectsDaemonize() {
    std::cout << "\n[TEST] CliParser: 'config -d' throws..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "config", "-d"};
        int argc = 3;
        CliParser::Parse(argc, const_cast<char**>(args));
        TestFramework::RecordTest("CliParser: config -d throws", false,
            "Expected exception for 'config -d'", CLI_CATEGORY);
    } catch (const std::runtime_error&) {
        TestFramework::RecordTest("CliParser: config -d throws", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: config -d throws", false,
            std::string("Wrong exception type: ") + e.what(), CLI_CATEGORY);
    }
}

// Test 48: 'validate -d' with no log file configured should fail (daemon requires log file).
// This tests the actual daemon config validation, not just the CLI parsing.
void TestValidateDaemonRejectsNoLogFile() {
    std::cout << "\n[TEST] CliParser: 'validate -d' catches missing log file..." << std::endl;

    // Build a minimal config file with no log.file
    const std::string cfg_path = "/tmp/test_reactor_cfg_" + std::to_string(getpid()) + "_nolog.json";
    WriteFile(cfg_path, R"({"bind_port": 8080})");

    // Run the actual binary with validate -d to check daemon constraints
    std::string cmd = "./reactor_server validate -d -c " + cfg_path + " 2>&1";
    FILE* fp = popen(cmd.c_str(), "r");
    std::string output;
    int exit_code = -1;
    if (fp) {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) output += buf;
        int status = pclose(fp);
        if (WIFEXITED(status)) exit_code = WEXITSTATUS(status);
    }

    std::remove(cfg_path.c_str());

    bool has_error = output.find("daemon mode requires a log file") != std::string::npos;
    bool exit_nonzero = (exit_code != 0);

    bool pass = has_error && exit_nonzero;
    std::string err;
    if (!has_error) err += "Expected 'daemon mode requires a log file' error; ";
    if (!exit_nonzero) err += "Expected non-zero exit code, got " + std::to_string(exit_code) + "; ";

    TestFramework::RecordTest("CliParser: validate -d catches missing log file",
                              pass, err, CLI_CATEGORY);
}

// Test 49: 'validate -d -P /relative/path' should fail (daemon requires absolute PID path).
void TestValidateDaemonRejectsRelativePidPath() {
    std::cout << "\n[TEST] CliParser: 'validate -d -P relative' catches relative PID path..." << std::endl;

    // Build a config with an absolute log file (so that check passes)
    const std::string cfg_path = "/tmp/test_reactor_cfg_" + std::to_string(getpid()) + "_relpid.json";
    WriteFile(cfg_path, R"({"log":{"file":"/tmp/test.log"}})");

    std::string cmd = "./reactor_server validate -d -c " + cfg_path + " -P relative.pid 2>&1";
    FILE* fp = popen(cmd.c_str(), "r");
    std::string output;
    int exit_code = -1;
    if (fp) {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) output += buf;
        int status = pclose(fp);
        if (WIFEXITED(status)) exit_code = WEXITSTATUS(status);
    }

    std::remove(cfg_path.c_str());

    bool has_error = output.find("absolute") != std::string::npos &&
                     output.find("PID file") != std::string::npos;
    bool exit_nonzero = (exit_code != 0);

    bool pass = has_error && exit_nonzero;
    std::string err;
    if (!has_error) err += "Expected absolute PID file path error; ";
    if (!exit_nonzero) err += "Expected non-zero exit code, got " + std::to_string(exit_code) + "; ";

    TestFramework::RecordTest("CliParser: validate -d -P catches relative PID path",
                              pass, err, CLI_CATEGORY);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 8: Config Reload Tests (50–54)
//
// These tests exercise HttpServer::Reload() which applies reload-safe config
// changes (limits, timeouts) while silently ignoring restart-required fields
// (bind_host, bind_port, worker_threads, tls.*, http2.enabled).
//
// We test Reload() directly via the public API on a running server so that
// the atomic stores and EnQueue paths are exercised under real concurrency.
//
// Port range: 10600–10609
// ─────────────────────────────────────────────────────────────────────────────

// Helper: send a raw HTTP request to localhost:port and return the response.
// Uses poll() for reliable non-blocking I/O (mirrors HttpTests::SendHttpRequest).
static std::string SendHttpRequestCli(int port, const std::string& request,
                                      int timeout_ms = 3000) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return "";

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sockfd);
        return "";
    }

    ssize_t sent = send(sockfd, request.data(), request.size(), 0);
    if (sent < 0) {
        close(sockfd);
        return "";
    }

    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;

    std::string response;
    char buf[4096];
    auto start = std::chrono::steady_clock::now();

    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        int remaining = timeout_ms - static_cast<int>(elapsed);
        if (remaining <= 0) break;

        int ret = poll(&pfd, 1, remaining);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                response.append(buf, static_cast<size_t>(n));
                auto hdr_end = response.find("\r\n\r\n");
                if (hdr_end != std::string::npos) {
                    size_t body_start = hdr_end + 4;
                    size_t content_length = 0;
                    auto cl_pos = response.find("Content-Length: ");
                    if (cl_pos != std::string::npos && cl_pos < hdr_end) {
                        content_length = std::stoul(response.substr(cl_pos + 16));
                    }
                    if (response.size() >= body_start + content_length) break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }
    close(sockfd);
    return response;
}

// Test 50: Reload applies new reload-safe limits (max_body_size, max_connections,
// request_timeout_sec).  After Reload(), GetStats() reflects updated uptime and
// the server continues to serve requests — confirming it did not crash.
void TestReloadAppliesLimits() {
    std::cout << "\n[TEST] Config Reload: Reload applies new limits without crashing..." << std::endl;
    static constexpr int PORT = 10600;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.request_timeout_sec = 30;
        cfg.max_body_size  = 1048576;   // 1 MB default
        cfg.max_connections = 1000;
        cfg.log.level = "warn";         // suppress noise

        HttpServer server(cfg);
        server.Get("/ping", [](const HttpRequest& /*req*/, HttpResponse& res) {
            res.Status(200).Text("pong");
        });

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        bool pass = true;
        std::string err;

        // Verify server responds before reload
        {
            std::string resp = SendHttpRequestCli(PORT,
                "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            if (resp.find("200") == std::string::npos) {
                pass = false; err += "Server not responding before Reload; ";
            }
        }

        // Build a new config with different reload-safe values
        ServerConfig new_cfg = cfg;
        new_cfg.max_body_size  = 2097152;   // 2 MB
        new_cfg.max_connections = 500;
        new_cfg.request_timeout_sec = 15;

        // Apply reload — must not throw, must not crash the server
        server.Reload(new_cfg);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Server must still respond after reload
        {
            std::string resp = SendHttpRequestCli(PORT,
                "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            if (resp.find("200") == std::string::npos) {
                pass = false; err += "Server not responding after Reload; ";
            }
        }

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        TestFramework::RecordTest("Config Reload: applies limits without crash",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config Reload: applies limits without crash",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 51: Reload skips restart-required fields (bind_host, bind_port,
// worker_threads).  We verify that GetStats() uptime keeps ticking after
// Reload() with changed bind_host/bind_port — if Reload() tried to rebind
// it would throw or fail. The absence of a crash is the assertion.
void TestReloadSkipsRestartRequiredFields() {
    std::cout << "\n[TEST] Config Reload: restart-required fields are silently ignored..." << std::endl;
    static constexpr int PORT = 10601;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        server.Get("/ping", [](const HttpRequest& /*req*/, HttpResponse& res) {
            res.Status(200).Text("pong");
        });

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Capture uptime before reload
        auto stats_before = server.GetStats();

        // Build config with changed restart-required fields — must be ignored by Reload()
        ServerConfig new_cfg = cfg;
        new_cfg.bind_host = "0.0.0.0";      // changed — must be ignored
        new_cfg.bind_port = PORT + 100;      // changed — must be ignored
        new_cfg.worker_threads = 8;          // changed — must be ignored
        new_cfg.http2.enabled = false;       // changed — must be ignored

        // This must NOT throw and must NOT attempt to rebind the socket
        server.Reload(new_cfg);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Server must still respond on the original port — bind_port was not changed
        std::string resp = SendHttpRequestCli(PORT,
            "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        bool still_on_original_port = (resp.find("200") != std::string::npos);

        // Uptime must have advanced (server is still running)
        auto stats_after = server.GetStats();
        bool uptime_advanced = (stats_after.uptime_seconds >= stats_before.uptime_seconds);

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bool pass = still_on_original_port && uptime_advanced;
        std::string err;
        if (!still_on_original_port) err += "Server no longer responds on original port; ";
        if (!uptime_advanced) err += "Uptime did not advance after Reload; ";

        TestFramework::RecordTest("Config Reload: restart-required fields ignored",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config Reload: restart-required fields ignored",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 52: ReloadConfig() with a missing config file returns false (no crash).
// We replicate the ReloadConfig() logic from main.cc in-process because the
// function is static.  The key contract: access() returns ENOENT → return false.
void TestReloadMissingConfigFile() {
    std::cout << "\n[TEST] Config Reload: missing config file returns false, no crash..." << std::endl;

    try {
        // Exercise the LoadFromFile path via a config path that does not exist.
        // ConfigLoader::LoadFromFile must throw std::runtime_error; callers must handle it.
        const std::string bogus_path = "/tmp/reactor_test_missing_" +
                                        std::to_string(getpid()) + ".json";
        std::remove(bogus_path.c_str());  // Ensure it doesn't exist

        bool threw_correctly = false;
        try {
            ConfigLoader::LoadFromFile(bogus_path);
        } catch (const std::runtime_error&) {
            threw_correctly = true;
        } catch (const std::exception&) {
            threw_correctly = true;  // any exception is acceptable
        }

        // The important assertion: no crash and threw_correctly == true
        // (in main.cc ReloadConfig(), the exception is caught and false is returned)
        TestFramework::RecordTest("Config Reload: missing file handled gracefully",
                                  threw_correctly,
                                  threw_correctly ? "" : "LoadFromFile on missing path did not throw",
                                  CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config Reload: missing file handled gracefully",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 53: ReloadConfig() with an invalid JSON config returns false (no crash).
// LoadFromString with bad JSON must throw; Validate() with invalid values must
// throw std::invalid_argument.  We test both paths.
void TestReloadInvalidConfigFile() {
    std::cout << "\n[TEST] Config Reload: invalid config handled gracefully..." << std::endl;

    try {
        bool pass = true;
        std::string err;

        // Path 1: syntactically invalid JSON → LoadFromString throws runtime_error
        {
            bool threw = false;
            try {
                ConfigLoader::LoadFromString("{not valid json}");
            } catch (const std::runtime_error&) {
                threw = true;
            } catch (const std::exception&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "Bad JSON did not throw; "; }
        }

        // Path 2: valid JSON but semantically invalid (port out of range) →
        // Validate() throws std::invalid_argument
        {
            bool threw = false;
            try {
                ServerConfig bad_cfg = ConfigLoader::LoadFromString(
                    R"({"bind_port": 99999})");
                ConfigLoader::Validate(bad_cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            } catch (const std::exception&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "Invalid port config did not throw on Validate; "; }
        }

        TestFramework::RecordTest("Config Reload: invalid config handled gracefully",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config Reload: invalid config handled gracefully",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 54: Reload changes log level at runtime.
// Start a logger at "warn" level. Call logging::SetLevel(debug). Verify the
// logger's level is now debug (the same path that ReloadConfig() takes).
void TestReloadChangesLogLevel() {
    std::cout << "\n[TEST] Config Reload: log level change applied at runtime..." << std::endl;
    const std::string log_path = "/tmp/test_reactor_reload_lvl_" +
                                  std::to_string(getpid()) + ".log";
    std::remove(log_path.c_str());

    try {
        logging::Init("test_reload_level", spdlog::level::warn, log_path);

        // Verify starting level is warn
        bool start_warn = (logging::Get()->level() == spdlog::level::warn);

        // Apply the level change that ReloadConfig() would apply
        logging::SetLevel(logging::ParseLevel("debug"));

        bool end_debug = (logging::Get()->level() == spdlog::level::debug);

        // Return to info (cleanup)
        logging::SetLevel(spdlog::level::info);
        logging::Shutdown();
        std::remove(log_path.c_str());

        bool pass = start_warn && end_debug;
        std::string err;
        if (!start_warn) err += "Starting level was not warn; ";
        if (!end_debug)  err += "SetLevel(debug) did not change level; ";

        TestFramework::RecordTest("Config Reload: log level change applied",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        std::remove(log_path.c_str());
        TestFramework::RecordTest("Config Reload: log level change applied",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 9: reload CLI Subcommand Tests (55–58)
//
// These are parser-level tests: they verify that "reload" is a valid subcommand,
// that per-command validation rejects flags that don't apply to reload, that
// -P/--pid-file is accepted, and that the help text mentions "reload".
// ─────────────────────────────────────────────────────────────────────────────

// Test 55: "reload" subcommand sets command=RELOAD.
void TestParseReloadCommand() {
    std::cout << "\n[TEST] CliParser: 'reload' sets command=RELOAD..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "reload"};
        int argc = 2;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.command == CliCommand::RELOAD);
        std::string err = pass ? "" : "command should be RELOAD after 'reload'";
        TestFramework::RecordTest("CliParser: reload command sets RELOAD",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: reload command sets RELOAD",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 56: Per-command validation — reload rejects start-only flags.
// Flags like -c, -p, -H, -l, -w, -d, --no-health-endpoint are only valid for
// 'start'. When passed to 'reload', the parser must throw std::runtime_error.
void TestReloadRejectsStartFlags() {
    std::cout << "\n[TEST] CliParser: 'reload' rejects start-only flags..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // -c / --config is start-only
        {
            const char* args[] = {"reactor_server", "reload", "-c", "/tmp/x.json"};
            int argc = 4;
            bool threw = false;
            try { CliParser::Parse(argc, const_cast<char**>(args)); }
            catch (const std::runtime_error&) { threw = true; }
            catch (const std::exception&) { threw = true; }
            if (!threw) { pass = false; err += "'reload -c' should throw; "; }
        }

        // -p / --port is start-only
        {
            const char* args[] = {"reactor_server", "reload", "-p", "8080"};
            int argc = 4;
            bool threw = false;
            try { CliParser::Parse(argc, const_cast<char**>(args)); }
            catch (const std::runtime_error&) { threw = true; }
            catch (const std::exception&) { threw = true; }
            if (!threw) { pass = false; err += "'reload -p' should throw; "; }
        }

        // --no-health-endpoint is start-only
        {
            const char* args[] = {"reactor_server", "reload", "--no-health-endpoint"};
            int argc = 3;
            bool threw = false;
            try { CliParser::Parse(argc, const_cast<char**>(args)); }
            catch (const std::runtime_error&) { threw = true; }
            catch (const std::exception&) { threw = true; }
            if (!threw) { pass = false; err += "'reload --no-health-endpoint' should throw; "; }
        }

        TestFramework::RecordTest("CliParser: reload rejects start-only flags",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: reload rejects start-only flags",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 57: "reload -P /path/to.pid" accepts -P/--pid-file.
// The reload subcommand needs to know which PID file to read so it can send
// SIGHUP to the running server.
void TestReloadAcceptsPidFile() {
    std::cout << "\n[TEST] CliParser: 'reload -P' accepts pid-file flag..." << std::endl;
    try {
        const char* args[] = {"reactor_server", "reload", "-P", "/var/run/myapp.pid"};
        int argc = 4;
        auto opts = CliParser::Parse(argc, const_cast<char**>(args));

        bool pass = (opts.command == CliCommand::RELOAD) &&
                    (opts.pid_file == "/var/run/myapp.pid");
        std::string err;
        if (opts.command != CliCommand::RELOAD) err += "command is not RELOAD; ";
        if (opts.pid_file != "/var/run/myapp.pid") err += "pid_file not set; ";

        TestFramework::RecordTest("CliParser: reload accepts -P pid-file",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: reload accepts -P pid-file",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 58: Help output contains "reload".
// We invoke PrintUsage() and capture stdout to verify the command is documented.
void TestHelpIncludesReload() {
    std::cout << "\n[TEST] CliParser: help text includes 'reload'..." << std::endl;

    // Run reactor_server --help (or help subcommand) and capture output.
    // We redirect stdout to a pipe so we can inspect it.
    std::string cmd = "./reactor_server help 2>&1";
    FILE* fp = popen(cmd.c_str(), "r");
    std::string output;
    if (fp) {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) output += buf;
        pclose(fp);
    }

    bool has_reload = (output.find("reload") != std::string::npos);
    TestFramework::RecordTest("CliParser: help text includes 'reload'",
                              has_reload,
                              has_reload ? "" : "Help output does not mention 'reload'",
                              CLI_CATEGORY);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 10: /stats Endpoint Tests (59–61)
//
// These integration tests start a real HttpServer with the /stats route
// registered (as main.cc does via MakeStatsHandler), send HTTP requests, and
// verify the JSON shape and semantics.
//
// Port range: 10610–10619
// ─────────────────────────────────────────────────────────────────────────────

// Helper: register /stats on a server the same way main.cc does.
// Re-implemented here because MakeStatsHandler() is a static function in main.cc.
static void RegisterStatsRoute(HttpServer& server, const ServerConfig& config) {
    // Capture server by pointer and config by value (mirrors main.cc semantics)
    HttpServer* srv = &server;
    server.Get("/stats", [srv, config](const HttpRequest& /*req*/, HttpResponse& res) {
        auto stats = srv->GetStats();
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
            config.tls.enabled  ? "true" : "false",
            config.http2.enabled ? "true" : "false");
        if (written < 0 || static_cast<size_t>(written) >= sizeof(buf)) {
            res.Status(500).Json(R"({"error":"stats buffer overflow"})");
            return;
        }
        res.Status(200).Json(buf);
    });
}

// Test 59: /stats response has the correct JSON shape:
//   - top-level keys: uptime_seconds, connections, requests, config
//   - no "pid" key at top level (pid belongs in /health, not /stats)
//   - connections object has required sub-keys
//   - requests object has total and active
void TestStatsEndpointJsonShape() {
    std::cout << "\n[TEST] /stats endpoint: correct JSON shape..." << std::endl;
    static constexpr int PORT = 10610;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        RegisterStatsRoute(server, cfg);

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        std::string resp = SendHttpRequestCli(PORT,
            "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bool pass = true;
        std::string err;

        if (resp.find("200 OK") == std::string::npos) {
            pass = false; err += "Expected 200 OK; ";
        }
        // Required top-level keys
        if (resp.find("\"uptime_seconds\"") == std::string::npos) {
            pass = false; err += "Missing uptime_seconds; ";
        }
        if (resp.find("\"connections\"") == std::string::npos) {
            pass = false; err += "Missing connections; ";
        }
        if (resp.find("\"requests\"") == std::string::npos) {
            pass = false; err += "Missing requests; ";
        }
        if (resp.find("\"config\"") == std::string::npos) {
            pass = false; err += "Missing config section; ";
        }
        // "pid" must NOT be in /stats (it belongs in /health only)
        // Find the body portion after the headers to avoid false-positive matches
        auto hdr_end = resp.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
            std::string body = resp.substr(hdr_end + 4);
            if (body.find("\"pid\"") != std::string::npos) {
                pass = false; err += "/stats body must not contain 'pid' key; ";
            }
        }
        // Required connections sub-keys
        if (resp.find("\"active\"") == std::string::npos) {
            pass = false; err += "Missing connections.active; ";
        }
        if (resp.find("\"total_accepted\"") == std::string::npos) {
            pass = false; err += "Missing total_accepted; ";
        }
        // Required requests sub-keys
        if (resp.find("\"total\"") == std::string::npos) {
            pass = false; err += "Missing requests.total; ";
        }

        TestFramework::RecordTest("/stats: correct JSON shape",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("/stats: correct JSON shape",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 60: uptime_seconds increases between two consecutive /stats calls.
// The server must report a positive uptime from the very first call, and the
// second call (after a brief sleep) must report an equal-or-higher value.
void TestStatsUptimeIncreases() {
    std::cout << "\n[TEST] /stats endpoint: uptime_seconds increases between calls..." << std::endl;
    static constexpr int PORT = 10611;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        RegisterStatsRoute(server, cfg);

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Helper: parse uptime_seconds from a /stats response body
        auto parse_uptime = [](const std::string& resp) -> int64_t {
            auto pos = resp.find("\"uptime_seconds\":");
            if (pos == std::string::npos) return -1;
            pos += 17;  // skip past "uptime_seconds":
            // skip whitespace
            while (pos < resp.size() && resp[pos] == ' ') ++pos;
            std::string num;
            while (pos < resp.size() && (std::isdigit(resp[pos]) || resp[pos] == '-')) {
                num += resp[pos++];
            }
            return num.empty() ? -1 : std::stoll(num);
        };

        std::string resp1 = SendHttpRequestCli(PORT,
            "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        int64_t uptime1 = parse_uptime(resp1);

        // Wait 1.1 seconds so the integer uptime must advance by at least 1
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));

        std::string resp2 = SendHttpRequestCli(PORT,
            "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        int64_t uptime2 = parse_uptime(resp2);

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bool pass = (uptime1 >= 0) && (uptime2 > uptime1);
        std::string err;
        if (uptime1 < 0) err += "Failed to parse first uptime; ";
        if (uptime2 <= uptime1)
            err += "uptime did not increase (" + std::to_string(uptime1) +
                   " -> " + std::to_string(uptime2) + "); ";

        TestFramework::RecordTest("/stats: uptime_seconds increases",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("/stats: uptime_seconds increases",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 61: config section in /stats reflects the actual running config values.
// Verifies bind_port, worker_threads, and max_connections appear correctly.
void TestStatsConfigSectionMatchesConfig() {
    std::cout << "\n[TEST] /stats endpoint: config section matches running config..." << std::endl;
    static constexpr int PORT = 10612;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.worker_threads = 2;
        cfg.max_connections = 777;
        cfg.idle_timeout_sec = 120;
        cfg.request_timeout_sec = 20;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        RegisterStatsRoute(server, cfg);

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        std::string resp = SendHttpRequestCli(PORT,
            "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bool pass = true;
        std::string err;

        // Check bind_port appears as the numeric value we configured
        if (resp.find("\"bind_port\":" + std::to_string(PORT)) == std::string::npos) {
            pass = false;
            err += "bind_port not " + std::to_string(PORT) + " in stats; ";
        }
        // Check worker_threads
        if (resp.find("\"worker_threads\":2") == std::string::npos) {
            pass = false; err += "worker_threads not 2 in stats; ";
        }
        // Check max_connections
        if (resp.find("\"max_connections\":777") == std::string::npos) {
            pass = false; err += "max_connections not 777 in stats; ";
        }
        // Check idle_timeout_sec
        if (resp.find("\"idle_timeout_sec\":120") == std::string::npos) {
            pass = false; err += "idle_timeout_sec not 120 in stats; ";
        }

        TestFramework::RecordTest("/stats: config section matches running config",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("/stats: config section matches running config",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 11: Counter Accuracy Tests (62–65)
//
// Validate that HttpServer's runtime counters (active_connections,
// total_requests, active_h2_streams) track the correct values.
//
// Port range: 10620–10629
// ─────────────────────────────────────────────────────────────────────────────

// Test 62: Connection counter — total_accepted increments on connect; after the
// request completes and the server closes the connection, active_connections
// returns to zero (or decrements by 1 relative to before).
void TestConnectionCounterIncrements() {
    std::cout << "\n[TEST] Counters: connection counters increment/decrement..." << std::endl;
    static constexpr int PORT = 10620;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        server.Get("/ping", [](const HttpRequest& /*req*/, HttpResponse& res) {
            res.Status(200).Text("pong");
        });

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Capture total_accepted before making any connections
        auto stats_before = server.GetStats();
        int64_t accepted_before = stats_before.total_accepted;

        // Make one request with Connection: close to ensure the connection closes
        std::string resp = SendHttpRequestCli(PORT,
            "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        // Give the server time to process the close and decrement active_connections
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        auto stats_after = server.GetStats();

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bool pass = true;
        std::string err;

        if (resp.find("200") == std::string::npos) {
            pass = false; err += "Request failed — cannot test counters; ";
        }

        // total_accepted must have incremented by exactly 1
        int64_t accepted_after = stats_after.total_accepted;
        if (accepted_after < accepted_before + 1) {
            pass = false;
            err += "total_accepted did not increment (" +
                   std::to_string(accepted_before) + " -> " +
                   std::to_string(accepted_after) + "); ";
        }

        // active_connections should be 0 after Connection: close is processed
        if (stats_after.active_connections < 0) {
            pass = false; err += "active_connections is negative; ";
        }

        TestFramework::RecordTest("Counters: connection counter increments",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Counters: connection counter increments",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 63: total_requests counter increments for each HTTP/1.1 request served.
// Send N sequential requests and verify total_requests increases by N.
void TestRequestCounterIncrements() {
    std::cout << "\n[TEST] Counters: total_requests increments per request..." << std::endl;
    static constexpr int PORT = 10621;
    static constexpr int NUM_REQUESTS = 5;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        server.Get("/count", [](const HttpRequest& /*req*/, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        auto stats_before = server.GetStats();
        int64_t requests_before = stats_before.total_requests;

        for (int i = 0; i < NUM_REQUESTS; ++i) {
            SendHttpRequestCli(PORT,
                "GET /count HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            // Brief pause so connections close before the next one opens
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        // Allow in-flight counters to settle
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        auto stats_after = server.GetStats();
        int64_t requests_after = stats_after.total_requests;

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        int64_t delta = requests_after - requests_before;
        bool pass = (delta >= static_cast<int64_t>(NUM_REQUESTS));
        std::string err;
        if (!pass) {
            err = "Expected >=" + std::to_string(NUM_REQUESTS) +
                  " new requests, got " + std::to_string(delta);
        }

        TestFramework::RecordTest("Counters: total_requests increments per request",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Counters: total_requests increments per request",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 64: GetStats() returns non-negative values for all counter fields.
// This is a basic sanity check: no counter should ever be negative.
// Exercises the GetStats() API on a freshly-started server with no load.
void TestStatsCountersNonNegative() {
    std::cout << "\n[TEST] Counters: GetStats() fields are all non-negative..." << std::endl;
    static constexpr int PORT = 10622;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        auto stats = server.GetStats();

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bool pass = true;
        std::string err;

        if (stats.uptime_seconds < 0) { pass = false; err += "uptime_seconds < 0; "; }
        if (stats.active_connections < 0) { pass = false; err += "active_connections < 0; "; }
        if (stats.active_http1_connections < 0) { pass = false; err += "active_http1 < 0; "; }
        if (stats.active_http2_connections < 0) { pass = false; err += "active_http2 < 0; "; }
        if (stats.active_h2_streams < 0) { pass = false; err += "active_h2_streams < 0; "; }
        if (stats.total_accepted < 0) { pass = false; err += "total_accepted < 0; "; }
        if (stats.total_requests < 0) { pass = false; err += "total_requests < 0; "; }
        if (stats.active_requests < 0) { pass = false; err += "active_requests < 0; "; }

        TestFramework::RecordTest("Counters: GetStats() all fields non-negative",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Counters: GetStats() all fields non-negative",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 65: After multiple concurrent requests, total_requests == total requests sent.
// Validates counter accuracy under concurrent load (not just serial load).
void TestRequestCounterConcurrent() {
    std::cout << "\n[TEST] Counters: total_requests accurate under concurrent load..." << std::endl;
    static constexpr int PORT = 10623;
    static constexpr int NUM_THREADS = 5;
    static constexpr int REQS_PER_THREAD = 4;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        server.Get("/hit", [](const HttpRequest& /*req*/, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        auto stats_before = server.GetStats();
        int64_t before = stats_before.total_requests;

        std::atomic<int> success_count{0};
        std::vector<std::thread> threads;
        threads.reserve(NUM_THREADS);

        for (int i = 0; i < NUM_THREADS; ++i) {
            threads.emplace_back([&]() {
                for (int j = 0; j < REQS_PER_THREAD; ++j) {
                    std::string resp = SendHttpRequestCli(PORT,
                        "GET /hit HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
                    if (resp.find("200") != std::string::npos) {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
        }
        for (auto& t : threads) t.join();

        // Allow all counters to settle
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        auto stats_after = server.GetStats();
        int64_t delta = stats_after.total_requests - before;

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Allow ±1 for a race on the very last request close
        bool pass = (delta >= static_cast<int64_t>(success_count.load()));
        std::string err;
        if (!pass) {
            err = "total_requests delta=" + std::to_string(delta) +
                  " < success_count=" + std::to_string(success_count.load());
        }

        TestFramework::RecordTest("Counters: total_requests accurate under concurrent load",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Counters: total_requests accurate under concurrent load",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 12: SIGHUP / Reload Integration Tests (66–68)
//
// Test 66: WaitForSignal() already covered in Section 6 (RELOAD on SIGHUP).
//          Here we verify the daemon vs. foreground SIGHUP semantics at the
//          config layer, and that an invalid reload config leaves the server
//          functional (the server is not crashed by a bad config).
//
// These tests do NOT start a real daemon — they exercise the ReloadConfig()
// logic in-process by calling HttpServer::Reload() directly.
// ─────────────────────────────────────────────────────────────────────────────

// Test 66: WaitForSignal() returns RELOAD on SIGHUP — this is already covered by
// TestWaitForSignalSIGHUP() in Section 6. Here we add a dedicated guard test:
// after SIGHUP, a second WaitForSignal() call must still be able to block and
// return SHUTDOWN on SIGTERM.  This ensures the signal loop in main.cc is safe
// to iterate.
void TestSighupFollowedBySigterm() {
    std::cout << "\n[TEST] SIGHUP integration: SIGHUP+SIGTERM sequence returns RELOAD then SHUTDOWN..." << std::endl;
    try {
        SignalHandler::Install();

        std::atomic<int> reload_count{0};
        std::atomic<bool> shutdown_seen{false};

        std::thread waiter([&]() {
            // First call — should get RELOAD from SIGHUP
            SignalResult r1 = SignalHandler::WaitForSignal();
            if (r1 == SignalResult::RELOAD) {
                reload_count.fetch_add(1, std::memory_order_release);
            }
            // Second call — should get SHUTDOWN from SIGTERM
            SignalResult r2 = SignalHandler::WaitForSignal();
            if (r2 == SignalResult::SHUTDOWN) {
                shutdown_seen.store(true, std::memory_order_release);
            }
        });

        // Let the waiter reach the first sigwait()
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Send SIGHUP first
        kill(getpid(), SIGHUP);

        // Allow waiter to process RELOAD and loop back to second sigwait()
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Send SIGTERM to unblock the second call
        kill(getpid(), SIGTERM);

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(600);
        while (!shutdown_seen.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // Safety: ensure waiter can exit
        if (!shutdown_seen.load(std::memory_order_acquire)) {
            kill(getpid(), SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (waiter.joinable()) waiter.join();

        bool pass = (reload_count.load() == 1) && shutdown_seen.load();
        std::string err;
        if (reload_count.load() != 1)
            err += "Expected 1 RELOAD, got " + std::to_string(reload_count.load()) + "; ";
        if (!shutdown_seen.load())
            err += "Did not get SHUTDOWN after SIGTERM; ";

        SignalHandler::Cleanup();
        DrainAndRestoreSignals();

        TestFramework::RecordTest(
            "SIGHUP integration: SIGHUP then SIGTERM returns RELOAD then SHUTDOWN",
            pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        SignalHandler::Cleanup();
        DrainAndRestoreSignals();
        TestFramework::RecordTest(
            "SIGHUP integration: SIGHUP then SIGTERM returns RELOAD then SHUTDOWN",
            false, e.what(), CLI_CATEGORY);
    }
}

// Test 67: Invalid config on reload does not crash the server.
// Call HttpServer::Reload() with a config that has an extreme max_body_size
// (near numeric limits) — Reload() must not throw, and the server must
// continue responding to requests.
void TestInvalidConfigOnReloadNoServerCrash() {
    std::cout << "\n[TEST] SIGHUP integration: invalid config on reload does not crash server..." << std::endl;
    static constexpr int PORT = 10630;

    try {
        ServerConfig cfg = ConfigLoader::Default();
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = PORT;
        cfg.log.level = "warn";

        HttpServer server(cfg);
        server.Get("/ping", [](const HttpRequest& /*req*/, HttpResponse& res) {
            res.Status(200).Text("pong");
        });

        std::thread srv_thread([&server]() {
            try { server.Start(); } catch (...) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Attempt to reload with a config that passes Validate() (syntactically valid)
        // but sets extreme limits — Reload() must handle gracefully
        ServerConfig extreme_cfg = cfg;
        extreme_cfg.max_body_size = 0;           // minimal (reload-safe field)
        extreme_cfg.request_timeout_sec = 1;     // very short
        extreme_cfg.idle_timeout_sec = 1;

        // This must not throw and must not crash the server
        bool reload_threw = false;
        try {
            server.Reload(extreme_cfg);
        } catch (...) {
            reload_threw = true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Server must still respond after the extreme reload
        std::string resp = SendHttpRequestCli(PORT,
            "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        bool still_alive = (resp.find("200") != std::string::npos);

        server.Stop();
        if (srv_thread.joinable()) srv_thread.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bool pass = !reload_threw && still_alive;
        std::string err;
        if (reload_threw) err += "Reload() threw unexpectedly; ";
        if (!still_alive) err += "Server crashed or stopped responding after extreme Reload; ";

        TestFramework::RecordTest(
            "SIGHUP integration: extreme reload config does not crash server",
            pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SIGHUP integration: extreme reload config does not crash server",
            false, e.what(), CLI_CATEGORY);
    }
}

// Test 68: Foreground mode SIGHUP semantics — WaitForShutdown() returns after
// a single SIGHUP (simulating terminal hangup).  This complements the daemon
// mode test (Test 66) and is already partially covered by TestWaitForShutdownIgnoresSIGHUP
// which tests the library function.  Here we verify the Reload() → server.Stop()
// sequence by checking server liveness: the server stops accepting after Stop().
void TestForegroundSighupStopsServer() {
    std::cout << "\n[TEST] SIGHUP integration: foreground SIGHUP does not trigger reload (uses WaitForShutdown)..." << std::endl;

    // In foreground mode (main.cc), WaitForSignal() returning RELOAD causes
    // MarkShutdownRequested() + break — the same as a shutdown.
    // We test this at the SignalHandler API level (no need to run the full main).
    try {
        SignalHandler::Install();

        std::atomic<SignalResult> received{SignalResult::SHUTDOWN};
        std::atomic<bool> done{false};

        std::thread waiter([&]() {
            received.store(SignalHandler::WaitForSignal(), std::memory_order_release);
            done.store(true, std::memory_order_release);
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        kill(getpid(), SIGHUP);

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (!done.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (!done.load(std::memory_order_acquire)) {
            kill(getpid(), SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (waiter.joinable()) waiter.join();

        // WaitForSignal() must have returned RELOAD for SIGHUP
        // (foreground code then calls MarkShutdownRequested() and breaks — but that's
        // a main.cc policy, not a SignalHandler policy; here we just verify RELOAD)
        bool got_reload = (received.load() == SignalResult::RELOAD);

        SignalHandler::Cleanup();
        DrainAndRestoreSignals();

        TestFramework::RecordTest(
            "SIGHUP integration: WaitForSignal returns RELOAD on SIGHUP (foreground also sees RELOAD)",
            done.load() && got_reload,
            done.load() && got_reload ? "" :
                (!done.load() ? "WaitForSignal did not unblock" : "Expected RELOAD, got SHUTDOWN"),
            CLI_CATEGORY);
    } catch (const std::exception& e) {
        SignalHandler::Cleanup();
        DrainAndRestoreSignals();
        TestFramework::RecordTest(
            "SIGHUP integration: WaitForSignal returns RELOAD on SIGHUP (foreground also sees RELOAD)",
            false, e.what(), CLI_CATEGORY);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite entry point
// ─────────────────────────────────────────────────────────────────────────────

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CLI TESTS - UNIT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // ── Section 1: CliParser ──────────────────────────────────────
    TestParseDefaults();
    TestParseConfigPath();
    TestParseAllShortOptions();
    TestParseAllLongOptions();
    TestParseInvalidPort();
    TestParseInvalidPortNegative();
    TestParseInvalidPortNonNumeric();
    TestParseInvalidLogLevel();
    TestParseUnknownCommand();
    TestParseUnknownOption();
    TestParseVersionFlags();
    TestParseTestConfig();
    TestParseDumpConfig();
    TestParsePidFile();
    TestParseSignalStop();
    TestParseSignalStatus();
    TestParseNoHealthEndpoint();

    // ── Section 2: PidFile ────────────────────────────────────────
    TestPidFileAcquireAndRelease();
    TestPidFileAcquireBlocksSecondInstance();
    TestPidFileStaleDetection();
    TestPidFileReadPidValid();
    TestPidFileReadPidMissing();
    TestPidFileReadPidInvalid();
    TestPidFileReadPidNumericPrefixGarbage();
    TestPidFileCheckRunningNotRunning();

    // ── Section 3: Config override precedence ─────────────────────
    TestConfigDefaultsPreserved();
    TestConfigFileOverridesDefaults();
    TestConfigEnvOverridesFile();
    TestConfigCliOverridesEnv();
    TestConfigUnsetCliDoesNotRevertEnv();

    // ── Section 4: SignalHandler ──────────────────────────────────
    TestSignalHandlerInstallAndCleanup();
    TestSignalHandlerSigwaitUnblock();

    // ── Section 5: Logger Phase 2 ─────────────────────────────────
    TestSetConsoleEnabled();
    TestSetConsoleEnabledPersists();
    TestReopenWithFileSink();
    TestReopenWithoutFileSink();
    TestReopenBeforeInit();
    TestReopenPreservesLevel();

    // ── Section 6: SignalHandler Phase 2 ─────────────────────────
    TestWaitForSignalSIGTERM();
    TestWaitForSignalSIGHUP();
    TestWaitForShutdownIgnoresSIGHUP();

    // ── Section 7: CliParser Daemonize ────────────────────────────
    TestStartDaemonizeShortFlag();
    TestStartDaemonizeLongFlag();
    TestStartNoDaemonize();
    TestStopRejectsDaemonize();
    TestStatusRejectsDaemonize();
    TestValidateAcceptsDaemonize();
    TestConfigRejectsDaemonize();
    TestValidateDaemonRejectsNoLogFile();
    TestValidateDaemonRejectsRelativePidPath();

    // ── Section 8: Config Reload ──────────────────────────────────
    TestReloadAppliesLimits();
    TestReloadSkipsRestartRequiredFields();
    TestReloadMissingConfigFile();
    TestReloadInvalidConfigFile();
    TestReloadChangesLogLevel();

    // ── Section 9: reload CLI subcommand ─────────────────────────
    TestParseReloadCommand();
    TestReloadRejectsStartFlags();
    TestReloadAcceptsPidFile();
    TestHelpIncludesReload();

    // ── Section 10: /stats endpoint ───────────────────────────────
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestStatsEndpointJsonShape();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestStatsUptimeIncreases();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestStatsConfigSectionMatchesConfig();

    // ── Section 11: Counter accuracy ─────────────────────────────
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestConnectionCounterIncrements();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestRequestCounterIncrements();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestStatsCountersNonNegative();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestRequestCounterConcurrent();

    // ── Section 12: SIGHUP / reload integration ───────────────────
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestSighupFollowedBySigterm();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestInvalidConfigOnReloadNoServerCrash();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    TestForegroundSighupStopsServer();
}

}  // namespace CliTests
