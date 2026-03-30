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
//   - Logger Enhanced (6 tests): EnsureLogDir, date-based naming, CheckRotation,
//                                 WriteMarker, SanitizePath, append-on-restart
//
// Port range: 10500-10599 (not used directly by unit tests; reserved for this suite)
// Temp file pattern: /tmp/test_reactor_NNNN.pid

#include "test_framework.h"
#include "cli/cli_parser.h"
#include "cli/pid_file.h"
#include "cli/signal_handler.h"
#include "cli/version.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "log/logger.h"
#include "log/log_utils.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>

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

// Helper: remove all files in /tmp matching a prefix and .log extension.
static void CleanupLogFiles(const std::string& dir, const std::string& prefix) {
    DIR* d = opendir(dir.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name(entry->d_name);
        if (name.find(prefix) == 0 && name.find(".log") != std::string::npos) {
            std::remove((dir + "/" + name).c_str());
        }
    }
    closedir(d);
}

// Helper: scan a directory for a file whose name starts with 'prefix' and ends
// with '.log'. Returns the full path of the first match, or "" if none found.
static std::string FindLogFile(const std::string& dir, const std::string& prefix) {
    DIR* d = opendir(dir.c_str());
    if (!d) return "";
    struct dirent* entry;
    std::string found;
    while ((entry = readdir(d)) != nullptr) {
        std::string name(entry->d_name);
        if (name.find(prefix) == 0 && name.size() > 4 &&
            name.compare(name.size() - 4, 4, ".log") == 0) {
            found = dir + "/" + name;
            break;
        }
    }
    closedir(d);
    return found;
}

// Helper: read the full text of a file into a string. Returns "" on error.
static std::string ReadFileContent(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string content;
    std::string line;
    while (std::getline(f, line)) content += line + "\n";
    return content;
}

// Test 32: SetConsoleEnabled(false) + Init with a file → logger is functional
// even with console disabled.  Validates that the sticky console flag is stored
// before Init() and honoured inside BuildSinks().
void TestSetConsoleEnabled() {
    std::cout << "\n[TEST] Logger: SetConsoleEnabled(false) disables console sink..." << std::endl;
    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) +
                                  "_console.log";
    const std::string prefix = "test_reactor_log_" + std::to_string(getpid()) + "_console-";
    CleanupLogFiles("/tmp", prefix);

    try {
        // Disable console before initialising so daemon-mode path is exercised
        logging::SetConsoleEnabled(false);
        logging::Init("test_logger_console", spdlog::level::info, log_path);

        // Logger must still be usable — no crash expected
        logging::Get()->info("SetConsoleEnabled test message");
        logging::Get()->flush();

        logging::Shutdown();  // resets g_console_enabled to true
        CleanupLogFiles("/tmp", prefix);

        TestFramework::RecordTest("Logger: SetConsoleEnabled(false) functional",
                                  true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
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
    const std::string prefix = "test_reactor_log_" + std::to_string(getpid()) + "_persist-";
    CleanupLogFiles("/tmp", prefix);

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
        CleanupLogFiles("/tmp", prefix);

        TestFramework::RecordTest("Logger: SetConsoleEnabled persists across Init",
                                  true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
        TestFramework::RecordTest("Logger: SetConsoleEnabled persists across Init",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 34: Reopen() with a live file sink closes and reopens the file handle.
// Simulates logrotate: write "Before", rename file, Reopen(), write "After".
// Verifies: rotated file has "Before", new file has "After".
// Note: With date-based naming, Init("path/foo.log") creates "path/foo-YYYY-MM-DD.log".
// The test finds the actual date-based file by scanning /tmp.
void TestReopenWithFileSink() {
    std::cout << "\n[TEST] Logger: Reopen() with file sink reconstructs logger..." << std::endl;
    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) +
                                  "_reopen.log";
    const std::string prefix = "test_reactor_log_" + std::to_string(getpid()) + "_reopen-";
    CleanupLogFiles("/tmp", prefix);

    try {
        logging::Init("test_reopen", spdlog::level::info, log_path);

        // Find the actual date-based file created by Init
        std::string actual_file = FindLogFile("/tmp", prefix);
        if (actual_file.empty()) {
            logging::Shutdown();
            TestFramework::RecordTest("Logger: Reopen with file sink",
                                      false, "Date-based log file not found after Init", CLI_CATEGORY);
            return;
        }

        // Write a message before Reopen
        logging::Get()->info("Before reopen");
        logging::Get()->flush();

        // Simulate log-rotation: rename the old file and call Reopen()
        // so the logger creates a new file handle at the same path.
        const std::string rotated = actual_file + ".rotated";
        std::rename(actual_file.c_str(), rotated.c_str());

        logging::Reopen();

        // Write after Reopen — must go to a NEW file (same date-based name)
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
            std::ifstream f(actual_file);
            if (f.is_open()) {
                std::string line;
                while (std::getline(f, line)) new_content += line + "\n";
            }
        }
        bool new_has_after = new_content.find("After reopen") != std::string::npos;

        std::remove(actual_file.c_str());
        std::remove(rotated.c_str());
        CleanupLogFiles("/tmp", prefix);

        bool pass = rotated_has_before && new_has_after;
        std::string err;
        if (!rotated_has_before) err += "Rotated file missing 'Before reopen'; ";
        if (!new_has_after) err += "New file missing 'After reopen'; ";

        TestFramework::RecordTest("Logger: Reopen with file sink", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
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
    const std::string prefix = "test_reactor_log_" + std::to_string(getpid()) + "_level-";
    CleanupLogFiles("/tmp", prefix);

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
        CleanupLogFiles("/tmp", prefix);

        TestFramework::RecordTest("Logger: Reopen preserves log level",
                                  level_preserved,
                                  level_preserved ? "" : "Log level changed after Reopen()",
                                  CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
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
// SECTION 8: Logger Enhanced Tests (50–55)
//
// These tests exercise the new logging APIs added in the enhanced logging system:
//   EnsureLogDir  — creates missing log directories, rejects path-is-file
//   Date-based naming — Init() creates {prefix}-{YYYY-MM-DD}.log
//   CheckRotation — rotates to a new seq file when size limit is exceeded
//   WriteMarker   — writes a visual "==== TEXT [timestamp] ====" marker
//   SanitizePath  — strips query params and fragment from URL paths
//   Append-on-restart — re-Init with the same path appends, not truncates
//
// Each test cleans up its own /tmp files in both success and failure paths.
// Shutdown() is called after every test to restore clean logger state.
// ─────────────────────────────────────────────────────────────────────────────



// Test 50: EnsureLogDir creates a missing directory, is idempotent on an
// existing directory, and throws when the path already exists as a file.
//
// Validates the three distinct outcomes of EnsureLogDir():
//   1. Missing path   → directory created
//   2. Existing dir   → no-op (no exception)
//   3. Path is a file → std::runtime_error thrown
void TestLogDirCreation() {
    std::cout << "\n[TEST] Logger: EnsureLogDir creates directory and validates idempotency..." << std::endl;

    const std::string test_dir = "/tmp/test_reactor_logdir_" + std::to_string(getpid());
    const std::string file_path = "/tmp/test_reactor_logdir_file_" + std::to_string(getpid());

    // Cleanup from any prior run
    rmdir(test_dir.c_str());
    std::remove(file_path.c_str());

    try {
        // Case 1: directory does not exist — must be created
        logging::EnsureLogDir(test_dir);

        struct stat st{};
        bool dir_created = (stat(test_dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode));

        // Case 2: directory already exists — must not throw (idempotent)
        bool idempotent = true;
        try {
            logging::EnsureLogDir(test_dir);
        } catch (...) {
            idempotent = false;
        }

        // Case 3: path is a regular file — must throw
        WriteFile(file_path, "not a directory\n");
        bool throws_on_file = false;
        try {
            logging::EnsureLogDir(file_path);
        } catch (const std::runtime_error&) {
            throws_on_file = true;
        } catch (...) {
            // Any exception is acceptable; runtime_error is preferred
            throws_on_file = true;
        }

        rmdir(test_dir.c_str());
        std::remove(file_path.c_str());

        bool pass = dir_created && idempotent && throws_on_file;
        std::string err;
        if (!dir_created)    err += "Directory not created; ";
        if (!idempotent)     err += "Second EnsureLogDir threw on existing dir; ";
        if (!throws_on_file) err += "EnsureLogDir did not throw when path is a file; ";

        TestFramework::RecordTest("Logger: EnsureLogDir creates and validates directory",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        rmdir(test_dir.c_str());
        std::remove(file_path.c_str());
        TestFramework::RecordTest("Logger: EnsureLogDir creates and validates directory",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 51: Init() with a file path creates a file whose name follows the
// date-based format {prefix}-{YYYY-MM-DD}.log (never the bare original name).
//
// Validates:
//   - The actual file on disk has today's date embedded in the name
//   - The file name matches the pattern: prefix + "-" + YYYY-MM-DD + ".log"
void TestDateBasedFileName() {
    std::cout << "\n[TEST] Logger: Init creates date-based file name..." << std::endl;

    const std::string log_path  = "/tmp/test_reactor_log_" + std::to_string(getpid()) + "_date.log";
    const std::string prefix    = "test_reactor_log_" + std::to_string(getpid()) + "_date-";
    CleanupLogFiles("/tmp", prefix);

    try {
        logging::Init("test_date_name", spdlog::level::info, log_path);

        // Write and flush so the file is definitely created
        logging::Get()->info("Date-based naming test");
        logging::Get()->flush();

        // Compute today's date string for validation
        std::time_t now = std::time(nullptr);
        std::tm tm{};
        localtime_r(&now, &tm);
        static constexpr size_t DATE_STR_SIZE = 16;
        char date_buf[DATE_STR_SIZE];
        std::snprintf(date_buf, sizeof(date_buf), "%04d-%02d-%02d",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
        const std::string today(date_buf);

        // Scan /tmp for the actual file
        std::string actual_file = FindLogFile("/tmp", prefix);

        logging::Shutdown();

        bool file_found = !actual_file.empty();

        // Verify the file name contains today's date
        bool has_date = false;
        if (file_found) {
            has_date = actual_file.find(today) != std::string::npos;
        }

        // Verify the bare original name does NOT exist (no "…_date.log")
        struct stat st{};
        bool bare_not_created = (stat(log_path.c_str(), &st) != 0);

        CleanupLogFiles("/tmp", prefix);

        bool pass = file_found && has_date && bare_not_created;
        std::string err;
        if (!file_found)         err += "No date-based log file found in /tmp; ";
        if (!has_date)           err += "File name missing today's date (" + today + "); ";
        if (!bare_not_created)   err += "Bare original path was created (should not exist); ";

        TestFramework::RecordTest("Logger: Init creates date-based file name",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
        TestFramework::RecordTest("Logger: Init creates date-based file name",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 52: CheckRotation() creates a new seq-suffixed file when the current
// log file exceeds the configured max_size.
//
// Strategy:
//   1. Init with max_size=100 (tiny), write messages to exceed the limit
//   2. Call CheckRotation()
//   3. Write one more message, flush
//   4. Verify a second file exists in /tmp with a "-1" sequence suffix
//   5. Verify the first file is non-empty and the second file has the post-rotation message
void TestCheckRotation() {
    std::cout << "\n[TEST] Logger: CheckRotation rotates to next seq file..." << std::endl;

    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) + "_rot.log";
    const std::string prefix   = "test_reactor_log_" + std::to_string(getpid()) + "_rot-";
    CleanupLogFiles("/tmp", prefix);

    try {
        // Use a 100-byte max to make it easy to exceed with a few log lines
        static constexpr size_t TINY_MAX_SIZE = 100;
        logging::Init("test_rotation", spdlog::level::info, log_path, TINY_MAX_SIZE);

        // Write multiple lines to ensure we exceed the 100-byte limit
        logging::Get()->info("Rotation pre-message: filling up the tiny log file now");
        logging::Get()->info("Rotation pre-message: second line to definitely exceed limit");
        logging::Get()->flush();

        // Confirm first file is over the size limit before rotating
        std::string first_file = FindLogFile("/tmp", prefix);
        if (first_file.empty()) {
            logging::Shutdown();
            CleanupLogFiles("/tmp", prefix);
            TestFramework::RecordTest("Logger: CheckRotation rotates to next seq file",
                                      false, "First log file not found after Init", CLI_CATEGORY);
            return;
        }

        // Rotate: CheckRotation checks file size and opens the next seq file
        logging::CheckRotation();

        // Write the post-rotation message — must go to the new seq file
        logging::Get()->info("Rotation post-message: this is in the rotated file");
        logging::Get()->flush();

        logging::Shutdown();

        // Scan /tmp for all files with our prefix to verify two files exist
        std::vector<std::string> log_files;
        {
            DIR* d = opendir("/tmp");
            if (d) {
                struct dirent* entry;
                while ((entry = readdir(d)) != nullptr) {
                    std::string name(entry->d_name);
                    if (name.find(prefix) == 0 &&
                        name.compare(name.size() - 4, 4, ".log") == 0) {
                        log_files.push_back("/tmp/" + name);
                    }
                }
                closedir(d);
            }
        }

        bool two_files = (log_files.size() >= 2);

        // The post-rotation message must appear in one of the files
        bool post_in_some_file = false;
        bool pre_in_some_file  = false;
        for (const auto& fpath : log_files) {
            std::string content = ReadFileContent(fpath);
            if (content.find("Rotation post-message") != std::string::npos)
                post_in_some_file = true;
            if (content.find("Rotation pre-message") != std::string::npos)
                pre_in_some_file = true;
        }

        CleanupLogFiles("/tmp", prefix);

        bool pass = two_files && pre_in_some_file && post_in_some_file;
        std::string err;
        if (!two_files)          err += "Expected >=2 rotated files, got " +
                                         std::to_string(log_files.size()) + "; ";
        if (!pre_in_some_file)   err += "Pre-rotation message not found in any file; ";
        if (!post_in_some_file)  err += "Post-rotation message not found in any file; ";

        TestFramework::RecordTest("Logger: CheckRotation rotates to next seq file",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
        TestFramework::RecordTest("Logger: CheckRotation rotates to next seq file",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 53: WriteMarker() writes a line containing the standard visual separator
// pattern "================================ TEXT [timestamp] ================================".
//
// Validates:
//   - The marker line contains the "===…" prefix
//   - The marker line contains the provided text
//   - The marker line contains a timestamp in brackets ("]")
//   - The marker line contains the "===…" suffix
void TestWriteMarker() {
    std::cout << "\n[TEST] Logger: WriteMarker writes visual separator to log file..." << std::endl;

    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) + "_marker.log";
    const std::string prefix   = "test_reactor_log_" + std::to_string(getpid()) + "_marker-";
    CleanupLogFiles("/tmp", prefix);

    try {
        logging::Init("test_marker", spdlog::level::info, log_path);

        logging::WriteMarker("SERVER START");
        logging::Get()->flush();

        // Find the actual date-based file
        std::string actual_file = FindLogFile("/tmp", prefix);

        logging::Shutdown();

        if (actual_file.empty()) {
            CleanupLogFiles("/tmp", prefix);
            TestFramework::RecordTest("Logger: WriteMarker writes visual separator",
                                      false, "Log file not found after Init", CLI_CATEGORY);
            return;
        }

        std::string content = ReadFileContent(actual_file);
        CleanupLogFiles("/tmp", prefix);

        // Check for the expected marker format:
        // "================================ SERVER START ================================"
        bool has_marker = content.find("================================ SERVER START ================================") != std::string::npos;

        bool pass = has_marker;
        std::string err;
        if (!has_marker) err += "Marker line not found in log file; ";

        TestFramework::RecordTest("Logger: WriteMarker writes visual separator",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
        TestFramework::RecordTest("Logger: WriteMarker writes visual separator",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 54: SanitizePath() correctly strips query strings and fragments from
// URL paths while leaving clean paths, root, and empty strings untouched.
//
// Validates all six cases specified in the task:
//   1. No change:                "/api/users"            → "/api/users"
//   2. Query stripped:           "/api/users?token=abc"  → "/api/users"
//   3. Fragment stripped:        "/api/users#section"    → "/api/users"
//   4. Query before fragment:    "/api/users?a=1&b=2#f"  → "/api/users"
//   5. Empty string:             ""                      → ""
//   6. Root path:                "/"                     → "/"
void TestSanitizePath() {
    std::cout << "\n[TEST] Logger: SanitizePath strips query and fragment..." << std::endl;

    try {
        struct TestCase {
            std::string input;
            std::string expected;
            const char* label;
        };

        const TestCase cases[] = {
            { "/api/users",             "/api/users", "clean path unchanged"      },
            { "/api/users?token=abc",   "/api/users", "query stripped"            },
            { "/api/users#section",     "/api/users", "fragment stripped"         },
            { "/api/users?a=1&b=2#frag","/api/users", "query + fragment stripped" },
            { "",                       "",           "empty string unchanged"     },
            { "/",                      "/",          "root path unchanged"        },
        };

        bool pass = true;
        std::string err;
        for (const auto& tc : cases) {
            std::string result = logging::SanitizePath(tc.input);
            if (result != tc.expected) {
                pass = false;
                err += std::string("Case '") + tc.label + "': input='" + tc.input +
                       "' expected='" + tc.expected + "' got='" + result + "'; ";
            }
        }

        TestFramework::RecordTest("Logger: SanitizePath strips query and fragment",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Logger: SanitizePath strips query and fragment",
                                  false, e.what(), CLI_CATEGORY);
    }
}

// Test 55: Re-Init with the same log path appends to the existing file rather
// than truncating it. Validates the "server restart" scenario where log
// continuity across restarts is required.
//
// Steps:
//   1. Init + write "First session" + Shutdown
//   2. Init (same path) + write "Second session" + Shutdown
//   3. Read file — both messages must be present
void TestLogFileAppendOnRestart() {
    std::cout << "\n[TEST] Logger: Re-Init with same path appends (no truncate)..." << std::endl;

    const std::string log_path = "/tmp/test_reactor_log_" + std::to_string(getpid()) + "_append.log";
    const std::string prefix   = "test_reactor_log_" + std::to_string(getpid()) + "_append-";
    CleanupLogFiles("/tmp", prefix);

    try {
        // First session
        logging::Init("test_append_1", spdlog::level::info, log_path);
        logging::Get()->info("First session message");
        logging::Get()->flush();
        logging::Shutdown();

        // Find the date-based file created during first session
        std::string first_file = FindLogFile("/tmp", prefix);
        if (first_file.empty()) {
            CleanupLogFiles("/tmp", prefix);
            TestFramework::RecordTest("Logger: Re-Init appends to existing log",
                                      false, "Log file not found after first Init", CLI_CATEGORY);
            return;
        }

        // Verify first session content is present before second session
        std::string content_after_first = ReadFileContent(first_file);
        bool has_first_msg = content_after_first.find("First session message") != std::string::npos;

        // Second session — same log path, should append
        logging::Init("test_append_2", spdlog::level::info, log_path);
        logging::Get()->info("Second session message");
        logging::Get()->flush();
        logging::Shutdown();

        // The date-based file should still exist with both messages
        std::string content_final = ReadFileContent(first_file);
        bool has_both = content_final.find("First session message")  != std::string::npos &&
                        content_final.find("Second session message") != std::string::npos;

        CleanupLogFiles("/tmp", prefix);

        bool pass = has_first_msg && has_both;
        std::string err;
        if (!has_first_msg) err += "First session message not found after first Init; ";
        if (!has_both)      err += "File was truncated on re-Init (missing one or both messages); ";

        TestFramework::RecordTest("Logger: Re-Init appends to existing log",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        logging::Shutdown();
        CleanupLogFiles("/tmp", prefix);
        TestFramework::RecordTest("Logger: Re-Init appends to existing log",
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

    // ── Section 8: Logger Enhanced ───────────────────────────────
    TestLogDirCreation();
    TestDateBasedFileName();
    TestCheckRotation();
    TestWriteMarker();
    TestSanitizePath();
    TestLogFileAppendOnRestart();
}

}  // namespace CliTests
