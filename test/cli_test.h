#pragma once

// cli_test.h — Comprehensive test suite for the CLI entry point components.
//
// Covers:
//   - CliParser (17 tests): default values, all short/long options, validation errors
//   - PidFile (7 tests): acquire/release lifecycle, stale detection, ReadPid, CheckRunning
//   - Config override precedence (5 tests): defaults < file < env < CLI
//   - SignalHandler (2 tests): install/cleanup fd lifecycle, self-pipe unblocks WaitForSignal
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
void TestParseInvalidSignalAction() {
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
        TestFramework::RecordTest("CliParser: -t test-config flag", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: -t test-config flag", false, e.what(), CLI_CATEGORY);
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
        TestFramework::RecordTest("CliParser: --dump-effective-config", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: --dump-effective-config", false, e.what(), CLI_CATEGORY);
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
        TestFramework::RecordTest("CliParser: -s stop", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: -s stop", false, e.what(), CLI_CATEGORY);
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
        TestFramework::RecordTest("CliParser: -s status", pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CliParser: -s status", false, e.what(), CLI_CATEGORY);
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
// SECTION 4: SignalHandler Tests (30–31)
// ─────────────────────────────────────────────────────────────────────────────

// Test 30: Install() blocks signals via pthread_sigmask, Cleanup() unblocks.
// Verify neither throws.
void TestSignalHandlerInstallAndCleanup() {
    std::cout << "\n[TEST] SignalHandler: Install and Cleanup succeeds..." << std::endl;
    try {
        SignalHandler::Install();
        SignalHandler::Cleanup();

        TestFramework::RecordTest("SignalHandler: Install and Cleanup", true, "", CLI_CATEGORY);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("SignalHandler: Install and Cleanup", false, e.what(), CLI_CATEGORY);
    }
}

// Test 31: After Install(), sending SIGTERM causes WaitForSignal to unblock.
//
// Design:
//   1. Install() — blocks SIGTERM/SIGINT via pthread_sigmask
//   2. Spawn a thread that calls WaitForSignal(nullptr)
//      (nullptr: WaitForSignal just sets the shutdown flag, no Stop() call)
//   3. Main thread: kill(getpid(), SIGTERM) — process-directed so sigwait() dequeues it
//   4. Thread should unblock within a reasonable timeout (500 ms)
//   5. If not, send another SIGTERM to force unblock
//
// Note: kill(getpid(), ...) is process-directed. sigwait() in the waiter thread
// dequeues it. This exercises the complete sigwait-based shutdown path.
void TestSignalHandlerSigwaitUnblock() {
    std::cout << "\n[TEST] SignalHandler: SIGTERM unblocks WaitForSignal..." << std::endl;
    try {
        SignalHandler::Install();

        std::atomic<bool> thread_unblocked{false};

        std::thread waiter([&]() {
            // Pass nullptr: we just want to verify the pipe read unblocks.
            // The CAS on g_shutdown_requested prevents a real Stop() call.
            SignalHandler::WaitForSignal(nullptr);
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
        std::string err = pass ? "" : "WaitForSignal did not unblock within 500ms after SIGTERM";

        // Always cleanup (safe to call again: guards against double-close)
        SignalHandler::Cleanup();

        // Restore SIGTERM to default so subsequent tests are not surprised
        signal(SIGTERM, SIG_DFL);

        TestFramework::RecordTest("SignalHandler: SIGTERM unblocks WaitForSignal",
                                  pass, err, CLI_CATEGORY);
    } catch (const std::exception& e) {
        SignalHandler::Cleanup();
        signal(SIGTERM, SIG_DFL);
        TestFramework::RecordTest("SignalHandler: SIGTERM unblocks WaitForSignal",
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
    TestParseInvalidSignalAction();
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
}

}  // namespace CliTests
