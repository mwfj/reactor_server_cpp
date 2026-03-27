#pragma once

// Double-fork daemon mode for Unix systems (Linux, macOS/BSD).
//
// Daemonize() detaches the process from the controlling terminal via the
// standard double-fork pattern: fork → setsid → fork → redirect stdio.
// After return, the caller is the grandchild (daemon) process.
//
// The parent waits for a readiness signal from the grandchild via a pipe.
// The caller MUST call NotifyReady() after successful startup, or
// NotifyFailed() on failure, so the parent can exit with the correct code.
//
// Not available on Windows — guarded by #if !defined(_WIN32).

#if !defined(_WIN32)

class Daemonizer {
public:
    // Execute the double-fork daemon sequence.
    // On success, returns in the grandchild process (session leader's child).
    // On failure, prints error to stderr and calls _exit(1).
    // The parent blocks on a readiness pipe until NotifyReady/NotifyFailed.
    //
    // After this call:
    //   - stdin/stdout/stderr point to /dev/null
    //   - CWD is "/"
    //   - umask is 027 (owner rwx, group r-x, other ---)
    //   - Process is not a session leader (cannot acquire terminal)
    //   - getpid() returns the daemon PID
    //
    // MUST be called:
    //   - AFTER getopt_long parsing (global state doesn't survive fork well)
    //   - AFTER config loading/validation (errors go to parent's stderr)
    //   - BEFORE PidFile::Acquire (PID file needs daemon PID)
    //   - BEFORE logging::Init (spdlog fds must belong to daemon)
    //   - BEFORE SignalHandler::Install (signal masks per-process)
    //   - BEFORE any thread creation
    static void Daemonize();

    // Signal the parent that the daemon started successfully.
    // Parent exits with code 0. Must be called exactly once after startup.
    static void NotifyReady();

    // Signal the parent that the daemon failed to start.
    // Parent exits with code 1. Must be called on startup failure.
    static void NotifyFailed();

    Daemonizer() = delete;
};

#endif // !defined(_WIN32)
