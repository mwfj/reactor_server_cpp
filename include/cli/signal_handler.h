#pragma once

// Shutdown and reload signal handling using sigwait (no self-pipe, no shared fds).
//
// Design: Install() blocks SIGTERM/SIGINT/SIGPIPE/SIGHUP in ALL threads via
// pthread_sigmask. WaitForSignal() calls sigwait() which synchronously
// dequeues a blocked signal — no async signal handler, no pipe/eventfd,
// no fd sharing between threads.
//
// SIGHUP triggers log file rotation (RELOAD), not shutdown.
// SIGTERM/SIGINT trigger graceful shutdown (SHUTDOWN).

// Return value from WaitForSignal() indicating which signal category was received.
enum class SignalResult {
    SHUTDOWN,   // SIGTERM or SIGINT — caller should stop the server
    RELOAD,     // SIGHUP — caller decides: daemon reopens logs, foreground shuts down
};

class SignalHandler {
public:
    // Block SIGTERM, SIGINT, SIGPIPE, SIGHUP in all threads via pthread_sigmask.
    // Must be called from the main thread before spawning any threads.
    static void Install();

    // Wait for the next actionable signal via sigwait().
    // Returns SHUTDOWN for SIGTERM/SIGINT, RELOAD for SIGHUP.
    // Caller loops: on RELOAD, handle and re-call. On SHUTDOWN, teardown.
    static SignalResult WaitForSignal();

    // Synchronously wait for SIGTERM or SIGINT via sigwait().
    // Blocks until a shutdown signal is delivered. SIGHUP is silently ignored.
    // Kept for backward compatibility with tests and legacy callers.
    static void WaitForShutdown();

    // Ignore and unblock all handled signals for clean teardown.
    // Safe to call multiple times.
    static void Cleanup();

    // Returns true if a shutdown signal has been received.
    static bool ShutdownRequested();

    SignalHandler() = delete;
};
