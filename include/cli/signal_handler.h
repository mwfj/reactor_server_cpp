#pragma once

// Shutdown signal handling using sigwait (no self-pipe, no shared fds).
//
// Design: Install() blocks SIGTERM/SIGINT/SIGPIPE in ALL threads via
// pthread_sigmask. WaitForShutdown() calls sigwait() which synchronously
// dequeues a blocked signal — no async signal handler, no pipe/eventfd,
// no fd sharing between threads.
class SignalHandler {
public:
    // Block SIGTERM, SIGINT, SIGPIPE in all threads via pthread_sigmask.
    // Must be called from the main thread before spawning any threads.
    static void Install();

    // Synchronously wait for SIGTERM or SIGINT via sigwait().
    // Blocks until a shutdown signal is delivered. Caller handles Stop().
    static void WaitForShutdown();

    // Ignore and unblock shutdown signals for clean teardown. Safe to call multiple times.
    static void Cleanup();

    // Returns true if a shutdown signal has been received.
    static bool ShutdownRequested();

    SignalHandler() = delete;
};
