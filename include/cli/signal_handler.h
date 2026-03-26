#pragma once

class HttpServer;  // forward declaration

// Async-signal-safe shutdown using sigwait (no self-pipe, no shared fds).
//
// Design: Install() blocks SIGTERM/SIGINT/SIGPIPE in ALL threads via
// pthread_sigmask. WaitForSignal() calls sigwait() which synchronously
// dequeues a blocked signal — no async signal handler, no pipe/eventfd,
// no fd sharing between threads. This eliminates UB from concurrent fd
// access and avoids the Stop()/Start() race: Stop() only runs after
// sigwait() returns, and signals are only delivered to sigwait().
class SignalHandler {
public:
    // Block SIGTERM, SIGINT, SIGPIPE in all threads via pthread_sigmask.
    // Must be called from the main thread before spawning any threads.
    static void Install();

    // Synchronously wait for SIGTERM or SIGINT via sigwait(), then call
    // server.Stop(). Intended to run on a dedicated thread.
    static void WaitForSignal(HttpServer* server);

    // Ignore and unblock shutdown signals for clean teardown. Safe to call multiple times.
    static void Cleanup();

    // Returns true if a shutdown signal has been received.
    static bool ShutdownRequested();

    SignalHandler() = delete;
};
