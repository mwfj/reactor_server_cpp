#pragma once

class HttpServer;  // forward declaration

class SignalHandler {
public:
    // Install signal handlers for SIGTERM, SIGINT; ignore SIGPIPE.
    // Creates the self-pipe/eventfd internally.
    // Must be called from the main thread before spawning any threads.
    // Throws std::runtime_error if pipe/eventfd creation fails.
    static void Install();

    // Block until a shutdown signal is received, then call server.Stop().
    // Intended to run on a dedicated thread.
    // Returns when the signal is received and Stop() completes,
    // or when Cleanup() closes the pipe (for error-path unblocking).
    static void WaitForSignal(HttpServer* server);

    // Clean up the self-pipe/eventfd file descriptors.
    // Also unblocks WaitForSignal if it's still blocking.
    static void Cleanup();

    // Returns true if a shutdown signal has been received and processed.
    static bool ShutdownRequested();

    // Notify that the server is started and Stop() is safe to call.
    // Must be called from main thread right before HttpServer::Start().
    static void NotifyServerStarted();

    SignalHandler() = delete;

private:
    // Async-signal-safe signal handler — only writes to the self-pipe.
    static void HandleSignal(int signum);
};
