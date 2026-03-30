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

// Cleanup mode determines how signal state is restored.
enum class CleanupMode {
    // Set SIG_IGN + unblock. Safe for process exit — prevents pending signals
    // from killing the process between Cleanup and exit(). Terminal: do NOT
    // expect a later RESTORE call to recover the original pre-Install() state.
    FOR_EXIT,

    // Restore prior signal dispositions and thread signal mask saved by
    // Install(). Clean state for tests, embedders, and library-style reuse.
    // Must be called on the same thread that called Install(), after all
    // waiter/worker threads are joined.
    RESTORE,
};

class SignalHandler {
public:
    // Block SIGTERM, SIGINT, SIGPIPE, SIGHUP in all threads via pthread_sigmask.
    // Saves prior signal dispositions and thread mask for Cleanup(RESTORE).
    // Must be called from the main thread before spawning any threads.
    // No-op if already installed (prevents overwriting saved prior state).
    // @param daemon_mode  If true, SIGHUP is always reset to SIG_DFL even if
    //                     inherited as SIG_IGN (nohup). A daemon has no terminal,
    //                     so inherited SIG_IGN is meaningless and would silently
    //                     break SIGHUP-based log rotation.
    static void Install(bool daemon_mode = false);

    // Wait for the next actionable signal via sigwait().
    // Returns SHUTDOWN for SIGTERM/SIGINT, RELOAD for SIGHUP.
    // Caller loops: on RELOAD, handle and re-call. On SHUTDOWN, teardown.
    static SignalResult WaitForSignal();

    // Synchronously wait for SIGTERM or SIGINT via sigwait().
    // Blocks until a shutdown signal is delivered. SIGHUP is silently ignored.
    // Kept for backward compatibility with tests and legacy callers.
    static void WaitForShutdown();

    // Restore signal state based on the cleanup mode.
    // @param mode  FOR_EXIT: set SIG_IGN + unblock (safe for process exit).
    //              RESTORE: drain pending signals, restore prior dispositions
    //              and thread signal mask saved by Install(). Must be called
    //              on the same thread that called Install(), after all
    //              waiter/worker threads are joined.
    // Safe to call multiple times. No-op if not installed.
    static void Cleanup(CleanupMode mode);

    // Returns true if a shutdown signal has been received.
    static bool ShutdownRequested();

    // Mark shutdown as requested. Used when the caller decides to shut down
    // based on a RELOAD signal (foreground SIGHUP = terminal hangup).
    static void MarkShutdownRequested();

    SignalHandler() = delete;
};
