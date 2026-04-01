#include "cli/signal_handler.h"
#include "log/logger.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

#include <signal.h>
#include <pthread.h>

static std::atomic<bool> g_shutdown_requested{false};
static sigset_t g_block_mask;  // all signals we block (SIGTERM, SIGINT, SIGPIPE, SIGHUP)
static sigset_t g_wait_mask;   // signals we sigwait on (SIGTERM, SIGINT, SIGHUP)
static bool g_installed = false;
static bool g_was_cleaned_up = false;  // true after FOR_EXIT sets SIG_IGN

// Prior state saved by Install() for Cleanup(RESTORE)
static struct sigaction g_prev_sigterm;
static struct sigaction g_prev_sigint;
static struct sigaction g_prev_sigpipe;
static struct sigaction g_prev_sighup;
static sigset_t g_prev_mask;

// Helper: set a signal's disposition via sigaction.
static void SetDisposition(int sig, void (*handler)(int)) {
    struct sigaction sa{};
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, nullptr) != 0) {
        throw std::runtime_error(
            std::string("sigaction failed for signal ") +
            std::to_string(sig) + ": " + std::strerror(errno));
    }
}

void SignalHandler::Install(bool daemon_mode) {
    // Guard repeated Install() — don't overwrite saved prior state.
    if (g_installed) return;

    sigemptyset(&g_block_mask);
    sigaddset(&g_block_mask, SIGTERM);
    sigaddset(&g_block_mask, SIGINT);
    sigaddset(&g_block_mask, SIGPIPE);
    sigaddset(&g_block_mask, SIGHUP);

    // Save prior signal dispositions before we modify anything.
    sigaction(SIGTERM, nullptr, &g_prev_sigterm);
    sigaction(SIGINT,  nullptr, &g_prev_sigint);
    sigaction(SIGPIPE, nullptr, &g_prev_sigpipe);
    sigaction(SIGHUP,  nullptr, &g_prev_sighup);

    // Block signals and save prior thread mask.
    int rc = pthread_sigmask(SIG_BLOCK, &g_block_mask, &g_prev_mask);
    if (rc != 0) {
        throw std::runtime_error(
            std::string("Failed to block signals: ") + std::strerror(rc));
    }

    // On macOS/BSD, sigwait() cannot receive signals whose disposition is SIG_IGN —
    // the kernel discards them before they become pending. All waited signals must
    // be SIG_DFL so they reach sigwait(). Safe: signals are blocked, so SIG_DFL
    // cannot fire between here and sigwait().
    // SIGHUP: always reset, even if inherited as SIG_IGN from nohup. In daemon
    // mode, SIG_IGN would break SIGHUP-based config reload. In foreground mode,
    // SIG_IGN would silently swallow the terminal-hangup shutdown signal.
    SetDisposition(SIGTERM, SIG_DFL);
    SetDisposition(SIGINT, SIG_DFL);
    if (!daemon_mode && !g_was_cleaned_up &&
        g_prev_sighup.sa_handler == SIG_IGN) {
        // Overriding inherited SIG_IGN (e.g., nohup). Log so the operator
        // knows SIGHUP handling is active despite nohup.
        // Best-effort: logger may not be initialized yet.
        try {
            logging::Get()->info(
                "Overriding inherited SIGHUP SIG_IGN (nohup) — "
                "SIGHUP will trigger shutdown in foreground mode");
        } catch (...) {}
    }
    SetDisposition(SIGHUP, SIG_DFL);
    g_was_cleaned_up = false;

    sigemptyset(&g_wait_mask);
    sigaddset(&g_wait_mask, SIGTERM);
    sigaddset(&g_wait_mask, SIGINT);
    sigaddset(&g_wait_mask, SIGHUP);

    g_shutdown_requested.store(false);
    g_installed = true;
}

SignalResult SignalHandler::WaitForSignal() {
    int sig = 0;
    int rc = sigwait(&g_wait_mask, &sig);
    if (rc != 0) {
        // sigwait failed — treat as shutdown for safety.
        // Log is best-effort (logger may not be initialized in edge cases).
        try {
            logging::Get()->error("sigwait failed (rc={}), treating as shutdown",
                                  rc);
        } catch (...) {}
        g_shutdown_requested.store(true, std::memory_order_release);
        return SignalResult::SHUTDOWN;
    }

    if (sig == SIGHUP) {
        return SignalResult::RELOAD;
    }
    // SIGTERM or SIGINT
    g_shutdown_requested.store(true, std::memory_order_release);
    return SignalResult::SHUTDOWN;
}

void SignalHandler::WaitForShutdown() {
    // Loop until we get a shutdown signal (ignore SIGHUP in legacy path)
    while (true) {
        SignalResult result = WaitForSignal();
        if (result == SignalResult::SHUTDOWN) return;
        // RELOAD: no handler in legacy path, just loop
    }
}

bool SignalHandler::ShutdownRequested() {
    return g_shutdown_requested.load(std::memory_order_acquire);
}

void SignalHandler::MarkShutdownRequested() {
    g_shutdown_requested.store(true, std::memory_order_release);
}

void SignalHandler::Cleanup(CleanupMode mode) {
    if (!g_installed) return;

    if (mode == CleanupMode::FOR_EXIT) {
        // Set SIG_IGN before unblocking — prevents pending signals from killing
        // the process between Cleanup and exit().
        SetDisposition(SIGTERM, SIG_IGN);
        SetDisposition(SIGINT, SIG_IGN);
        SetDisposition(SIGPIPE, SIG_IGN);
        SetDisposition(SIGHUP, SIG_IGN);
        pthread_sigmask(SIG_UNBLOCK, &g_block_mask, nullptr);
        g_installed = false;
        g_was_cleaned_up = true;
    } else {
        // RESTORE: drain pending signals, restore saved dispositions + mask.
        // Keep signals blocked during the entire transition to prevent a
        // pending signal from firing with SIG_DFL before the previous
        // handler is restored.
        pthread_sigmask(SIG_BLOCK, &g_block_mask, nullptr);

        // Drain pending signals so they don't fire after restore.
#if defined(__linux__)
        struct timespec zero_timeout = {0, 0};
        while (sigtimedwait(&g_block_mask, nullptr, &zero_timeout) > 0) {}
#else
        // macOS/BSD: sigtimedwait doesn't exist. Use sigpending + sigwait loop.
        sigset_t pending;
        while (sigpending(&pending) == 0) {
            bool any = sigismember(&pending, SIGTERM) ||
                       sigismember(&pending, SIGINT) ||
                       sigismember(&pending, SIGPIPE) ||
                       sigismember(&pending, SIGHUP);
            if (!any) break;
            int sig;
            sigwait(&g_block_mask, &sig);
        }
#endif

        // Restore all saved dispositions including SIGPIPE. Embedders that
        // had a custom SIGPIPE handler before Install() expect it back.
        // NetServer uses call_once for SIGPIPE=SIG_IGN, so a new NetServer
        // after RESTORE won't re-set it — but that's the embedder's
        // responsibility if they choose to Cleanup(RESTORE) then create
        // new servers.
        sigaction(SIGTERM, &g_prev_sigterm, nullptr);
        sigaction(SIGINT,  &g_prev_sigint,  nullptr);
        sigaction(SIGPIPE, &g_prev_sigpipe, nullptr);
        sigaction(SIGHUP,  &g_prev_sighup,  nullptr);

        // Restore previous thread signal mask
        pthread_sigmask(SIG_SETMASK, &g_prev_mask, nullptr);

        g_installed = false;
        g_was_cleaned_up = false;  // state is clean, no undo needed
    }
}
