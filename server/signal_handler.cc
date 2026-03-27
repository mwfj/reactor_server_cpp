#include "cli/signal_handler.h"

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
static bool g_was_cleaned_up = false;  // true after Cleanup() sets SIG_IGN

void SignalHandler::Install(bool daemon_mode) {
    sigemptyset(&g_block_mask);
    sigaddset(&g_block_mask, SIGTERM);
    sigaddset(&g_block_mask, SIGINT);
    sigaddset(&g_block_mask, SIGPIPE);
    sigaddset(&g_block_mask, SIGHUP);

    int rc = pthread_sigmask(SIG_BLOCK, &g_block_mask, nullptr);
    if (rc != 0) {
        throw std::runtime_error(
            std::string("Failed to block signals: ") + std::strerror(rc));
    }

    // On macOS/BSD, sigwait() cannot receive signals whose disposition is SIG_IGN —
    // the kernel discards them before they become pending. SIGTERM/SIGINT must
    // always be SIG_DFL so shutdown signals reach sigwait().
    // SIGHUP: in daemon mode, always reset (no terminal → inherited SIG_IGN is
    // meaningless and would break log rotation). In foreground, only undo our
    // own Cleanup()'s SIG_IGN — preserve nohup's inherited SIG_IGN.
    // Safe: signals are blocked, so SIG_DFL cannot fire.
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    if (daemon_mode || g_was_cleaned_up) {
        signal(SIGHUP, SIG_DFL);
        g_was_cleaned_up = false;
    }

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
        // sigwait failed — treat as shutdown for safety
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

void SignalHandler::Cleanup() {
    if (g_installed) {
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        pthread_sigmask(SIG_UNBLOCK, &g_block_mask, nullptr);
        g_installed = false;
        g_was_cleaned_up = true;
    }
}
