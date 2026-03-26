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

void SignalHandler::Install() {
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

    // Restore default dispositions now that signals are blocked.
    // On macOS/BSD, sigwait() cannot receive signals whose disposition is SIG_IGN —
    // the kernel discards them before they become pending. Cleanup() sets SIG_IGN
    // before unblocking, so a subsequent Install() must reset to SIG_DFL.
    // Safe: signals are blocked, so default action (terminate) cannot fire.
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);

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

void SignalHandler::Cleanup() {
    if (g_installed) {
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        pthread_sigmask(SIG_UNBLOCK, &g_block_mask, nullptr);
        g_installed = false;
    }
}
