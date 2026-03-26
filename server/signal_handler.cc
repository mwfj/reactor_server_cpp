#include "cli/signal_handler.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

#include <signal.h>
#include <pthread.h>

static std::atomic<bool> g_shutdown_requested{false};
static sigset_t g_block_mask;     // all signals we block (SIGTERM, SIGINT, SIGPIPE)
static sigset_t g_shutdown_mask;  // only shutdown signals we sigwait on (SIGTERM, SIGINT)
static bool g_installed = false;

void SignalHandler::Install() {
    sigemptyset(&g_block_mask);
    sigaddset(&g_block_mask, SIGTERM);
    sigaddset(&g_block_mask, SIGINT);
    sigaddset(&g_block_mask, SIGPIPE);

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

    sigemptyset(&g_shutdown_mask);
    sigaddset(&g_shutdown_mask, SIGTERM);
    sigaddset(&g_shutdown_mask, SIGINT);

    g_shutdown_requested.store(false);
    g_installed = true;
}

void SignalHandler::WaitForShutdown() {
    int sig = 0;
    sigwait(&g_shutdown_mask, &sig);

    if (sig == SIGTERM || sig == SIGINT) {
        g_shutdown_requested.store(true, std::memory_order_release);
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
        pthread_sigmask(SIG_UNBLOCK, &g_block_mask, nullptr);
        g_installed = false;
    }
}
