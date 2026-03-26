#include "cli/signal_handler.h"
#include "http/http_server.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

#include <signal.h>
#include <pthread.h>

// ── File-scope static state ──────────────────────────────────────

static std::atomic<bool> g_shutdown_requested{false};
static sigset_t g_block_mask;   // signals we block/wait on
static bool g_installed = false;

// ── Install ──────────────────────────────────────────────────────

void SignalHandler::Install() {
    sigemptyset(&g_block_mask);
    sigaddset(&g_block_mask, SIGTERM);
    sigaddset(&g_block_mask, SIGINT);
    sigaddset(&g_block_mask, SIGPIPE);

    // Block these signals in ALL threads (inherited by child threads).
    // Blocked signals are queued by the kernel and only delivered to sigwait().
    if (pthread_sigmask(SIG_BLOCK, &g_block_mask, nullptr) != 0) {
        throw std::runtime_error(
            std::string("Failed to block signals: ") + std::strerror(errno));
    }

    g_shutdown_requested.store(false);
    g_installed = true;
}

// ── WaitForSignal ────────────────────────────────────────────────

void SignalHandler::WaitForSignal(HttpServer* server) {
    // sigwait() synchronously dequeues a blocked signal. No async signal
    // handler, no pipe/eventfd, no shared fds. The call blocks until
    // SIGTERM or SIGINT is delivered to this process.
    int sig = 0;
    int ret = sigwait(&g_block_mask, &sig);

    if (ret == 0 && (sig == SIGTERM || sig == SIGINT)) {
        bool expected = false;
        if (g_shutdown_requested.compare_exchange_strong(expected, true)) {
            if (server) {
                server->Stop();
            }
        }
    }
}

bool SignalHandler::ShutdownRequested() {
    return g_shutdown_requested.load(std::memory_order_acquire);
}

// ── Cleanup ──────────────────────────────────────────────────────

void SignalHandler::Cleanup() {
    if (g_installed) {
        // Restore default dispositions so the process can be killed normally
        // after cleanup (e.g., if it hangs during shutdown).
        pthread_sigmask(SIG_UNBLOCK, &g_block_mask, nullptr);
        signal(SIGPIPE, SIG_IGN);  // keep SIGPIPE ignored
        g_installed = false;
    }
}
