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
static sigset_t g_block_mask;     // all signals we block (SIGTERM, SIGINT, SIGPIPE)
static sigset_t g_shutdown_mask;  // only shutdown signals we sigwait on (SIGTERM, SIGINT)
static bool g_installed = false;

// ── Install ──────────────────────────────────────────────────────

void SignalHandler::Install() {
    // Block SIGTERM, SIGINT, SIGPIPE in all threads.
    sigemptyset(&g_block_mask);
    sigaddset(&g_block_mask, SIGTERM);
    sigaddset(&g_block_mask, SIGINT);
    sigaddset(&g_block_mask, SIGPIPE);

    int rc = pthread_sigmask(SIG_BLOCK, &g_block_mask, nullptr);
    if (rc != 0) {
        throw std::runtime_error(
            std::string("Failed to block signals: ") + std::strerror(rc));
    }

    // Only wait on shutdown signals — SIGPIPE is blocked but not waited on.
    sigemptyset(&g_shutdown_mask);
    sigaddset(&g_shutdown_mask, SIGTERM);
    sigaddset(&g_shutdown_mask, SIGINT);

    g_shutdown_requested.store(false);
    g_installed = true;
}

// ── WaitForSignal ────────────────────────────────────────────────

void SignalHandler::WaitForSignal(HttpServer* server) {
    int sig = 0;
    int ret = sigwait(&g_shutdown_mask, &sig);

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
        // Ignore shutdown signals BEFORE unblocking. Any pending SIGTERM/SIGINT
        // (e.g., repeated Ctrl+C, supervisor retry) is harmlessly discarded
        // instead of killing the process mid-cleanup with default SIG_DFL.
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        pthread_sigmask(SIG_UNBLOCK, &g_block_mask, nullptr);
        g_installed = false;
    }
}
