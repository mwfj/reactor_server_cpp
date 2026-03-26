#include "cli/signal_handler.h"
#include "http/http_server.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <poll.h>

#if defined(__linux__)
#include <sys/eventfd.h>
#endif

// ── File-scope static state ──────────────────────────────────────
// Signal handlers are C function pointers that cannot capture state,
// so the pipe fds must be module-level.

#if defined(__linux__)
static int g_signal_eventfd = -1;
#else
static int g_signal_pipe[2] = {-1, -1};
#endif

static std::atomic<bool> g_shutdown_requested{false};

// ── Signal handler (async-signal-safe) ───────────────────────────

void SignalHandler::HandleSignal(int /*signum*/) {
    // ONLY write() is called here — it is on the POSIX async-signal-safe list.
    // Return value intentionally ignored: if the pipe is full, one wakeup is enough.
#if defined(__linux__)
    uint64_t val = 1;
    (void)write(g_signal_eventfd, &val, sizeof(val));
#else
    char c = 1;
    (void)write(g_signal_pipe[1], &c, 1);
#endif
}

// ── Install ──────────────────────────────────────────────────────

void SignalHandler::Install() {
    // 1. Create self-pipe / eventfd
#if defined(__linux__)
    g_signal_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (g_signal_eventfd < 0) {
        throw std::runtime_error(
            std::string("Failed to create signal eventfd: ") + std::strerror(errno));
    }
#else
    if (pipe(g_signal_pipe) != 0) {
        throw std::runtime_error(
            std::string("Failed to create signal pipe: ") + std::strerror(errno));
    }
    // Set both ends non-blocking + close-on-exec
    for (int i = 0; i < 2; ++i) {
        int flags = fcntl(g_signal_pipe[i], F_GETFL, 0);
        if (flags == -1 ||
            fcntl(g_signal_pipe[i], F_SETFL, flags | O_NONBLOCK) == -1 ||
            fcntl(g_signal_pipe[i], F_SETFD, FD_CLOEXEC) == -1) {
            close(g_signal_pipe[0]);
            close(g_signal_pipe[1]);
            g_signal_pipe[0] = g_signal_pipe[1] = -1;
            throw std::runtime_error(
                std::string("Failed to configure signal pipe: ") + std::strerror(errno));
        }
    }
#endif

    // 2. Install signal handlers
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = HandleSignal;
    sa.sa_flags = SA_RESTART;  // restart interrupted system calls
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, nullptr) != 0 ||
        sigaction(SIGINT, &sa, nullptr) != 0) {
        Cleanup();
        throw std::runtime_error(
            std::string("Failed to install signal handlers: ") + std::strerror(errno));
    }

    // 3. Ignore SIGPIPE (already handled by MSG_NOSIGNAL on Linux,
    //    but explicit ignore is a safety net)
    signal(SIGPIPE, SIG_IGN);

    // Reset shutdown flag
    g_shutdown_requested.store(false);
}

// ── WaitForSignal ────────────────────────────────────────────────

void SignalHandler::WaitForSignal(HttpServer* server) {
    bool received_signal = false;

#if defined(__linux__)
    uint64_t val;
    while (true) {
        // Snapshot the fd — Cleanup() may close it concurrently.
        int fd = g_signal_eventfd;
        if (fd < 0) break;

        ssize_t n = read(fd, &val, sizeof(val));
        if (n == static_cast<ssize_t>(sizeof(val))) {
            received_signal = true;
            break;
        }
        if (n == -1 && errno == EINTR) continue;
        if (n == -1 && errno == EAGAIN) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            int ret = poll(&pfd, 1, 500);  // 500ms timeout to recheck fd validity
            if (ret < 0 && errno == EINTR) continue;
            if (ret == 0) continue;  // timeout — recheck g_signal_eventfd
            if (ret < 0) break;
            // Check for POLLNVAL — fd was closed by Cleanup()
            if (pfd.revents & POLLNVAL) break;
            continue;
        }
        break;  // read error or EBADF from closed fd
    }
#else
    char buf[16];
    while (true) {
        int fd = g_signal_pipe[0];
        if (fd < 0) break;

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            received_signal = true;
            break;
        }
        if (n == 0) break;  // pipe closed (Cleanup called)
        if (n == -1 && errno == EINTR) continue;
        if (n == -1 && errno == EAGAIN) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            int ret = poll(&pfd, 1, 500);
            if (ret < 0 && errno == EINTR) continue;
            if (ret == 0) continue;
            if (ret < 0) break;
            if (pfd.revents & POLLNVAL) break;
            continue;
        }
        break;
    }
#endif

    // Only call Stop() if a real signal arrived (not pipe closed by Cleanup)
    if (received_signal) {
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
#if defined(__linux__)
    if (g_signal_eventfd >= 0) {
        close(g_signal_eventfd);
        g_signal_eventfd = -1;
    }
#else
    if (g_signal_pipe[0] >= 0) {
        close(g_signal_pipe[0]);
        g_signal_pipe[0] = -1;
    }
    if (g_signal_pipe[1] >= 0) {
        close(g_signal_pipe[1]);
        g_signal_pipe[1] = -1;
    }
#endif
}
