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
// std::atomic<int> for the fds: accessed from signal handler, waiter
// thread, and Cleanup(). Atomics eliminate the data race on the fd
// values themselves. The signal handler uses relaxed load which
// compiles to a plain load on all relevant architectures.

#if defined(__linux__)
static std::atomic<int> g_signal_fd{-1};
#else
static std::atomic<int> g_signal_read_fd{-1};
static std::atomic<int> g_signal_write_fd{-1};
#endif

static std::atomic<bool> g_shutdown_requested{false};

// ── Signal handler (async-signal-safe) ───────────────────────────

void SignalHandler::HandleSignal(int /*signum*/) {
    // ONLY write() is called here — it is on the POSIX async-signal-safe list.
    // Return value intentionally ignored: if the pipe is full, one wakeup is enough.
    // relaxed load: compiles to a plain load, safe in signal context.
#if defined(__linux__)
    int fd = g_signal_fd.load(std::memory_order_relaxed);
    if (fd >= 0) {
        uint64_t val = 1;
        (void)write(fd, &val, sizeof(val));
    }
#else
    int fd = g_signal_write_fd.load(std::memory_order_relaxed);
    if (fd >= 0) {
        char c = 1;
        (void)write(fd, &c, 1);
    }
#endif
}

// ── Install ──────────────────────────────────────────────────────

void SignalHandler::Install() {
#if defined(__linux__)
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) {
        throw std::runtime_error(
            std::string("Failed to create signal eventfd: ") + std::strerror(errno));
    }
    g_signal_fd.store(fd, std::memory_order_release);
#else
    int pfd[2];
    if (pipe(pfd) != 0) {
        throw std::runtime_error(
            std::string("Failed to create signal pipe: ") + std::strerror(errno));
    }
    for (int i = 0; i < 2; ++i) {
        int flags = fcntl(pfd[i], F_GETFL, 0);
        if (flags == -1 ||
            fcntl(pfd[i], F_SETFL, flags | O_NONBLOCK) == -1 ||
            fcntl(pfd[i], F_SETFD, FD_CLOEXEC) == -1) {
            close(pfd[0]);
            close(pfd[1]);
            throw std::runtime_error(
                std::string("Failed to configure signal pipe: ") + std::strerror(errno));
        }
    }
    g_signal_read_fd.store(pfd[0], std::memory_order_release);
    g_signal_write_fd.store(pfd[1], std::memory_order_release);
#endif

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = HandleSignal;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, nullptr) != 0 ||
        sigaction(SIGINT, &sa, nullptr) != 0) {
        Cleanup();
        throw std::runtime_error(
            std::string("Failed to install signal handlers: ") + std::strerror(errno));
    }

    signal(SIGPIPE, SIG_IGN);
    g_shutdown_requested.store(false);
}

// ── WaitForSignal ────────────────────────────────────────────────

void SignalHandler::WaitForSignal(HttpServer* server) {
    bool received_signal = false;

#if defined(__linux__)
    uint64_t val;
    while (true) {
        int fd = g_signal_fd.load(std::memory_order_acquire);
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
            int ret = poll(&pfd, 1, 500);
            if (ret < 0 && errno == EINTR) continue;
            if (ret == 0) continue;
            if (ret < 0) break;
            if (pfd.revents & POLLNVAL) break;
            continue;
        }
        break;
    }
#else
    char buf[16];
    while (true) {
        int fd = g_signal_read_fd.load(std::memory_order_acquire);
        if (fd < 0) break;

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            received_signal = true;
            break;
        }
        if (n == 0) break;
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
    int fd = g_signal_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd >= 0) close(fd);
#else
    int rfd = g_signal_read_fd.exchange(-1, std::memory_order_acq_rel);
    if (rfd >= 0) close(rfd);
    int wfd = g_signal_write_fd.exchange(-1, std::memory_order_acq_rel);
    if (wfd >= 0) close(wfd);
#endif
}
