#include "upstream/upstream_connection.h"
#include "tls/tls_connection.h"
#include "log/logger.h"
#include <poll.h>

UpstreamConnection::UpstreamConnection(
    std::shared_ptr<ConnectionHandler> conn,
    const std::string& host, int port)
    : conn_(std::move(conn))
    , upstream_host_(host)
    , upstream_port_(port)
    , created_at_(std::chrono::steady_clock::now())
    , last_used_at_(created_at_)
{
    logging::Get()->debug("UpstreamConnection created fd={} to {}:{}",
                          fd(), host, port);
}

UpstreamConnection::~UpstreamConnection() {
    logging::Get()->debug("UpstreamConnection destroyed fd={} {}:{} "
                          "requests={}", fd(), upstream_host_,
                          upstream_port_, request_count_);
}

int UpstreamConnection::fd() const {
    return conn_ ? conn_->fd() : -1;
}

void UpstreamConnection::MarkInUse() {
    state_ = State::IN_USE;
    last_used_at_ = std::chrono::steady_clock::now();
}

void UpstreamConnection::MarkIdle() {
    state_ = State::READY;
    last_used_at_ = std::chrono::steady_clock::now();
}

void UpstreamConnection::MarkClosing() {
    state_ = State::CLOSING;
}

void UpstreamConnection::IncrementRequestCount() {
    ++request_count_;
}

void UpstreamConnection::IncReadDisable() {
    int previous = read_disable_count_.fetch_add(1, std::memory_order_acq_rel);
    if (previous == 0 && conn_) {
        conn_->DisableReadMode();
    }
}

void UpstreamConnection::DecReadDisable() {
    int current = read_disable_count_.load(std::memory_order_acquire);
    if (current <= 0) {
        logging::Get()->warn(
            "UpstreamConnection read-disable underflow fd={} host={}:{} count={}",
            fd(), upstream_host_, upstream_port_, current);
        return;
    }
    while (current > 0) {
        if (read_disable_count_.compare_exchange_weak(
                current, current - 1,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            if (current == 1 && conn_) {
                conn_->EnableReadMode();
            }
            return;
        }
    }
    logging::Get()->warn(
        "UpstreamConnection read-disable underflow raced to zero fd={} host={}:{}",
        fd(), upstream_host_, upstream_port_);
}

bool UpstreamConnection::IsAlive() const {
    int conn_fd = fd();
    if (conn_fd < 0) return false;

    // Non-blocking poll to detect dead connections.
    // POLLHUP/POLLERR = connection is dead.
    // POLLIN on an idle connection = unexpected data (RST, half-close).
    struct pollfd pfd;
    pfd.fd = conn_fd;
    pfd.events = POLLIN | POLLHUP | POLLERR;
    pfd.revents = 0;

    int ret = ::poll(&pfd, 1, 0);
    if (ret < 0) {
        // poll() error — EINTR is retryable but for a 0-timeout poll
        // it's extremely unlikely. Treat as dead to be safe.
        if (errno == EINTR) return true;  // transient, assume alive
        return false;
    }
    if (ret == 0) {
        // No kernel-level events. For TLS connections, also check OpenSSL's
        // internal buffer — it can hold unread application bytes from a
        // previous response even when poll() sees no POLLIN (the kernel
        // buffer was already drained into SSL's buffer). Reusing such a
        // connection would corrupt the next request with stale bytes.
        if (conn_ && conn_->IsTlsReady()) {
            char peek_buf[1];
            int peek_result = conn_->TlsPeek(peek_buf, sizeof(peek_buf));
            if (peek_result > 0) {
                // Application data buffered — stale bytes from previous response
                logging::Get()->debug("UpstreamConnection fd={} has buffered TLS "
                                      "data, marking non-reusable", conn_fd);
                return false;
            }
            // TLS_COMPLETE = no app data, TLS_ERROR/TLS_PEER_CLOSED = dead
            if (peek_result != TlsConnection::TLS_COMPLETE) {
                return false;
            }
        }
        return true;
    }

    // Events detected on an idle connection — not expected
    if (pfd.revents & (POLLHUP | POLLERR)) {
        logging::Get()->debug("UpstreamConnection fd={} dead (POLLHUP/POLLERR)",
                              conn_fd);
        return false;
    }
    if (pfd.revents & POLLIN) {
        // For TLS connections, POLLIN may be a benign post-handshake record
        // (e.g., TLS 1.3 NewSessionTicket). Use SSL_peek to distinguish:
        // - TLS_COMPLETE (WANT_READ): benign record consumed internally → alive
        // - >0: stale application data buffered → not reusable
        // - TLS_PEER_CLOSED / TLS_ERROR: close_notify or error → dead
        if (conn_ && conn_->IsTlsReady()) {
            char peek_buf[1];
            int peek_result = conn_->TlsPeek(peek_buf, sizeof(peek_buf));
            if (peek_result == TlsConnection::TLS_COMPLETE) {
                // Benign TLS record consumed (e.g., NewSessionTicket) — still alive
                return true;
            }
            logging::Get()->debug("UpstreamConnection fd={} TLS peek returned {}, "
                                  "marking non-reusable", conn_fd, peek_result);
            return false;
        }
        // For raw TCP: unexpected data on idle — likely RST or half-close
        logging::Get()->debug("UpstreamConnection fd={} POLLIN while idle, "
                              "marking non-reusable", conn_fd);
        return false;
    }

    return true;
}

bool UpstreamConnection::IsExpired(int max_lifetime_sec,
                                    int max_requests_per_conn) const {
    auto now = std::chrono::steady_clock::now();

    // Check max lifetime (0 = unlimited)
    if (max_lifetime_sec > 0) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - created_at_);
        if (age.count() >= max_lifetime_sec) {
            return true;
        }
    }

    // Check max requests per connection (0 = unlimited)
    if (max_requests_per_conn > 0 &&
        static_cast<int>(request_count_) >= max_requests_per_conn) {
        return true;
    }

    return false;
}
