#include "upstream/upstream_connection.h"
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
        // No events — socket is healthy and idle
        return true;
    }

    // Events detected on an idle connection — not expected
    if (pfd.revents & (POLLHUP | POLLERR)) {
        logging::Get()->debug("UpstreamConnection fd={} dead (POLLHUP/POLLERR)",
                              conn_fd);
        return false;
    }
    if (pfd.revents & POLLIN) {
        // For TLS connections, POLLIN on idle is often benign: TLS 1.3 servers
        // send post-handshake records (NewSessionTicket) on keep-alive sockets.
        // Destroying these connections defeats connection reuse for HTTPS pools.
        // The SSL layer will handle the data on next use.
        if (conn_ && conn_->HasTls()) {
            return true;
        }
        // For raw TCP: unexpected data on idle — likely RST or half-close
        logging::Get()->debug("UpstreamConnection fd={} unexpected POLLIN "
                              "while idle", conn_fd);
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
