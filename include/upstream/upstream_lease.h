#pragma once

// Forward declarations — no heavy includes needed for this lightweight RAII handle
class UpstreamConnection;
class PoolPartition;

// Lightweight move-only RAII handle for a checked-out upstream connection.
// The pool always retains ownership of the UpstreamConnection. This handle
// holds a raw pointer and auto-returns the connection on destruction.
//
// Thread safety: must only be used and destroyed on the dispatcher thread
// that issued the checkout. If the lease must be destroyed on another thread,
// call Release() explicitly first or route through EnQueue.
class UpstreamLease {
public:
    UpstreamLease() = default;

    UpstreamLease(UpstreamConnection* conn, PoolPartition* partition)
        : conn_(conn), partition_(partition) {}

    ~UpstreamLease();  // Out-of-line: calls PoolPartition::ReturnConnection

    // Move-only (exactly one return per checkout)
    UpstreamLease(UpstreamLease&& other) noexcept
        : conn_(other.conn_), partition_(other.partition_) {
        other.conn_ = nullptr;
        other.partition_ = nullptr;
    }

    UpstreamLease& operator=(UpstreamLease&& other) noexcept {
        if (this != &other) {
            Release();
            conn_ = other.conn_;
            partition_ = other.partition_;
            other.conn_ = nullptr;
            other.partition_ = nullptr;
        }
        return *this;
    }

    UpstreamLease(const UpstreamLease&) = delete;
    UpstreamLease& operator=(const UpstreamLease&) = delete;

    // Access the underlying connection (nullptr if empty/released)
    UpstreamConnection* Get() const { return conn_; }
    UpstreamConnection* operator->() const { return conn_; }
    explicit operator bool() const { return conn_ != nullptr; }

    // Explicit release — returns connection to pool early (before destruction)
    void Release();

private:
    UpstreamConnection* conn_ = nullptr;
    PoolPartition* partition_ = nullptr;
};
