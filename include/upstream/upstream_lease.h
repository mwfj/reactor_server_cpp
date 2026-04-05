#pragma once

#include <atomic>
#include <memory>

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
//
// Partition lifetime: the lease keeps a shared_ptr copy of PoolPartition's
// `alive_` flag. If the partition is destroyed before this lease is released
// (e.g. standalone UpstreamManager::~UpstreamManager runs with an outstanding
// lease), Release()/the destructor detect `alive=false` and skip the
// ReturnConnection call — avoiding a use-after-free on the freed partition.
class UpstreamLease {
public:
    UpstreamLease() = default;

    UpstreamLease(UpstreamConnection* conn, PoolPartition* partition,
                  std::shared_ptr<std::atomic<bool>> alive)
        : conn_(conn), partition_(partition), alive_(std::move(alive)) {}

    ~UpstreamLease();  // Out-of-line: calls PoolPartition::ReturnConnection

    // Move-only (exactly one return per checkout)
    UpstreamLease(UpstreamLease&& other) noexcept
        : conn_(other.conn_),
          partition_(other.partition_),
          alive_(std::move(other.alive_)) {
        other.conn_ = nullptr;
        other.partition_ = nullptr;
    }

    UpstreamLease& operator=(UpstreamLease&& other) noexcept {
        if (this != &other) {
            Release();
            conn_ = other.conn_;
            partition_ = other.partition_;
            alive_ = std::move(other.alive_);
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
    // Copy of PoolPartition::alive_. Set to false in ~PoolPartition BEFORE
    // any partition member is freed. Checked in Release() to detect whether
    // the partition is still reachable.
    std::shared_ptr<std::atomic<bool>> alive_;
};
