#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

class UpstreamConnection;
class UpstreamH2Connection;
class UpstreamH2Stream;
class PoolPartition;

// Move-only RAII handle for a checked-out upstream resource. Two flavors:
//
//   Kind::H1 — owns a transport (`UpstreamConnection*`) for a single
//              request/response. Release calls `ReturnConnection`.
//   Kind::H2 — owns a stream slot on a multiplexed session
//              (`UpstreamH2Connection*` + nghttp2 stream_id). Release calls
//              `ReturnH2Stream`. Carries TWO alive tokens (partition + conn)
//              because the H2 conn can be destroyed under the lease while
//              the partition is still alive (DestroyOnDispatcher).
//
// Dispatcher-thread-only — construction, use, destruction all run on the
// dispatcher that issued the checkout. Cross-thread destruction must
// Release() explicitly on the dispatcher first.
class UpstreamLease {
public:
    enum class Kind { EMPTY, H1, H2 };

    UpstreamLease() = default;

    UpstreamLease(UpstreamConnection* conn, PoolPartition* partition,
                  std::shared_ptr<std::atomic<bool>> partition_alive)
        : kind_(Kind::H1),
          conn_(conn),
          partition_(partition),
          partition_alive_(std::move(partition_alive)) {}

    UpstreamLease(UpstreamH2Connection* h2_conn, int32_t stream_id,
                  PoolPartition* partition,
                  std::shared_ptr<std::atomic<bool>> partition_alive,
                  std::shared_ptr<std::atomic<bool>> conn_alive)
        : kind_(Kind::H2),
          h2_conn_(h2_conn),
          h2_stream_id_(stream_id),
          partition_(partition),
          partition_alive_(std::move(partition_alive)),
          conn_alive_(std::move(conn_alive)) {}

    ~UpstreamLease();

    UpstreamLease(UpstreamLease&& other) noexcept
        : kind_(other.kind_),
          conn_(other.conn_),
          h2_conn_(other.h2_conn_),
          h2_stream_id_(other.h2_stream_id_),
          partition_(other.partition_),
          partition_alive_(std::move(other.partition_alive_)),
          conn_alive_(std::move(other.conn_alive_)) {
        other.kind_ = Kind::EMPTY;
        other.conn_ = nullptr;
        other.h2_conn_ = nullptr;
        other.h2_stream_id_ = -1;
        other.partition_ = nullptr;
    }

    UpstreamLease& operator=(UpstreamLease&& other) noexcept {
        if (this != &other) {
            Release();
            kind_ = other.kind_;
            conn_ = other.conn_;
            h2_conn_ = other.h2_conn_;
            h2_stream_id_ = other.h2_stream_id_;
            partition_ = other.partition_;
            partition_alive_ = std::move(other.partition_alive_);
            conn_alive_ = std::move(other.conn_alive_);
            other.kind_ = Kind::EMPTY;
            other.conn_ = nullptr;
            other.h2_conn_ = nullptr;
            other.h2_stream_id_ = -1;
            other.partition_ = nullptr;
        }
        return *this;
    }

    UpstreamLease(const UpstreamLease&) = delete;
    UpstreamLease& operator=(const UpstreamLease&) = delete;

    Kind kind() const { return kind_; }
    bool empty() const { return kind_ == Kind::EMPTY; }

    // H1 accessors. `Get()` / `operator->()` return nullptr when not H1.
    UpstreamConnection* Get() const {
        return kind_ == Kind::H1 ? conn_ : nullptr;
    }
    UpstreamConnection* operator->() const { return Get(); }
    explicit operator bool() const {
        return (kind_ == Kind::H1 && conn_ != nullptr) ||
               (kind_ == Kind::H2 && h2_conn_ != nullptr);
    }

    // H2 accessors. Both alive tokens are consulted; either dead → null.
    UpstreamH2Connection* GetH2Connection() const {
        if (kind_ != Kind::H2) return nullptr;
        if (!partition_alive_ ||
            !partition_alive_->load(std::memory_order_acquire)) return nullptr;
        if (!conn_alive_ ||
            !conn_alive_->load(std::memory_order_acquire)) return nullptr;
        return h2_conn_;
    }
    int32_t GetH2StreamId() const {
        return kind_ == Kind::H2 ? h2_stream_id_ : -1;
    }
    // Returns the stream entry if both alive tokens are live AND the conn
    // still holds the entry. Defined out-of-line because it dereferences
    // UpstreamH2Connection.
    UpstreamH2Stream* GetH2Stream() const;

    void Release();

private:
    Kind kind_ = Kind::EMPTY;
    UpstreamConnection* conn_ = nullptr;
    UpstreamH2Connection* h2_conn_ = nullptr;
    int32_t h2_stream_id_ = -1;
    PoolPartition* partition_ = nullptr;
    std::shared_ptr<std::atomic<bool>> partition_alive_;
    std::shared_ptr<std::atomic<bool>> conn_alive_;
};
