#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

class UpstreamConnection;
class UpstreamH2Connection;
struct UpstreamH2Stream;
class PoolPartition;
class Dispatcher;

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

    // `off_dispatcher_release_drops` is the heap-owned counter captured
    // at construction so that off-dispatcher Release() can bump it
    // without dereferencing `partition` (which may be racing
    // destruction). `dispatcher` is captured for the same race-safety
    // reason — the off-dispatcher `is_on_loop_thread()` check must NOT
    // dereference the partition. Both are null for test fixtures and
    // for any lease constructed outside the production partition
    // vending path; the Release code path then short-circuits via
    // `partition_live=false` since those fixtures pass `partition=null`.
    UpstreamLease(UpstreamConnection* conn, PoolPartition* partition,
                  std::shared_ptr<std::atomic<bool>> partition_alive,
                  std::shared_ptr<std::atomic<int64_t>>
                      off_dispatcher_release_drops = nullptr,
                  std::shared_ptr<Dispatcher> dispatcher = nullptr)
        : kind_(Kind::H1),
          conn_(conn),
          partition_(partition),
          partition_alive_(std::move(partition_alive)),
          off_dispatcher_release_drops_(
              std::move(off_dispatcher_release_drops)),
          dispatcher_(std::move(dispatcher)) {}

    UpstreamLease(UpstreamH2Connection* h2_conn, int32_t stream_id,
                  PoolPartition* partition,
                  std::shared_ptr<std::atomic<bool>> partition_alive,
                  std::shared_ptr<std::atomic<bool>> conn_alive,
                  std::shared_ptr<std::atomic<int64_t>>
                      off_dispatcher_release_drops = nullptr,
                  std::shared_ptr<Dispatcher> dispatcher = nullptr)
        : kind_(Kind::H2),
          h2_conn_(h2_conn),
          h2_stream_id_(stream_id),
          partition_(partition),
          partition_alive_(std::move(partition_alive)),
          conn_alive_(std::move(conn_alive)),
          off_dispatcher_release_drops_(
              std::move(off_dispatcher_release_drops)),
          dispatcher_(std::move(dispatcher)) {}

    ~UpstreamLease();

    UpstreamLease(UpstreamLease&& other) noexcept
        : kind_(other.kind_),
          conn_(other.conn_),
          h2_conn_(other.h2_conn_),
          h2_stream_id_(other.h2_stream_id_),
          partition_(other.partition_),
          partition_alive_(std::move(other.partition_alive_)),
          conn_alive_(std::move(other.conn_alive_)),
          off_dispatcher_release_drops_(
              std::move(other.off_dispatcher_release_drops_)),
          dispatcher_(std::move(other.dispatcher_)),
          donated_to_h2_(other.donated_to_h2_) {
        other.kind_ = Kind::EMPTY;
        other.conn_ = nullptr;
        other.h2_conn_ = nullptr;
        other.h2_stream_id_ = -1;
        other.partition_ = nullptr;
        other.donated_to_h2_ = false;
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
            off_dispatcher_release_drops_ =
                std::move(other.off_dispatcher_release_drops_);
            dispatcher_ = std::move(other.dispatcher_);
            donated_to_h2_ = other.donated_to_h2_;
            other.kind_ = Kind::EMPTY;
            other.conn_ = nullptr;
            other.h2_conn_ = nullptr;
            other.h2_stream_id_ = -1;
            other.partition_ = nullptr;
            other.donated_to_h2_ = false;
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
        if (kind_ == Kind::H1) {
            if (conn_ == nullptr) return false;
            // partition_alive guard mirrors Release()'s gate: if the
            // token is present AND observed dead, the lease outlived
            // its partition → false. Token-absent (detached lease in
            // test fixtures, where partition_=nullptr too) accepts
            // conn_ alone — matches Release()'s null-partition skip.
            if (partition_alive_ &&
                !partition_alive_->load(std::memory_order_acquire)) {
                return false;
            }
            return true;
        }
        if (kind_ == Kind::H2) {
            if (h2_conn_ == nullptr) return false;
            if (!partition_alive_ ||
                !partition_alive_->load(std::memory_order_acquire)) {
                return false;
            }
            if (!conn_alive_ ||
                !conn_alive_->load(std::memory_order_acquire)) {
                return false;
            }
            return true;
        }
        return false;
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

    // Called by UpstreamH2Connection::AdoptLease to tag this lease as
    // long-lived ownership of a donated transport, not a per-request
    // checkout. The accounting consequences are:
    //   - UpstreamManager::inflight_leases_ is decremented at adoption
    //     time (the per-request count drops because the request handed
    //     off ownership).
    //   - UpstreamManager::donated_h2_leases_ is incremented.
    //   - When Release fires, ReturnConnection observes the donated
    //     flag and decrements donated_h2_leases_ instead of
    //     inflight_leases_.
    // The drain predicate in HttpServer::WaitForAllAsyncDrain consults
    // only inflight_leases_, so a long-lived donation does not stall
    // observability flush.
    void MarkDonatedToH2() { donated_to_h2_ = true; }
    bool IsDonatedToH2() const { return donated_to_h2_; }

private:
    Kind kind_ = Kind::EMPTY;
    UpstreamConnection* conn_ = nullptr;
    UpstreamH2Connection* h2_conn_ = nullptr;
    int32_t h2_stream_id_ = -1;
    PoolPartition* partition_ = nullptr;
    std::shared_ptr<std::atomic<bool>> partition_alive_;
    std::shared_ptr<std::atomic<bool>> conn_alive_;
    // Heap-owned counter captured at construction. Outlives the
    // partition so off-dispatcher Release() can bump it without
    // dereferencing partition_ (which would race destruction).
    std::shared_ptr<std::atomic<int64_t>> off_dispatcher_release_drops_;
    // Dispatcher captured at construction. Outlives the partition
    // so the off-dispatcher `is_on_loop_thread()` check can fire
    // without dereferencing partition_ (which would race the
    // partition's destructor between alive-flag observation and
    // dispatcher access).
    std::shared_ptr<Dispatcher> dispatcher_;
    bool donated_to_h2_ = false;
};
