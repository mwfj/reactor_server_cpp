#pragma once

#include "common.h"
#include <cassert>
// <atomic>, <functional>, <memory>, <mutex>, <stdexcept>, <unordered_map>,
// <utility>, <vector>, <cstddef> all provided by common.h.

namespace UTIL_NAMESPACE {

// Sharded, intrusive doubly-linked LRU cache with per-shard mutex.
//
// Each shard owns its entries via std::unordered_map<Key, unique_ptr<Node>>
// and an intrusive LRU list (lru_head = MRU, lru_tail = LRU). Operations on
// the same shard serialize through that shard's mutex; operations on
// different shards are wait-free with respect to each other.
//
// Touch-on-access discipline:
//   Find()         : NO touch. Caller decides via Touch(handle).
//   Touch()        : explicit promote-to-MRU of an in-hand Handle.
//   FindAndTouch() : Find + promote on hit.
//   FindOrCreate() : Find + promote, OR create + promote on miss.
//   Insert()       : Upsert + promote, always.
//
// The class is non-copyable AND non-movable — shards contain std::mutex and
// the cache is intended to be constructed in-place via the owner's member-
// initializer-list and never reassigned.
//
// shard_count must be a power of two in [1, 64]; per_shard_cap must be > 0.
// Hash:    used for shard selection (low bits → mask).
// MapHash: used for the per-shard unordered_map's bucket placement.
//
// Splitting these matters when Hash deliberately consumes only part of the
// key (e.g. IntrospectionCache's HexPrefixHash takes the first 4 hex chars
// for shard derivation). Threading the same constrained hash through the
// per-shard map would limit per-bucket entropy to whatever bits Hash kept
// after the shard mask. Keep MapHash as the default std::hash<Key> unless
// you need a custom one.
template <typename Key,
          typename Value,
          typename Hash = std::hash<Key>,
          typename MapHash = std::hash<Key>>
class ShardedLruCache {
 private:
    // Forward-declared so Handle (public section, below) can hold Node*
    // and Shard*. Full definitions live at the bottom of the class.
    struct Node;
    struct Shard;

 public:
    ShardedLruCache(std::size_t shard_count,
                    std::size_t per_shard_cap,
                    std::size_t reserve_per_shard = 0)
        : shards_(ValidateAndReturnShardCount(shard_count, per_shard_cap)) {
        for (auto& s : shards_) {
            s.cap.store(per_shard_cap, std::memory_order_relaxed);
            if (reserve_per_shard > 0) {
                s.index.reserve(reserve_per_shard);
            }
        }
    }

    ShardedLruCache(const ShardedLruCache&) = delete;
    ShardedLruCache& operator=(const ShardedLruCache&) = delete;
    ShardedLruCache(ShardedLruCache&&) = delete;
    ShardedLruCache& operator=(ShardedLruCache&&) = delete;

    // --- RAII handle (move-only) ---
    //
    // While alive, holds the shard's mutex. Dereferencing is safe — the entry
    // cannot be evicted or relocated by another thread. Drop the Handle to
    // release the lock.
    //
    // Move semantics: transfer the unique_lock AND null source's shard_ and
    // node_ pointers. operator bool returns owns_lock() && node_ != nullptr,
    // so moved-from Handles are definitively "empty" (no stale-pointer race).
    //
    // shard_ rationale: Touch(Handle&) needs to splice node_ to the LRU head
    // of its owning shard. The Handle stores Shard* alongside Node* so Touch
    // can reach both without the caller passing a shard index.
    class Handle {
     public:
        Handle() noexcept = default;

        Handle(Handle&& other) noexcept
            : lock_(std::move(other.lock_)),
              shard_(other.shard_),
              node_(other.node_) {
            other.shard_ = nullptr;
            other.node_ = nullptr;
        }

        Handle& operator=(Handle&& other) noexcept {
            if (this != &other) {
                lock_ = std::move(other.lock_);
                shard_ = other.shard_;
                node_ = other.node_;
                other.shard_ = nullptr;
                other.node_ = nullptr;
            }
            return *this;
        }

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        explicit operator bool() const noexcept {
            return lock_.owns_lock() && node_ != nullptr;
        }

        // Dereference is UB when the Handle is empty (i.e., when operator bool
        // returns false). Callers MUST check operator bool first. Debug builds
        // catch the violation via assert; release builds get the same UB as
        // std::unique_ptr / std::optional dereference.
        Value& operator*() noexcept {
            assert(node_ != nullptr && "Handle::operator*: empty handle");
            return node_->value;
        }
        Value* operator->() noexcept {
            assert(node_ != nullptr && "Handle::operator->: empty handle");
            return &node_->value;
        }
        const Value& operator*() const noexcept {
            assert(node_ != nullptr && "Handle::operator*: empty handle");
            return node_->value;
        }
        const Value* operator->() const noexcept {
            assert(node_ != nullptr && "Handle::operator->: empty handle");
            return &node_->value;
        }

     private:
        friend class ShardedLruCache;

        Handle(std::unique_lock<std::mutex> lk, Shard* s, Node* n) noexcept
            : lock_(std::move(lk)), shard_(s), node_(n) {}

        std::unique_lock<std::mutex> lock_;
        Shard* shard_ = nullptr;
        Node* node_ = nullptr;
    };

    // --- Hot-path operations ---

    Handle Find(const Key& key) {
        Shard& s = shards_[ShardIndexFor(key)];
        std::unique_lock<std::mutex> lk(s.mu);
        auto it = s.index.find(key);
        if (it == s.index.end()) {
            return Handle{};
        }
        return Handle(std::move(lk), &s, it->second.get());
    }

    void Touch(Handle& handle) noexcept {
        if (!handle) return;
        handle.shard_->Promote(handle.node_);
    }

    Handle FindAndTouch(const Key& key) {
        Shard& s = shards_[ShardIndexFor(key)];
        std::unique_lock<std::mutex> lk(s.mu);
        auto it = s.index.find(key);
        if (it == s.index.end()) {
            return Handle{};
        }
        Node* n = it->second.get();
        s.Promote(n);
        return Handle(std::move(lk), &s, n);
    }

    // Look up; on miss, call factory() to construct the value, evict from
    // tail while size >= cap, then insert at MRU. Always returns a non-empty
    // Handle on normal return.
    //
    // Exception semantics:
    //   - factory() throws → propagates, cache unchanged (no evict, no insert).
    //   - Post-factory bad_alloc on insertion → propagates. Any tail evictions
    //     already performed by the while-loop are NOT rolled back.
    template <typename Factory>
    Handle FindOrCreate(const Key& key, Factory&& factory) {
        Shard& s = shards_[ShardIndexFor(key)];
        std::unique_lock<std::mutex> lk(s.mu);
        auto it = s.index.find(key);
        if (it != s.index.end()) {
            Node* n = it->second.get();
            s.Promote(n);
            return Handle(std::move(lk), &s, n);
        }
        // Miss path: construct value first. If factory throws, the lock
        // releases on unwind and the cache is left untouched.
        Value new_value = std::forward<Factory>(factory)();
        EvictWhileOverCap(s);
        auto new_node = std::make_unique<Node>(key, std::move(new_value));
        Node* raw = new_node.get();
        s.index.emplace(key, std::move(new_node));
        s.PushFront(raw);
        ++s.size;
        return Handle(std::move(lk), &s, raw);
    }

    // Upsert. On existing key: replace value, promote. On miss: evict-while-
    // over-cap, then insert at MRU.
    void Insert(const Key& key, Value value) {
        Shard& s = shards_[ShardIndexFor(key)];
        std::lock_guard<std::mutex> lk(s.mu);
        auto it = s.index.find(key);
        if (it != s.index.end()) {
            it->second->value = std::move(value);
            s.Promote(it->second.get());
            return;
        }
        EvictWhileOverCap(s);
        auto new_node = std::make_unique<Node>(key, std::move(value));
        Node* raw = new_node.get();
        s.index.emplace(key, std::move(new_node));
        s.PushFront(raw);
        ++s.size;
    }

    bool Erase(const Key& key) {
        Shard& s = shards_[ShardIndexFor(key)];
        std::lock_guard<std::mutex> lk(s.mu);
        auto it = s.index.find(key);
        if (it == s.index.end()) return false;
        s.Unlink(it->second.get());
        s.index.erase(it);
        --s.size;
        return true;
    }

    // --- Bulk operations ---

    void Clear() {
        for (auto& s : shards_) {
            std::lock_guard<std::mutex> lk(s.mu);
            s.index.clear();
            s.lru_head = nullptr;
            s.lru_tail = nullptr;
            s.size = 0;
        }
    }

    // Throws std::invalid_argument on new_per_shard_cap == 0.
    void ResizePerShardCap(std::size_t new_per_shard_cap) {
        if (new_per_shard_cap == 0) {
            throw std::invalid_argument(
                "ShardedLruCache: per_shard_cap must be > 0");
        }
        for (auto& s : shards_) {
            s.cap.store(new_per_shard_cap, std::memory_order_relaxed);
        }
    }

    // --- LRU-tail-ordered conditional eviction ---
    //
    // Walks the shard's LRU list from tail (oldest) toward head, evicting
    // each entry while predicate(value, current_size) returns true. Stops
    // on the first false return; the caller is responsible for choosing a
    // predicate where stopping at the first false is the desired semantic
    // (typically: predicate is monotonic over LRU order).
    //
    // Predicate signature: bool(const Value&, std::size_t current_size).
    // Returns the number of entries evicted.
    template <typename Predicate>
    std::size_t EvictFromTailWhile(std::size_t shard_idx, Predicate&& predicate) {
        Shard& s = shards_[shard_idx];
        std::lock_guard<std::mutex> lk(s.mu);
        std::size_t evicted = 0;
        while (s.lru_tail != nullptr) {
            Node* candidate = s.lru_tail;
            if (!predicate(static_cast<const Value&>(candidate->value), s.size)) {
                break;
            }
            s.Unlink(candidate);
            s.index.erase(candidate->key);
            --s.size;
            ++evicted;
        }
        return evicted;
    }

    // --- Iteration (for stats / debug only) ---

    std::size_t ShardCount() const noexcept { return shards_.size(); }

    // Walk one shard from LRU (tail) toward MRU (head). Visitor signature:
    // bool(const Key&, Value&). Return false to stop iteration. Shard mutex
    // is held for the entire visit — do not perform long operations inside.
    template <typename Visitor>
    void VisitShardLruToMru(std::size_t shard_idx, Visitor&& visitor) {
        Shard& s = shards_[shard_idx];
        std::lock_guard<std::mutex> lk(s.mu);
        Node* n = s.lru_tail;
        while (n != nullptr) {
            Node* prev = n->prev;  // toward MRU
            if (!visitor(static_cast<const Key&>(n->key), n->value)) {
                break;
            }
            n = prev;
        }
    }

    // --- Stats ---

    // Approximate total size — sum of per-shard sizes captured under each
    // shard's lock in turn. Not a global atomic snapshot.
    std::size_t Size() const {
        std::size_t total = 0;
        for (const auto& s : shards_) {
            std::lock_guard<std::mutex> lk(s.mu);
            total += s.size;
        }
        return total;
    }

    std::size_t ShardSize(std::size_t shard_idx) const {
        const Shard& s = shards_[shard_idx];
        std::lock_guard<std::mutex> lk(s.mu);
        return s.size;
    }

 private:
    struct Node {
        Key key;
        Value value;
        Node* prev = nullptr;  // toward MRU (head)
        Node* next = nullptr;  // toward LRU (tail)

        Node(Key k, Value v) : key(std::move(k)), value(std::move(v)) {}
    };

    struct Shard {
        mutable std::mutex mu;
        std::unordered_map<Key, std::unique_ptr<Node>, MapHash> index;
        Node* lru_head = nullptr;  // MRU
        Node* lru_tail = nullptr;  // LRU
        std::size_t size = 0;
        std::atomic<std::size_t> cap{0};

        // Helpers — caller holds mu.
        void Unlink(Node* n) noexcept {
            if (n->prev) n->prev->next = n->next;
            else          lru_head     = n->next;
            if (n->next) n->next->prev = n->prev;
            else          lru_tail     = n->prev;
            n->prev = nullptr;
            n->next = nullptr;
        }

        void PushFront(Node* n) noexcept {
            n->prev = nullptr;
            n->next = lru_head;
            if (lru_head) lru_head->prev = n;
            lru_head = n;
            if (!lru_tail) lru_tail = n;
        }

        void Promote(Node* n) noexcept {
            if (lru_head == n) return;
            Unlink(n);
            PushFront(n);
        }
    };

    static std::size_t ValidateAndReturnShardCount(std::size_t shard_count,
                                                   std::size_t per_shard_cap) {
        if (shard_count == 0 || shard_count > 64 ||
            (shard_count & (shard_count - 1)) != 0) {
            throw std::invalid_argument(
                "ShardedLruCache: shard_count must be a power of two in [1, 64]");
        }
        if (per_shard_cap == 0) {
            throw std::invalid_argument(
                "ShardedLruCache: per_shard_cap must be > 0");
        }
        return shard_count;
    }

    // Evict from tail while size >= cap. Caller holds s.mu. Used by both
    // FindOrCreate (after factory succeeds) and Insert (miss path).
    void EvictWhileOverCap(Shard& s) {
        const std::size_t cap = s.cap.load(std::memory_order_relaxed);
        while (s.size >= cap && s.lru_tail != nullptr) {
            Node* victim = s.lru_tail;
            s.Unlink(victim);
            s.index.erase(victim->key);
            --s.size;
        }
    }

    std::size_t ShardIndexFor(const Key& key) const {
        // shard_count is power-of-two; mask is cheaper than modulo.
        return hasher_(key) & (shards_.size() - 1);
    }

    std::vector<Shard> shards_;
    Hash hasher_;
};

}  // namespace UTIL_NAMESPACE
