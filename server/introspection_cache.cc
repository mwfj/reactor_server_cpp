#include "auth/introspection_cache.h"

#include "log/logger.h"

#include <new>
#include <utility>

namespace AUTH_NAMESPACE {

namespace {

constexpr size_t MAX_SHARD_COUNT = 64;
constexpr size_t SHARD_PREFIX_HEX_CHARS = 4;

// Parse a single hex character. Returns -1 on non-hex input.
int HexCharToInt(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

}  // namespace

// Intrusive LRU node owned by Shard::map (via unique_ptr value).
struct IntrospectionCache::Entry {
    std::string key;
    bool active = false;
    AuthContext ctx;
    std::chrono::steady_clock::time_point ttl_expiry{};
    Entry* prev = nullptr;
    Entry* next = nullptr;
};

struct IntrospectionCache::Shard {
    std::mutex mtx;
    std::unordered_map<std::string, std::unique_ptr<Entry>> map;
    Entry* head = nullptr;   // MRU
    Entry* tail = nullptr;   // LRU
    std::atomic<size_t> size_approx{0};

    // Detach from the doubly-linked LRU list. Caller must hold mtx.
    void Unlink(Entry* e) noexcept {
        if (e->prev) e->prev->next = e->next;
        else head = e->next;
        if (e->next) e->next->prev = e->prev;
        else tail = e->prev;
        e->prev = nullptr;
        e->next = nullptr;
    }

    // Splice to MRU position. Caller must hold mtx.
    void PushFront(Entry* e) noexcept {
        e->prev = nullptr;
        e->next = head;
        if (head) head->prev = e;
        head = e;
        if (!tail) tail = e;
    }

    // Promote an existing in-list entry to MRU. Caller must hold mtx.
    void Promote(Entry* e) noexcept {
        if (head == e) return;
        Unlink(e);
        PushFront(e);
    }
};

IntrospectionCache::IntrospectionCache(std::string issuer_name,
                                       size_t max_entries,
                                       size_t shard_count)
    : issuer_name_(std::move(issuer_name)),
      shard_count_(shard_count),
      per_shard_cap_(0) {
    if (shard_count == 0 || shard_count > MAX_SHARD_COUNT ||
        (shard_count & (shard_count - 1)) != 0) {
        throw std::invalid_argument(
            "IntrospectionCache: shard_count must be a power of two in [1, 64]");
    }
    if (max_entries == 0) {
        throw std::invalid_argument(
            "IntrospectionCache: max_entries must be > 0");
    }
    shards_.reserve(shard_count_);
    for (size_t i = 0; i < shard_count_; ++i) {
        shards_.push_back(std::make_unique<Shard>());
    }
    per_shard_cap_.store(
        (max_entries + shard_count_ - 1) / shard_count_,
        std::memory_order_relaxed);
}

IntrospectionCache::~IntrospectionCache() = default;

size_t IntrospectionCache::SelectShard(const std::string& key) const {
    if (key.size() < SHARD_PREFIX_HEX_CHARS) {
        logging::Get()->error(
            "IntrospectionCache[{}]: key too short for shard selection (len={})",
            issuer_name_, key.size());
        return 0;
    }
    uint16_t prefix = 0;
    for (size_t i = 0; i < SHARD_PREFIX_HEX_CHARS; ++i) {
        const int v = HexCharToInt(key[i]);
        if (v < 0) {
            logging::Get()->error(
                "IntrospectionCache[{}]: non-hex char in key prefix",
                issuer_name_);
            return 0;
        }
        prefix = static_cast<uint16_t>((prefix << 4) | static_cast<uint16_t>(v));
    }
    return static_cast<size_t>(prefix) & (shard_count_ - 1);
}

IntrospectionCache::LookupResult IntrospectionCache::Lookup(
    const std::string& key,
    std::chrono::steady_clock::time_point now) {
    Shard& s = *shards_[SelectShard(key)];
    std::lock_guard<std::mutex> lk(s.mtx);
    auto it = s.map.find(key);
    if (it == s.map.end()) {
        miss_.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    Entry* e = it->second.get();
    if (now >= e->ttl_expiry) {
        // Expired — leave in place; LookupStale serves it within grace, and
        // LRU eviction reaps it when the shard fills.
        miss_.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    s.Promote(e);
    LookupResult r;
    r.state = LookupState::Fresh;
    r.active = e->active;
    if (e->active) {
        r.ctx = e->ctx;
        hit_.fetch_add(1, std::memory_order_relaxed);
    } else {
        negative_hit_.fetch_add(1, std::memory_order_relaxed);
    }
    return r;
}

IntrospectionCache::LookupResult IntrospectionCache::LookupStale(
    const std::string& key,
    std::chrono::steady_clock::time_point now) {
    Shard& s = *shards_[SelectShard(key)];
    std::lock_guard<std::mutex> lk(s.mtx);
    auto it = s.map.find(key);
    if (it == s.map.end()) return {};

    Entry* e = it->second.get();
    if (!e->active) {
        // Never stale-serve a negative cache entry.
        return {};
    }
    const auto grace = std::chrono::seconds(
        stale_grace_sec_.load(std::memory_order_relaxed));
    if (now < e->ttl_expiry || now > e->ttl_expiry + grace) return {};

    LookupResult r;
    r.state = LookupState::Stale;
    r.active = true;
    r.ctx = e->ctx;
    stale_served_.fetch_add(1, std::memory_order_relaxed);
    return r;
}

void IntrospectionCache::Insert(const std::string& key,
                                AuthContext ctx,
                                bool active,
                                std::chrono::seconds ttl) {
    if (ttl <= std::chrono::seconds::zero()) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    const auto expiry = now + ttl;
    Shard& s = *shards_[SelectShard(key)];
    std::lock_guard<std::mutex> lk(s.mtx);

    auto it = s.map.find(key);
    if (it != s.map.end()) {
        Entry* e = it->second.get();
        e->active = active;
        e->ctx = std::move(ctx);
        e->ttl_expiry = expiry;
        s.Promote(e);
        return;
    }

    const size_t cap = per_shard_cap_.load(std::memory_order_relaxed);
    while (s.map.size() >= cap && s.tail != nullptr) {
        Entry* victim = s.tail;
        s.Unlink(victim);
        s.map.erase(victim->key);
        s.size_approx.store(s.map.size(), std::memory_order_relaxed);
    }

    try {
        auto entry = std::make_unique<Entry>();
        entry->key = key;
        entry->active = active;
        entry->ctx = std::move(ctx);
        entry->ttl_expiry = expiry;
        Entry* raw = entry.get();
        auto [ins_it, ok] = s.map.emplace(key, std::move(entry));
        if (!ok) {
            // Already-present case is handled above; reaching here implies
            // a concurrent insert under the same lock — unreachable.
            return;
        }
        s.PushFront(raw);
        s.size_approx.store(s.map.size(), std::memory_order_relaxed);
    } catch (const std::bad_alloc& e) {
        logging::Get()->warn(
            "IntrospectionCache[{}]: insert dropped on bad_alloc",
            issuer_name_);
    } catch (const std::exception& e) {
        logging::Get()->warn(
            "IntrospectionCache[{}]: insert dropped on exception: {}",
            issuer_name_, e.what());
    }
}

void IntrospectionCache::ApplyReload(const IntrospectionConfig& new_cfg) {
    cache_sec_.store(new_cfg.cache_sec, std::memory_order_relaxed);
    negative_cache_sec_.store(new_cfg.negative_cache_sec,
                              std::memory_order_relaxed);
    stale_grace_sec_.store(new_cfg.stale_grace_sec,
                           std::memory_order_relaxed);
    if (new_cfg.max_entries > 0) {
        const size_t max_entries = static_cast<size_t>(new_cfg.max_entries);
        const size_t per_shard =
            (max_entries + shard_count_ - 1) / shard_count_;
        per_shard_cap_.store(per_shard, std::memory_order_relaxed);
    }
}

void IntrospectionCache::Clear() {
    for (auto& shard : shards_) {
        std::lock_guard<std::mutex> lk(shard->mtx);
        shard->map.clear();
        shard->head = nullptr;
        shard->tail = nullptr;
        shard->size_approx.store(0, std::memory_order_relaxed);
    }
}

IntrospectionCache::Stats IntrospectionCache::SnapshotStats() const {
    Stats s;
    s.hit = hit_.load(std::memory_order_relaxed);
    s.miss = miss_.load(std::memory_order_relaxed);
    s.negative_hit = negative_hit_.load(std::memory_order_relaxed);
    s.stale_served = stale_served_.load(std::memory_order_relaxed);
    size_t total = 0;
    for (const auto& shard : shards_) {
        total += shard->size_approx.load(std::memory_order_relaxed);
    }
    s.entries = total;
    return s;
}

}  // namespace AUTH_NAMESPACE
