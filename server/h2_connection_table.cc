#include "upstream/h2_connection_table.h"
#include "log/logger.h"

namespace {

bool IsExpired(const std::unique_ptr<UpstreamH2Connection>& c) {
    if (!c) return true;
    // A connection is reapable only when it cannot serve traffic AND
    // has no in-flight streams to drain. Dead+empty and goaway+empty
    // are both fully drained — but `dead && active>0` is the
    // endpoint-mismatch case (PoolPartition::AcquireH2Connection
    // calls MarkDead WITHOUT FailAllStreams to let in-flight streams
    // finish on the stale-IP transport — H1 keepalive parity).
    // Reaping that case here would drop the table's last strong ref,
    // destroy the nghttp2 session, and strand the in-flight requests.
    return c->active_stream_count() == 0 &&
           (c->IsDead() || c->goaway_seen());
}

}  // namespace

size_t H2ConnectionTable::TotalConnections() const {
    size_t total = 0;
    for (const auto& [_, conns] : by_upstream_) {
        total += conns.size();
    }
    return total;
}

size_t H2ConnectionTable::ConnectionsForUpstream(
    const std::string& upstream_name) const
{
    auto it = by_upstream_.find(upstream_name);
    if (it == by_upstream_.end()) return 0;
    return it->second.size();
}

void H2ConnectionTable::Clear() {
    by_upstream_.clear();
}

size_t H2ConnectionTable::ReapDrained() {
    size_t removed = 0;
    for (auto& [_, conns] : by_upstream_) {
        auto end = std::remove_if(conns.begin(), conns.end(), IsExpired);
        removed += static_cast<size_t>(conns.end() - end);
        conns.erase(end, conns.end());
    }
    return removed;
}

UpstreamH2Connection* H2ConnectionTable::FindUsable(
    const std::string& upstream_name)
{
    auto it = by_upstream_.find(upstream_name);
    if (it == by_upstream_.end()) return nullptr;
    auto& conns = it->second;

    // Reap dead / null / fully-drained inline so the lookup never
    // returns an unusable connection and the table stays compact.
    auto end = std::remove_if(conns.begin(), conns.end(), IsExpired);
    conns.erase(end, conns.end());

    for (auto& c : conns) {
        if (c && c->IsUsable()) return c.get();
    }
    return nullptr;
}

std::vector<UpstreamH2Connection*>
H2ConnectionTable::CollectUsableForUpstream(
    const std::string& upstream_name)
{
    std::vector<UpstreamH2Connection*> out;
    auto it = by_upstream_.find(upstream_name);
    if (it == by_upstream_.end()) return out;
    auto& conns = it->second;

    // Reap expired inline so the returned set reflects only currently
    // usable connections (mirrors FindUsable's side effect).
    auto end = std::remove_if(conns.begin(), conns.end(), IsExpired);
    conns.erase(end, conns.end());

    out.reserve(conns.size());
    for (auto& c : conns) {
        if (c && c->IsUsable()) out.push_back(c.get());
    }
    return out;
}

void H2ConnectionTable::Insert(
    const std::string& upstream_name,
    std::unique_ptr<UpstreamH2Connection> conn)
{
    if (!conn) return;
    by_upstream_[upstream_name].push_back(std::move(conn));
}

std::unique_ptr<UpstreamH2Connection> H2ConnectionTable::Extract(
    UpstreamH2Connection* conn)
{
    if (!conn) return nullptr;
    for (auto& [_, conns] : by_upstream_) {
        for (auto it = conns.begin(); it != conns.end(); ++it) {
            if (it->get() == conn) {
                auto out = std::move(*it);
                conns.erase(it);
                return out;
            }
        }
    }
    return nullptr;
}

std::vector<std::unique_ptr<UpstreamH2Connection>>
H2ConnectionTable::ExtractAll() {
    // reserve() up-front so push_back below is noexcept — without this,
    // a mid-loop bad_alloc would leave by_upstream_ in moved-but-not-
    // cleared state (null entries in the vectors, skipped clear()) on
    // rethrow.
    std::vector<std::unique_ptr<UpstreamH2Connection>> out;
    out.reserve(TotalConnections());
    for (auto& [_, conns] : by_upstream_) {
        for (auto& c : conns) {
            if (c) out.push_back(std::move(c));
        }
    }
    by_upstream_.clear();
    return out;
}

std::vector<UpstreamH2Connection*> H2ConnectionTable::CollectAll() const {
    std::vector<UpstreamH2Connection*> out;
    out.reserve(TotalConnections());
    for (const auto& [_, conns] : by_upstream_) {
        for (const auto& c : conns) {
            if (c) out.push_back(c.get());
        }
    }
    return out;
}

void H2ConnectionTable::TickAll(std::chrono::steady_clock::time_point now) {
    for (auto& [_, conns] : by_upstream_) {
        auto it = conns.begin();
        while (it != conns.end()) {
            auto& c = *it;
            if (!c) {
                it = conns.erase(it);
                continue;
            }
            const auto& cfg = c->config_snapshot();
            if (!cfg) {
                // UpstreamH2Connection's class invariant requires a
                // non-null cfg captured at construction. A null here means
                // a malformed connection slipped past Init() (or some
                // future refactor breaks the invariant). Treating each
                // timer as 0 (disabled) silently keeps the connection
                // alive forever — surface it instead and evict.
                logging::Get()->error(
                    "H2ConnectionTable::TickAll: connection has null "
                    "config_snapshot — class invariant violated; evicting");
                c->MarkDead();
                it = conns.erase(it);
                continue;
            }
            int idle = cfg->ping_idle_sec;
            int timeout = cfg->ping_timeout_sec;
            int goaway_drain = cfg->goaway_drain_timeout_sec;
            if (!c->Tick(now, idle, timeout, goaway_drain)) {
                // Move + erase BEFORE FailAllStreams: a sink's OnError
                // could synchronously re-enter FindUsable on this same
                // bucket. Removing the dying entry from `conns` first
                // means reentrants see an empty slot for this key,
                // preserving iterator validity. MarkDead still runs on
                // `victim` so any weak_ptr observer sees IsDead()=true.
                // Pitfall doc: UPSTREAM_PROXY.md "After any
                // FailAllStreams call site, the connection MUST be
                // marked dead".
                auto victim = std::move(*it);
                it = conns.erase(it);
                victim->MarkDead();
                victim->FailAllStreams(
                    -1, victim->goaway_seen() ? "h2 GOAWAY drain timeout"
                                              : "h2 PING timeout");
            } else if (c->goaway_seen() && c->active_stream_count() == 0) {
                // Mark dead before erasing so any weak_ptr observer
                // racing the destructor sees `IsDead() == true` instead
                // of "alive but goaway-drained" — symmetric with the
                // PING/GOAWAY-timeout branch above. The partition's
                // strong-ref is the last one in practice, but the
                // explicit MarkDead is cheap insurance against future
                // observers that latch on a weak_ptr between erase and
                // destruction.
                c->MarkDead();
                it = conns.erase(it);
            } else if (c->IsDead() && c->active_stream_count() == 0) {
                // Connections marked dead via paths other than Tick or
                // goaway-drain (e.g., the endpoint-mismatch reuse gate
                // in PoolPartition::AcquireH2Connection) accumulate here
                // until a fresh AcquireH2Connection call inline-reaps
                // them via FindUsable. Reap them on the timer too so a
                // sustained pattern of reuse-gate misses on an upstream
                // that no longer receives traffic doesn't leak entries.
                it = conns.erase(it);
            } else {
                ++it;
            }
        }
    }
}
