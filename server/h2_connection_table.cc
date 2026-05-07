#include "upstream/h2_connection_table.h"

namespace {

bool IsExpired(const std::shared_ptr<UpstreamH2Connection>& c) {
    if (!c) return true;
    if (c->IsDead()) return true;
    return c->goaway_seen() && c->active_stream_count() == 0;
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

std::shared_ptr<UpstreamH2Connection> H2ConnectionTable::FindUsable(
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
        if (c && c->IsUsable()) return c;
    }
    return nullptr;
}

void H2ConnectionTable::Insert(
    const std::string& upstream_name,
    std::shared_ptr<UpstreamH2Connection> conn)
{
    if (!conn) return;
    by_upstream_[upstream_name].push_back(std::move(conn));
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
            int idle = cfg ? cfg->ping_idle_sec : 0;
            int timeout = cfg ? cfg->ping_timeout_sec : 0;
            if (!c->Tick(now, idle, timeout)) {
                // MarkDead BEFORE FailAllStreams: between the failure
                // fan-out and the table erase below, FindUsable could be
                // called from another path and would return this conn
                // with dead_=false / streams_.empty() / IsUsable()=true.
                // The next SubmitRequest then fails on a poisoned session
                // and burns retry budget. Pitfall doc: UPSTREAM_PROXY.md
                // "After any FailAllStreams call site, the connection
                // MUST be marked dead".
                c->MarkDead();
                c->FailAllStreams(-1, "h2 PING timeout");
                it = conns.erase(it);
            } else if (c->goaway_seen() && c->active_stream_count() == 0) {
                it = conns.erase(it);
            } else {
                ++it;
            }
        }
    }
}
