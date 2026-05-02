#include "observability/trace_state.h"

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Trim leading + trailing OWS (space + horizontal tab) per RFC 7230 §3.2.3.
std::string_view TrimOws(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
    return s;
}

}  // namespace

std::optional<TraceState> TraceState::Parse(std::string_view header) {
    TraceState ts;
    if (header.empty()) return ts;

    size_t pos = 0;
    while (pos <= header.size()) {
        // Find next comma; everything before it (after OWS-trim) is one
        // list-member.
        const size_t comma = header.find(',', pos);
        std::string_view member = (comma == std::string_view::npos)
            ? header.substr(pos)
            : header.substr(pos, comma - pos);
        member = TrimOws(member);

        if (!member.empty()) {
            if (member.size() > kMaxListMemberLen) {
                // Oversized list-member → drop the entire tracestate.
                return std::nullopt;
            }
            const size_t eq = member.find('=');
            if (eq == std::string_view::npos) {
                return std::nullopt;  // malformed: no '='
            }
            std::string key   = std::string(TrimOws(member.substr(0, eq)));
            std::string value = std::string(TrimOws(member.substr(eq + 1)));
            if (key.empty()) return std::nullopt;

            if (ts.entries_.size() >= kMaxListMembers) {
                // Exceeded max list-members → drop the entire tracestate.
                return std::nullopt;
            }
            ts.entries_.emplace_back(std::move(key), std::move(value));
        }

        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return ts;
}

std::string TraceState::Serialize() const {
    std::string out;
    if (entries_.empty()) return out;
    bool first = true;
    for (const auto& e : entries_) {
        if (!first) out.push_back(',');
        first = false;
        out.append(e.first);
        out.push_back('=');
        out.append(e.second);
    }
    return out;
}

std::string TraceState::Get(std::string_view key) const {
    for (const auto& e : entries_) {
        if (e.first == key) return e.second;
    }
    return {};
}

void TraceState::Set(std::string key, std::string value) {
    // W3C §3.3: a `set` operation moves the key to the head of the list.
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->first == key) {
            entries_.erase(it);
            entries_.insert(entries_.begin(), {std::move(key), std::move(value)});
            return;
        }
    }
    if (entries_.size() >= kMaxListMembers) return;  // silently drop
    entries_.insert(entries_.begin(), {std::move(key), std::move(value)});
}

}  // namespace OBSERVABILITY_NAMESPACE
