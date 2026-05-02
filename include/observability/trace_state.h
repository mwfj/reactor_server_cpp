#pragma once

// W3C tracestate parser/writer per W3C Trace Context Level 1 §3.3.
//
// tracestate = list-member 0*31( OWS "," OWS list-member )
// list-member = key "=" value
// key   = lcalpha *(lcalpha / DIGIT / "_" / "-" / "*" / "/") [tenant "@" vendor]
//   (we accept the simpler RFC 8941 token shape; strict W3C key parse is
//   not required for our use — we only round-trip the field opaquely.)
// value = *(printable - "," - "=") (chars 0x20..0x7e excluding ',' and '=')
//
// This implementation is OPAQUE: we tokenize on commas, validate length
// caps, and preserve insertion order. We do NOT enforce strict per-key
// charset rules — the inbound traceparent path validates structure;
// tracestate is treated as best-effort metadata that round-trips through
// the gateway. Oversized list-members or >32 entries → drop tracestate
// entirely (per the design's "TraceStateOversized" test in §16.2).

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

class TraceState {
public:
    static constexpr size_t kMaxListMembers = 32;
    static constexpr size_t kMaxListMemberLen = 256;

    TraceState() = default;

    // Parse a comma-separated tracestate header value. Returns empty
    // optional if the header is structurally invalid (>32 members,
    // any list-member >256 chars). On success, returns a TraceState
    // preserving the inbound member order.
    static std::optional<TraceState> Parse(std::string_view header_value);

    // Serialize back to the wire form. Empty TraceState → "".
    std::string Serialize() const;

    // Get the value for a given key. Empty string if absent.
    std::string Get(std::string_view key) const;

    // Set / update a key. If the key already exists, its value is
    // updated AND it's moved to the front of the list per W3C §3.3
    // ("set" semantics — a new mutation moves the entry to the head).
    // No-op if adding a new key would exceed kMaxListMembers.
    void Set(std::string key, std::string value);

    bool Empty() const noexcept { return entries_.empty(); }
    size_t Size() const noexcept { return entries_.size(); }

    using Entry = std::pair<std::string, std::string>;
    const std::vector<Entry>& Entries() const noexcept { return entries_; }

private:
    std::vector<Entry> entries_;
};

}  // namespace OBSERVABILITY_NAMESPACE
