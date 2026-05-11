#include "observability/propagator.h"

#include "common.h"
#include <set>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Case-insensitive lookup over std::map<string,string>. Hot path on the
// inbound traceparent + tracestate read — the fast path is the
// case-sensitive find(); the linear scan only fires when the caller
// built the map with non-canonical casing.
const std::string* FindHeader(
    const std::map<std::string, std::string>& headers,
    std::string_view lower_key) {
    auto it = headers.find(std::string(lower_key));
    if (it != headers.end()) return &it->second;
    for (const auto& [k, v] : headers) {
        if (EqualsLowerAscii(k, lower_key)) return &v;
    }
    return nullptr;
}

inline void EraseVecHeader(
    std::vector<std::pair<std::string, std::string>>& headers,
    std::string_view lower_key) {
    headers.erase(
        std::remove_if(headers.begin(), headers.end(),
            [&](const std::pair<std::string, std::string>& kv) {
                return EqualsLowerAscii(kv.first, lower_key);
            }),
        headers.end());
}

// Single-pass map erase that drops every entry whose lowercased key
// matches any of the supplied references. Avoids the per-iteration
// std::string allocation that ToLower() would incur.
inline void EraseMapHeadersIfLowerMatches(
    std::map<std::string, std::string>& headers,
    std::initializer_list<std::string_view> lower_keys) {
    for (auto it = headers.begin(); it != headers.end(); ) {
        bool match = false;
        for (auto lk : lower_keys) {
            if (EqualsLowerAscii(it->first, lk)) { match = true; break; }
        }
        it = match ? headers.erase(it) : std::next(it);
    }
}

// Lowercase a string_view into the receiver. Used only by the
// post-strip survivor-set bookkeeping in the vector overload, which
// is a one-shot cost per Inject(HeadersVec&) call rather than a
// per-header hot-path operation.
inline std::string ToLower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out.push_back((c >= 'A' && c <= 'Z')
                          ? static_cast<char>(c + 32)
                          : static_cast<char>(c));
    }
    return out;
}

inline void AppendFlagsHex(uint8_t flags, std::string& out) {
    static constexpr const char digits[] = "0123456789abcdef";
    out.push_back(digits[(flags >> 4) & 0x0f]);
    out.push_back(digits[flags & 0x0f]);
}

}  // namespace

// ---------- Propagator base default overloads ----------

bool Propagator::Inject(const SpanContext& ctx, HeadersVec& headers) const {
    HeadersMap tmp;
    if (!Inject(ctx, tmp)) return false;
    // Strip the FULL owned-key set from the vec before appending. We
    // can't rely on "keys present in tmp" because a child Inject may
    // conditionally OMIT a header (e.g. W3C with empty tracestate) —
    // the omitted name would then survive as a stale entry on the wire.
    // Concrete propagators with a hot-path Vec form should override
    // this whole method (W3C does); the default is the safe shape.
    StripOwnedHeaders(headers);
    for (auto& kv : tmp) {
        headers.emplace_back(kv.first, std::move(kv.second));
    }
    return true;
}

void Propagator::StripOwnedHeaders(HeadersVec& headers) const {
    HeadersMap tmp;
    for (auto& kv : headers) tmp.emplace(kv.first, kv.second);
    StripOwnedHeaders(tmp);
    // Build a set of surviving lowercase keys; remove vector entries
    // whose key (lowercased) is not in the survivor set.
    std::set<std::string> survivors;
    for (const auto& [k, _] : tmp) survivors.insert(ToLower(k));
    headers.erase(
        std::remove_if(headers.begin(), headers.end(),
            [&](const std::pair<std::string, std::string>& kv) {
                return survivors.find(ToLower(kv.first)) == survivors.end();
            }),
        headers.end());
}

// Union of every shipped propagator's owned headers. Edited in lockstep
// with each concrete StripOwnedHeaders impl; adding a new propagator
// requires adding its keys here.
namespace {
constexpr std::array<std::string_view, 3> kAllKnownTraceHeaders = {
    "traceparent",     // W3C Trace Context
    "tracestate",      // W3C Trace Context
    "uber-trace-id",   // Jaeger
};
}  // namespace

void Propagator::StripAllKnownTraceHeaders(HeadersMap& headers) {
    for (auto it = headers.begin(); it != headers.end(); ) {
        bool match = false;
        for (auto lk : kAllKnownTraceHeaders) {
            if (EqualsLowerAscii(it->first, lk)) { match = true; break; }
        }
        it = match ? headers.erase(it) : std::next(it);
    }
}

void Propagator::StripAllKnownTraceHeaders(HeadersVec& headers) {
    headers.erase(
        std::remove_if(headers.begin(), headers.end(),
            [](const std::pair<std::string, std::string>& kv) {
                for (auto lk : kAllKnownTraceHeaders) {
                    if (EqualsLowerAscii(kv.first, lk)) return true;
                }
                return false;
            }),
        headers.end());
}

// ---------- W3CPropagator ----------

std::optional<SpanContext> W3CPropagator::ParseTraceparent(
    std::string_view header) const noexcept {
    if (header.size() != kTraceparentLen) return std::nullopt;
    if (header[2] != '-' || header[35] != '-' || header[52] != '-') {
        return std::nullopt;
    }
    if (header[0] != '0' || header[1] != '0') return std::nullopt;

    for (size_t i = 3; i < kTraceparentLen; ++i) {
        if (i == 35 || i == 52) continue;
        if (!IsHexCharLower(header[i])) return std::nullopt;
    }

    auto trace_id = TraceId::FromHex(header.substr(3, 32));
    if (!trace_id.IsValid()) return std::nullopt;
    auto span_id = SpanId::FromHex(header.substr(36, 16));
    if (!span_id.IsValid()) return std::nullopt;

    auto from_hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        return -1;
    };
    int hi = from_hex(header[53]);
    int lo = from_hex(header[54]);
    if (hi < 0 || lo < 0) return std::nullopt;
    TraceFlags flags{static_cast<uint8_t>((hi << 4) | lo)};

    return SpanContext(trace_id, span_id, flags, TraceState{},
                        /*is_remote=*/true);
}

std::optional<TraceState> W3CPropagator::ParseTracestate(
    std::string_view header) const {
    return TraceState::Parse(header);
}

std::optional<SpanContext> W3CPropagator::Extract(
    const HeadersMap& headers) const {
    const std::string* tp = FindHeader(headers, "traceparent");
    if (!tp) return std::nullopt;
    auto ctx = ParseTraceparent(*tp);
    if (!ctx) return std::nullopt;
    // tracestate parse failure does NOT invalidate traceparent (W3C §3.3.5).
    const std::string* ts = FindHeader(headers, "tracestate");
    if (ts) {
        auto parsed = ParseTracestate(*ts);
        if (parsed) ctx->mutable_state() = std::move(*parsed);
    }
    return ctx;
}

std::optional<std::string> W3CPropagator::SerializeTraceparent(
    const SpanContext& ctx) const {
    if (!ctx.IsValid()) return std::nullopt;
    std::string out;
    out.reserve(kTraceparentLen);
    out.append(kVersion00);
    out.push_back('-');
    out.append(ctx.trace_id().ToHex());
    out.push_back('-');
    out.append(ctx.span_id().ToHex());
    out.push_back('-');
    AppendFlagsHex(ctx.flags().value, out);
    return out;
}

bool W3CPropagator::Inject(const SpanContext& ctx,
                              HeadersMap& headers) const {
    auto tp = SerializeTraceparent(ctx);
    if (!tp) return false;
    // Strip-then-inject is the documented contract. The case-sensitive
    // upserts below would leave any non-canonical-case duplicate
    // ("Traceparent", "TraceParent") behind — defeating the spoofing
    // defense the design relies on. StripOwnedHeaders sweeps both
    // canonical lowercase and any mixed-case copy in one pass.
    StripOwnedHeaders(headers);
    headers["traceparent"] = std::move(*tp);
    if (!ctx.state().Empty()) {
        headers["tracestate"] = ctx.state().Serialize();
    }
    return true;
}

bool W3CPropagator::Inject(const SpanContext& ctx,
                              HeadersVec& headers) const {
    auto tp = SerializeTraceparent(ctx);
    if (!tp) return false;
    EraseVecHeader(headers, "traceparent");
    headers.emplace_back("traceparent", std::move(*tp));
    EraseVecHeader(headers, "tracestate");
    if (!ctx.state().Empty()) {
        headers.emplace_back("tracestate", ctx.state().Serialize());
    }
    return true;
}

void W3CPropagator::StripOwnedHeaders(HeadersMap& headers) const {
    headers.erase("traceparent");
    headers.erase("tracestate");
    // Tolerate any non-lower-case duplicates a caller might have built.
    // Single linear pass with EqualsLowerAscii — no per-header allocation.
    EraseMapHeadersIfLowerMatches(headers, {"traceparent", "tracestate"});
}

void W3CPropagator::StripOwnedHeaders(HeadersVec& headers) const {
    EraseVecHeader(headers, "traceparent");
    EraseVecHeader(headers, "tracestate");
}

}  // namespace OBSERVABILITY_NAMESPACE
