#include "observability/propagator.h"

#include <algorithm>
#include <cctype>
#include <set>

namespace OBSERVABILITY_NAMESPACE {

namespace {

inline std::string ToLower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

const std::string* FindHeader(
    const std::map<std::string, std::string>& headers,
    const std::string& lower_key) {
    auto it = headers.find(lower_key);
    if (it != headers.end()) return &it->second;
    for (const auto& [k, v] : headers) {
        if (k.size() == lower_key.size() && ToLower(k) == lower_key) {
            return &v;
        }
    }
    return nullptr;
}

inline bool EqualsLowerAscii(std::string_view name, std::string_view lower) {
    if (name.size() != lower.size()) return false;
    for (size_t i = 0; i < lower.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(name[i])) != lower[i]) {
            return false;
        }
    }
    return true;
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
    // Strip the keys we're about to write so we don't duplicate. The
    // map-side Inject already strip-replaced its owned keys via the
    // concrete impl; here we mirror that on the vector representation.
    for (const auto& [k, _] : tmp) EraseVecHeader(headers, k);
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
    headers["traceparent"] = std::move(*tp);
    if (!ctx.state().Empty()) {
        headers["tracestate"] = ctx.state().Serialize();
    } else {
        headers.erase("tracestate");
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
    for (auto it = headers.begin(); it != headers.end(); ) {
        const std::string lower = ToLower(it->first);
        if (lower == "traceparent" || lower == "tracestate") {
            it = headers.erase(it);
        } else {
            ++it;
        }
    }
}

void W3CPropagator::StripOwnedHeaders(HeadersVec& headers) const {
    EraseVecHeader(headers, "traceparent");
    EraseVecHeader(headers, "tracestate");
}

}  // namespace OBSERVABILITY_NAMESPACE
