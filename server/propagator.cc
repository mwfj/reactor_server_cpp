#include "observability/propagator.h"

#include <algorithm>
#include <cctype>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Lower-case ASCII compare — used to find the traceparent / tracestate
// headers in a header map that may contain mixed-case keys (HTTP/1
// stores lower-cased; HTTP/2 emits lower-cased; defensive to support
// either).
inline std::string ToLower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

inline bool IsHexChar(char c) noexcept {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

// Find a header value by lower-cased key. Returns nullptr when absent.
const std::string* FindHeader(
    const std::map<std::string, std::string>& headers,
    const std::string& lower_key) {
    auto it = headers.find(lower_key);
    if (it != headers.end()) return &it->second;
    // Tolerate non-lower-case keys (defensive — shouldn't happen with
    // the project's HttpRequest convention but cheap to scan).
    for (const auto& [k, v] : headers) {
        if (k.size() == lower_key.size() && ToLower(k) == lower_key) {
            return &v;
        }
    }
    return nullptr;
}

}  // namespace

std::optional<SpanContext> W3CPropagator::ParseTraceparent(
    std::string_view header) noexcept {
    if (header.size() != kTraceparentLen) return std::nullopt;
    // Layout: pp pp - tttttttttttttttttttttttttttttttt - pppppppppppppppp - ff
    //         0  1   2                                  35                  52
    //         (dashes at offsets 2, 35, 52)
    if (header[2] != '-' || header[35] != '-' || header[52] != '-') {
        return std::nullopt;
    }
    // Version must be "00".
    if (header[0] != '0' || header[1] != '0') return std::nullopt;

    // All other characters must be hex.
    for (size_t i = 3; i < kTraceparentLen; ++i) {
        if (i == 35 || i == 52) continue;
        if (!IsHexChar(header[i])) return std::nullopt;
    }

    auto trace_id = TraceId::FromHex(header.substr(3, 32));
    if (!trace_id.IsValid()) return std::nullopt;
    auto span_id = SpanId::FromHex(header.substr(36, 16));
    if (!span_id.IsValid()) return std::nullopt;

    // Parse trace-flags as 2 hex chars → uint8_t.
    auto from_hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    int hi = from_hex(header[53]);
    int lo = from_hex(header[54]);
    if (hi < 0 || lo < 0) return std::nullopt;
    TraceFlags flags{static_cast<uint8_t>((hi << 4) | lo)};

    SpanContext ctx(trace_id, span_id, flags, TraceState{}, /*is_remote=*/true);
    return ctx;
}

std::optional<TraceState> W3CPropagator::ParseTracestate(
    std::string_view header) {
    return TraceState::Parse(header);
}

std::optional<SpanContext> W3CPropagator::Extract(
    const std::map<std::string, std::string>& headers) {
    const std::string* tp = FindHeader(headers, "traceparent");
    if (!tp) return std::nullopt;
    auto ctx = ParseTraceparent(*tp);
    if (!ctx) return std::nullopt;
    // Tracestate parse failure does NOT invalidate the traceparent
    // (per W3C §3.3.5 — drop tracestate silently).
    const std::string* ts = FindHeader(headers, "tracestate");
    if (ts) {
        auto parsed = ParseTracestate(*ts);
        if (parsed) ctx->mutable_state() = std::move(*parsed);
    }
    return ctx;
}

namespace {

// Encode a TraceFlags value as 2 lowercase hex chars.
inline void AppendFlagsHex(uint8_t flags, std::string& out) {
    static constexpr const char digits[] = "0123456789abcdef";
    out.push_back(digits[(flags >> 4) & 0x0f]);
    out.push_back(digits[flags & 0x0f]);
}

}  // namespace

std::optional<std::string> W3CPropagator::SerializeTraceparent(
    const SpanContext& ctx) {
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
                             std::map<std::string, std::string>& headers) {
    auto tp = SerializeTraceparent(ctx);
    if (!tp) return false;
    headers["traceparent"] = std::move(*tp);
    if (!ctx.state().Empty()) {
        headers["tracestate"] = ctx.state().Serialize();
    } else {
        // If a previous tracestate was in the map, leave it alone —
        // strip-then-inject is the caller's responsibility per
        // OPENTELEMETRY_DESIGN.md §4.4.
    }
    return true;
}

bool W3CPropagator::Inject(const SpanContext& ctx,
                             std::vector<std::pair<std::string, std::string>>& headers) {
    auto tp = SerializeTraceparent(ctx);
    if (!tp) return false;
    // Replace existing traceparent / tracestate if present (case-
    // insensitive match) — same strip-then-inject contract.
    auto erase_if_match = [&](std::string_view name_lower) {
        headers.erase(
            std::remove_if(headers.begin(), headers.end(),
                [&](const std::pair<std::string, std::string>& kv) {
                    if (kv.first.size() != name_lower.size()) return false;
                    for (size_t i = 0; i < name_lower.size(); ++i) {
                        if (std::tolower(static_cast<unsigned char>(kv.first[i]))
                            != name_lower[i]) {
                            return false;
                        }
                    }
                    return true;
                }),
            headers.end());
    };
    erase_if_match("traceparent");
    headers.emplace_back("traceparent", std::move(*tp));
    if (!ctx.state().Empty()) {
        erase_if_match("tracestate");
        headers.emplace_back("tracestate", ctx.state().Serialize());
    }
    return true;
}

}  // namespace OBSERVABILITY_NAMESPACE
