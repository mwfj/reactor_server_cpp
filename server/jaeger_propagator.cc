#include "observability/propagator.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

namespace OBSERVABILITY_NAMESPACE {

namespace {

bool IsHexLowercase(std::string_view s) {
    for (char c : s) {
        if (!IsHexCharLower(c)) return false;
    }
    return !s.empty();
}

std::optional<TraceId> ParseTraceIdHex(std::string_view hex) {
    if (hex.size() == 16) {
        // Legacy 64-bit; left-pad with 16 zero hex chars on the stack
        // to get the canonical 128-bit TraceId carrier — no heap alloc.
        char buf[32];
        std::fill_n(buf, 16, '0');
        std::copy(hex.begin(), hex.end(), buf + 16);
        TraceId t = TraceId::FromHex(std::string_view(buf, 32));
        return t.IsValid() ? std::optional<TraceId>{t} : std::nullopt;
    }
    if (hex.size() == 32) {
        TraceId t = TraceId::FromHex(hex);
        return t.IsValid() ? std::optional<TraceId>{t} : std::nullopt;
    }
    return std::nullopt;
}

}  // namespace

std::optional<SpanContext> JaegerPropagator::Parse(std::string_view value) {
    std::array<std::string_view, 4> parts{};
    size_t cur = 0;
    size_t idx = 0;
    while (idx < 4) {
        const auto next = value.find(':', cur);
        const auto end = (next == std::string_view::npos) ? value.size() : next;
        parts[idx++] = value.substr(cur, end - cur);
        if (next == std::string_view::npos) break;
        // A 5th colon means trailing data after parts[3] — reject.
        // (The previous post-loop length check used the wrong base and
        // accidentally accepted "a:b:c:d:e" whenever len(e)==len(d).)
        if (idx == 4) return std::nullopt;
        cur = next + 1;
    }
    if (idx != 4) return std::nullopt;
    if (!IsHexLowercase(parts[0]) || !IsHexLowercase(parts[1])
        || !IsHexLowercase(parts[3])) {
        return std::nullopt;
    }
    // parent-span-id is informational; the 4-part contract requires it
    // to be present and hex. A literal "0" (root span) is permitted by
    // jaeger-client-go's serializer; empty is not.
    if (!IsHexLowercase(parts[2])) {
        return std::nullopt;
    }

    auto trace_id = ParseTraceIdHex(parts[0]);
    if (!trace_id) return std::nullopt;

    if (parts[1].size() != 16) return std::nullopt;
    SpanId span_id = SpanId::FromHex(parts[1]);
    if (!span_id.IsValid()) return std::nullopt;

    if (parts[3].size() < 1 || parts[3].size() > 2) return std::nullopt;
    char flag_buf[3] = {0};
    std::copy(parts[3].begin(), parts[3].end(), flag_buf);
    const auto flag_byte = static_cast<uint8_t>(
        std::strtoul(flag_buf, nullptr, 16));

    // Honor only the sampled bit; debug/firehose are reserved.
    return SpanContext(
        *trace_id, span_id,
        TraceFlags{static_cast<uint8_t>(flag_byte & TraceFlags::kSampled)},
        TraceState{}, /*is_remote=*/true);
}

std::optional<SpanContext> JaegerPropagator::Extract(
    const HeadersMap& headers) const {
    // Fast path: case-sensitive find for the canonical lowercase key.
    auto it = headers.find(kHeader);
    if (it != headers.end()) return Parse(it->second);
    // Fallback: tolerate mixed-case keys (e.g. "Uber-Trace-Id") so a
    // caller that built the map from raw client bytes still extracts
    // correctly. Mirrors W3C's case-insensitive FindHeader sweep.
    for (const auto& [k, v] : headers) {
        if (EqualsLowerAscii(k, kHeader)) return Parse(v);
    }
    return std::nullopt;
}

bool JaegerPropagator::Inject(const SpanContext& ctx,
                                 HeadersMap& headers) const {
    if (!ctx.IsValid()) return false;
    const auto tid_hex = ctx.trace_id().ToHex();   // 32 hex
    const auto sid_hex = ctx.span_id().ToHex();    // 16 hex
    const uint8_t sampled_bit =
        ctx.flags().IsSampled() ? TraceFlags::kSampled : uint8_t{0};
    // Layout: 32 trace + ':' + 16 span + ':0:' + 2 flag = 53 bytes + NUL.
    char buf[64];
    const int n = std::snprintf(
        buf, sizeof(buf), "%s:%s:0:%02x",
        tid_hex.c_str(), sid_hex.c_str(),
        static_cast<unsigned>(sampled_bit));
    if (n < 0 || static_cast<size_t>(n) >= sizeof(buf)) return false;
    headers[kHeader] = std::string(buf, static_cast<size_t>(n));
    return true;
}

void JaegerPropagator::StripOwnedHeaders(HeadersMap& headers) const {
    headers.erase(kHeader);
    // Mixed-case duplicates (e.g. "Uber-Trace-Id") would otherwise leak
    // through to the upstream — match W3C's case-insensitive sweep.
    for (auto it = headers.begin(); it != headers.end(); ) {
        if (EqualsLowerAscii(it->first, kHeader)) {
            it = headers.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace OBSERVABILITY_NAMESPACE
