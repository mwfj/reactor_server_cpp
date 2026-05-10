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

// Wire-format constants for `uber-trace-id`:
//
//   {trace-id}:{span-id}:{parent-span-id}:{flags}
//
// Field-length contract per jaeger-client-go's wire format. These
// match the comment block at the top of include/observability/propagator.h
// (JaegerPropagator section). UPPER_SNAKE_CASE constants per
// CODE_CONVENTIONS.md — never use bare numeric literals for
// non-obvious wire-format values.

// Number of colon-separated parts in a well-formed uber-trace-id.
static constexpr size_t UBER_TRACE_ID_PART_COUNT = 4;
// Hex length of the canonical 128-bit trace id field.
static constexpr size_t UBER_TRACE_ID_TRACE_HEX_LEN = 32;
// Hex length of the legacy 64-bit trace id (left-padded to 128-bit).
static constexpr size_t UBER_TRACE_ID_LEGACY_TRACE_HEX_LEN = 16;
// Number of zero hex chars used to left-pad a 64-bit trace id to 128-bit.
static constexpr size_t UBER_TRACE_ID_LEGACY_PAD_LEN =
    UBER_TRACE_ID_TRACE_HEX_LEN - UBER_TRACE_ID_LEGACY_TRACE_HEX_LEN;
// Hex length of the span id field (always 64-bit / 16 hex chars).
static constexpr size_t UBER_TRACE_ID_SPAN_HEX_LEN = 16;
// Maximum hex length of the flags field (1 or 2 hex chars).
static constexpr size_t UBER_TRACE_ID_FLAGS_HEX_MAX = 2;
// strtoul scratch buffer for the flags field: up to FLAGS_HEX_MAX
// bytes of payload + a trailing NUL.
static constexpr size_t UBER_TRACE_ID_FLAG_BUF_SIZE =
    UBER_TRACE_ID_FLAGS_HEX_MAX + 1;
// Output buffer for the serialized uber-trace-id header value.
//   32 (trace) + 1 (':') + 16 (span) + 3 (":0:") + 2 (flags) = 54
//   + 1 (NUL) = 55. Round up to 64 for alignment / safety margin —
//   snprintf is bounded by sizeof(kUberTraceIdSnprintfBufSize).
static constexpr size_t UBER_TRACE_ID_SNPRINTF_BUF_SIZE = 64;

bool IsHexLowercase(std::string_view s) {
    for (char c : s) {
        if (!IsHexCharLower(c)) return false;
    }
    return !s.empty();
}

std::optional<TraceId> ParseTraceIdHex(std::string_view hex) {
    if (hex.size() == UBER_TRACE_ID_LEGACY_TRACE_HEX_LEN) {
        // Legacy 64-bit; left-pad with zero hex chars on the stack to
        // get the canonical 128-bit TraceId carrier — no heap alloc.
        char buf[UBER_TRACE_ID_TRACE_HEX_LEN];
        std::fill_n(buf, UBER_TRACE_ID_LEGACY_PAD_LEN, '0');
        std::copy(hex.begin(), hex.end(),
                   buf + UBER_TRACE_ID_LEGACY_PAD_LEN);
        TraceId t = TraceId::FromHex(
            std::string_view(buf, UBER_TRACE_ID_TRACE_HEX_LEN));
        return t.IsValid() ? std::optional<TraceId>{t} : std::nullopt;
    }
    if (hex.size() == UBER_TRACE_ID_TRACE_HEX_LEN) {
        TraceId t = TraceId::FromHex(hex);
        return t.IsValid() ? std::optional<TraceId>{t} : std::nullopt;
    }
    return std::nullopt;
}

}  // namespace

std::optional<SpanContext> JaegerPropagator::Parse(std::string_view value) {
    std::array<std::string_view, UBER_TRACE_ID_PART_COUNT> parts{};
    size_t cur = 0;
    size_t idx = 0;
    while (idx < UBER_TRACE_ID_PART_COUNT) {
        const auto next = value.find(':', cur);
        const auto end = (next == std::string_view::npos) ? value.size() : next;
        parts[idx++] = value.substr(cur, end - cur);
        if (next == std::string_view::npos) break;
        // A 5th colon means trailing data after the last part — reject.
        // (A previous post-loop length check used the wrong base and
        // accidentally accepted "a:b:c:d:e" whenever len(e)==len(d).)
        if (idx == UBER_TRACE_ID_PART_COUNT) return std::nullopt;
        cur = next + 1;
    }
    if (idx != UBER_TRACE_ID_PART_COUNT) return std::nullopt;
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

    if (parts[1].size() != UBER_TRACE_ID_SPAN_HEX_LEN) return std::nullopt;
    SpanId span_id = SpanId::FromHex(parts[1]);
    if (!span_id.IsValid()) return std::nullopt;

    // Only the upper bound is useful: size==0 already returned nullopt
    // at the IsHexLowercase(parts[3]) gate above (its trailing
    // !s.empty() rejects empties).
    if (parts[3].size() > UBER_TRACE_ID_FLAGS_HEX_MAX) return std::nullopt;
    char flag_buf[UBER_TRACE_ID_FLAG_BUF_SIZE] = {0};
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
    const auto tid_hex = ctx.trace_id().ToHex();   // canonical 128-bit hex
    const auto sid_hex = ctx.span_id().ToHex();    // 64-bit hex
    const uint8_t sampled_bit =
        ctx.flags().IsSampled() ? TraceFlags::kSampled : uint8_t{0};
    // Layout: 32 (trace) + 1 (':') + 16 (span) + 3 (":0:") + 2 (flags)
    // = 54 bytes + NUL terminator. Buffer sized via the named constant.
    char buf[UBER_TRACE_ID_SNPRINTF_BUF_SIZE];
    const int n = std::snprintf(
        buf, sizeof(buf), "%s:%s:0:%02x",
        tid_hex.c_str(), sid_hex.c_str(),
        static_cast<unsigned>(sampled_bit));
    if (n < 0 || static_cast<size_t>(n) >= sizeof(buf)) return false;
    // Strip-then-inject contract: the case-sensitive upsert below would
    // leave a mixed-case duplicate ("Uber-Trace-Id") behind. Sweep all
    // case variants before emitting the canonical lowercase entry.
    StripOwnedHeaders(headers);
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

void JaegerPropagator::StripOwnedHeaders(HeadersVec& headers) const {
    // Single-pass remove_if mirrors W3C's vec-form strip — case-
    // insensitive, no per-header allocation, no map roundtrip.
    headers.erase(
        std::remove_if(headers.begin(), headers.end(),
            [](const std::pair<std::string, std::string>& kv) {
                return EqualsLowerAscii(kv.first, kHeader);
            }),
        headers.end());
}

}  // namespace OBSERVABILITY_NAMESPACE
