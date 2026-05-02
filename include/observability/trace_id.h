#pragma once

// W3C Trace Context identity primitives — TraceId (16 bytes), SpanId (8 bytes),
// TraceFlags (1 byte), RandomSource. Per W3C Trace Context Level 1 §3.2:
//   - trace-id: 32 hex chars (16 raw bytes); all-zero is invalid.
//   - parent-id: 16 hex chars (8 raw bytes); all-zero is invalid.
//   - trace-flags: 8 bits; bit 0 = sampled.
//
// These are POD-like value types — copyable, comparable, hex-serializable.
// The RandomSource produces non-cryptographic-quality 64-bit / 128-bit
// random words for ID generation; it is dispatcher-thread-local so no
// synchronization is needed (each dispatcher seeds its own state at
// construction time).

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace OBSERVABILITY_NAMESPACE {

// 128-bit (16-byte) trace identifier.
struct TraceId {
    std::array<uint8_t, 16> bytes{};

    constexpr TraceId() = default;

    static TraceId FromBytes(const uint8_t (&raw)[16]) noexcept {
        TraceId id;
        std::memcpy(id.bytes.data(), raw, 16);
        return id;
    }

    // Parse 32 hex characters. Returns a default-constructed (all-zero)
    // TraceId on parse failure; callers MUST check `IsValid()` after parse.
    static TraceId FromHex(std::string_view hex) noexcept;
    std::string ToHex() const;

    // W3C: an all-zero trace-id is invalid. `IsValid()` rejects it.
    bool IsValid() const noexcept {
        for (uint8_t b : bytes) if (b != 0) return true;
        return false;
    }

    bool operator==(const TraceId& o) const noexcept { return bytes == o.bytes; }
    bool operator!=(const TraceId& o) const noexcept { return bytes != o.bytes; }
};

// 64-bit (8-byte) span identifier.
struct SpanId {
    std::array<uint8_t, 8> bytes{};

    constexpr SpanId() = default;

    static SpanId FromBytes(const uint8_t (&raw)[8]) noexcept {
        SpanId id;
        std::memcpy(id.bytes.data(), raw, 8);
        return id;
    }

    static SpanId FromHex(std::string_view hex) noexcept;
    std::string ToHex() const;

    bool IsValid() const noexcept {
        for (uint8_t b : bytes) if (b != 0) return true;
        return false;
    }

    bool operator==(const SpanId& o) const noexcept { return bytes == o.bytes; }
    bool operator!=(const SpanId& o) const noexcept { return bytes != o.bytes; }
};

// W3C trace-flags: 8-bit field. Bit 0 (LSB) = sampled. All other bits
// are reserved; we preserve them on round-trip but do not interpret.
struct TraceFlags {
    uint8_t value = 0;

    constexpr TraceFlags() = default;
    explicit constexpr TraceFlags(uint8_t v) : value(v) {}

    static constexpr uint8_t kSampled = 0x01;

    bool IsSampled() const noexcept { return (value & kSampled) != 0; }
    void SetSampled(bool s) noexcept {
        if (s) value |= kSampled;
        else   value &= static_cast<uint8_t>(~kSampled);
    }

    bool operator==(TraceFlags o) const noexcept { return value == o.value; }
    bool operator!=(TraceFlags o) const noexcept { return value != o.value; }
};

// Per-dispatcher random source for ID generation. Non-cryptographic.
// Each dispatcher constructs its own instance; no synchronization needed
// because the same RandomSource is never touched cross-thread.
class RandomSource {
public:
    RandomSource();
    explicit RandomSource(uint64_t seed);

    TraceId NewTraceId() noexcept;
    SpanId  NewSpanId() noexcept;

private:
    uint64_t state_lo_ = 0;
    uint64_t state_hi_ = 0;
    uint64_t Next64() noexcept;
};

}  // namespace OBSERVABILITY_NAMESPACE
