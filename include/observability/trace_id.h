#pragma once

// W3C Trace Context identity primitives — TraceId (16 bytes), SpanId (8 bytes),
// TraceFlags (1 byte), RandomSource. Per W3C Trace Context Level 1 §3.2:
//   - trace-id: 32 hex chars (16 raw bytes); all-zero is invalid.
//   - parent-id: 16 hex chars (8 raw bytes); all-zero is invalid.
//   - trace-flags: 8 bits; bit 0 = sampled.
//
// These are POD-like value types — copyable, comparable, hex-serializable.
// RandomSource produces non-cryptographic-quality 64-bit / 128-bit random
// words for ID generation; it serialises access internally so a single
// instance may be safely shared across dispatchers (production wiring
// passes one RandomSource through the manager to all Tracers).

#include "../common.h"

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

// Random source for trace/span ID generation. Non-cryptographic.
//
// Production wires a single RandomSource through the manager →
// TracerProvider → all per-dispatcher Tracers, so a StartSpan() call
// from one dispatcher can race with another dispatcher's call against
// the same xoroshiro128+ state. The class therefore guards Next64()
// with a small mutex; ID generation is one-call-per-span and well
// outside the hot byte-shuffling path so the contention is negligible
// in practice.
class RandomSource {
public:
    RandomSource();
    explicit RandomSource(uint64_t seed);

    TraceId NewTraceId() noexcept;
    SpanId  NewSpanId() noexcept;

private:
    std::mutex state_mtx_;
    uint64_t state_lo_ = 0;
    uint64_t state_hi_ = 0;
    uint64_t Next64() noexcept;  // takes state_mtx_
};

}  // namespace OBSERVABILITY_NAMESPACE
