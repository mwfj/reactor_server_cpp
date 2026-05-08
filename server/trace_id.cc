#include "observability/trace_id.h"

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Decode one hex character. Returns 0xff on invalid input — callers
// detect failure via the resulting all-zero bytes failing IsValid().
inline uint8_t HexNibble(char c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + c - 'A');
    return 0xff;
}

inline char NibbleHex(uint8_t n) noexcept {
    static constexpr const char digits[] = "0123456789abcdef";
    return digits[n & 0x0f];
}

template <size_t N>
bool DecodeHex(std::string_view hex, std::array<uint8_t, N>& out) noexcept {
    if (hex.size() != 2 * N) return false;
    for (size_t i = 0; i < N; ++i) {
        const uint8_t hi = HexNibble(hex[2 * i]);
        const uint8_t lo = HexNibble(hex[2 * i + 1]);
        if (hi == 0xff || lo == 0xff) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

template <size_t N>
std::string EncodeHex(const std::array<uint8_t, N>& in) {
    std::string out;
    out.resize(2 * N);
    for (size_t i = 0; i < N; ++i) {
        out[2 * i]     = NibbleHex(static_cast<uint8_t>(in[i] >> 4));
        out[2 * i + 1] = NibbleHex(static_cast<uint8_t>(in[i] & 0x0f));
    }
    return out;
}

// Hash thread id + clock for a per-dispatcher non-zero seed. Cryptographic
// quality is NOT required (W3C trace ids only need to avoid collision
// across the trace tree, not across the security boundary).
uint64_t SeedFromThreadAndClock() noexcept {
    const auto tid_hash = std::hash<std::thread::id>{}(std::this_thread::get_id());
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return static_cast<uint64_t>(tid_hash) ^
           static_cast<uint64_t>(now);
}

// SplitMix64 — used to expand a single seed into the two 64-bit halves
// of xoroshiro128+ state. Avoids the all-zero state pathology.
uint64_t SplitMix64(uint64_t& s) noexcept {
    s += 0x9E3779B97F4A7C15ULL;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// xoroshiro128+ rotate-left helper.
inline uint64_t Rotl64(uint64_t x, int k) noexcept {
    return (x << k) | (x >> (64 - k));
}

}  // namespace

TraceId TraceId::FromHex(std::string_view hex) noexcept {
    TraceId id;
    if (!DecodeHex(hex, id.bytes)) {
        // Decode failed — return all-zero (which IsValid() rejects).
        id.bytes.fill(0);
    }
    return id;
}

std::string TraceId::ToHex() const { return EncodeHex(bytes); }

SpanId SpanId::FromHex(std::string_view hex) noexcept {
    SpanId id;
    if (!DecodeHex(hex, id.bytes)) {
        id.bytes.fill(0);
    }
    return id;
}

std::string SpanId::ToHex() const { return EncodeHex(bytes); }

RandomSource::RandomSource() : RandomSource(SeedFromThreadAndClock()) {}

RandomSource::RandomSource(uint64_t seed) {
    // Expand the single seed into two 64-bit halves via SplitMix64.
    // Guaranteed non-zero state (xoroshiro128+ requires at least one
    // non-zero word; SplitMix64 with seed!=0 produces non-zero output,
    // and seed==0 still produces non-zero after the first mix).
    state_lo_ = SplitMix64(seed);
    state_hi_ = SplitMix64(seed);
    if (state_lo_ == 0 && state_hi_ == 0) state_lo_ = 1;
}

uint64_t RandomSource::Next64() noexcept {
    // xoroshiro128+ (Vigna 2018). Wrapped in state_mtx_ so concurrent
    // calls from different dispatchers (production wiring shares one
    // RandomSource across all Tracers) don't corrupt the state vector.
    std::lock_guard<std::mutex> lock(state_mtx_);
    const uint64_t s0 = state_lo_;
    uint64_t s1 = state_hi_;
    const uint64_t result = s0 + s1;
    s1 ^= s0;
    state_lo_ = Rotl64(s0, 24) ^ s1 ^ (s1 << 16);
    state_hi_ = Rotl64(s1, 37);
    return result;
}

TraceId RandomSource::NewTraceId() noexcept {
    TraceId id;
    uint64_t lo = Next64();
    uint64_t hi = Next64();
    // Reject the (extremely rare) all-zero outcome — W3C requires
    // non-zero trace-ids. Re-roll until valid.
    while (lo == 0 && hi == 0) {
        lo = Next64();
        hi = Next64();
    }
    std::memcpy(id.bytes.data(),     &hi, 8);
    std::memcpy(id.bytes.data() + 8, &lo, 8);
    return id;
}

SpanId RandomSource::NewSpanId() noexcept {
    SpanId id;
    uint64_t v = Next64();
    while (v == 0) v = Next64();
    std::memcpy(id.bytes.data(), &v, 8);
    return id;
}

}  // namespace OBSERVABILITY_NAMESPACE
