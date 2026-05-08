#include "observability/attr_value.h"

#include <algorithm>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// FNV-1a 64-bit hash. Non-cryptographic; used for SeriesMap bucketing
// where speed matters more than collision resistance (the bucket-walk
// re-checks key/value equality per LabelSet::operator==).
constexpr uint64_t kFnvOffset = 0xcbf29ce484222325ULL;
constexpr uint64_t kFnvPrime  = 0x100000001b3ULL;

inline uint64_t Fnv1aMix(uint64_t h, std::string_view s) noexcept {
    for (char c : s) {
        h ^= static_cast<uint8_t>(c);
        h *= kFnvPrime;
    }
    return h;
}

}  // namespace

void LabelSet::SortAndHash() noexcept {
    std::sort(kv.begin(), kv.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    uint64_t h = kFnvOffset;
    for (const auto& [k, v] : kv) {
        h = Fnv1aMix(h, k);
        // Use 0xff as a key/value separator. The sequence (key, 0xff,
        // value, 0xfe) ensures different (k1+v1, k2+v2) splits hash
        // distinctly even when k1+v1 concat == k2+v2 concat as a
        // single string.
        h ^= 0xffULL;
        h *= kFnvPrime;
        h = Fnv1aMix(h, v);
        h ^= 0xfeULL;
        h *= kFnvPrime;
    }
    hash = h;
}

}  // namespace OBSERVABILITY_NAMESPACE
