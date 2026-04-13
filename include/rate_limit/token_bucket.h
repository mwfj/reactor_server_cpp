#pragma once

#include "common.h"
// <chrono> provided by common.h

class TokenBucket {
public:
    // Construct with rate (requests/sec) and capacity (max burst).
    // Both are stored internally as millitokens for integer precision.
    TokenBucket(double rate, int64_t capacity);

    // Try to consume one token. Returns true if allowed, false if denied.
    // NOT thread-safe — caller must hold external lock.
    bool TryConsume();

    // Return current available tokens (whole tokens, after lazy refill).
    // NOT thread-safe — caller must hold external lock.
    int64_t AvailableTokens() const;

    // Return the capacity in whole tokens.
    int64_t Capacity() const { return capacity_mt_ / MILLITOKENS_PER_TOKEN; }

    // Return the current rate in tokens per second.
    double Rate() const { return static_cast<double>(rate_mt_) / MILLITOKENS_PER_TOKEN; }

    // Return the current rate as stored internally (millitokens per second).
    // Used by RateLimitZone's lazy-update check for exact integer
    // comparison — avoids false "change detected" triggers from
    // floating-point round-trip (e.g., rate=0.3 → 299 mt/sec → 0.299 ≠ 0.3).
    int64_t RateMillitokens() const { return rate_mt_; }

    // Seconds until at least one token is available (0 if tokens >= 1).
    // Used for Retry-After header computation.
    double SecondsUntilAvailable() const;

    // Update rate and capacity (for hot-reload). Preserves current token
    // count (clamped to new capacity). NOT thread-safe.
    void UpdateConfig(double rate, int64_t capacity);

private:
    static constexpr int64_t MILLITOKENS_PER_TOKEN = 1000;

    int64_t rate_mt_;          // millitokens per second
    int64_t capacity_mt_;      // max millitokens
    mutable int64_t tokens_mt_;                                      // current millitokens
    mutable std::chrono::steady_clock::time_point last_refill_time_; // last refill timestamp

    // Lazy refill: compute tokens from elapsed time.
    void Refill() const;
};
