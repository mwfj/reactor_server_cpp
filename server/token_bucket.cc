#include "rate_limit/token_bucket.h"

TokenBucket::TokenBucket(double rate, int64_t capacity)
    : rate_mt_(static_cast<int64_t>(rate * MILLITOKENS_PER_TOKEN)),
      capacity_mt_(capacity * MILLITOKENS_PER_TOKEN),
      tokens_mt_(capacity * MILLITOKENS_PER_TOKEN),
      last_refill_time_(std::chrono::steady_clock::now())
{
}

void TokenBucket::Refill() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_refill_time_).count();
    if (elapsed_ms <= 0) return;
    if (rate_mt_ <= 0) return;

    // Fill-in-one-shot fast path for very long idle intervals.
    // We compare in seconds to avoid the multiplication overflow that
    // `elapsed_ms > capacity_mt_ * 1000 / rate_mt_` would have on large
    // capacities (capacity_mt_ * 1000 overflows above ~9.2e12).
    // Integer division fill_sec = capacity_mt_ / rate_mt_ always fits.
    {
        int64_t fill_sec = capacity_mt_ / rate_mt_;
        if (elapsed_ms / 1000 > fill_sec) {
            tokens_mt_ = capacity_mt_;
            last_refill_time_ = now;
            return;
        }
    }

    // Compute tokens to add: rate_mt_ (millitokens/sec) * elapsed_ms / 1000
    int64_t add = rate_mt_ * elapsed_ms / 1000;

    if (add == 0) {
        // Not enough elapsed time to accrue even one millitoken at this rate.
        // Do NOT advance last_refill_time_ — otherwise repeated probes at
        // intervals shorter than 1000/rate_mt_ ms would discard the
        // fractional refill credit and a low-rate bucket would never recover.
        return;
    }

    tokens_mt_ = std::min(capacity_mt_, tokens_mt_ + add);
    // Advance last_refill_time_ by exactly the time that produced `add`
    // millitokens. The truncation remainder (elapsed_ms - consumed_ms)
    // stays as credit for the next Refill() call.
    int64_t consumed_ms = (add * 1000) / rate_mt_;
    last_refill_time_ += std::chrono::milliseconds(consumed_ms);
}

bool TokenBucket::TryConsume() {
    Refill();
    if (tokens_mt_ >= MILLITOKENS_PER_TOKEN) {
        tokens_mt_ -= MILLITOKENS_PER_TOKEN;
        return true;
    }
    return false;
}

int64_t TokenBucket::AvailableTokens() const {
    Refill();
    return tokens_mt_ / MILLITOKENS_PER_TOKEN;
}

double TokenBucket::SecondsUntilAvailable() const {
    Refill();
    if (tokens_mt_ >= MILLITOKENS_PER_TOKEN) return 0.0;
    if (rate_mt_ <= 0) return 0.0;
    int64_t deficit = MILLITOKENS_PER_TOKEN - tokens_mt_;
    return static_cast<double>(deficit) / static_cast<double>(rate_mt_);
}

void TokenBucket::UpdateConfig(double rate, int64_t capacity) {
    // Materialize tokens accrued under the old rate before switching.
    // Without this, the next Refill() would charge pre-reload idle
    // time at the new rate, causing a sudden token jump.
    Refill();
    rate_mt_ = static_cast<int64_t>(rate * MILLITOKENS_PER_TOKEN);
    capacity_mt_ = capacity * MILLITOKENS_PER_TOKEN;
    if (tokens_mt_ > capacity_mt_) {
        tokens_mt_ = capacity_mt_;
    }
}
