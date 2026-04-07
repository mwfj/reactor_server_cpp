#include "upstream/retry_policy.h"
#include <random>

RetryPolicy::RetryPolicy(const Config& config)
    : config_(config)
{
}

bool RetryPolicy::IsIdempotent(const std::string& method) {
    // RFC 7231 section 4.2.2: safe/idempotent methods
    return method == "GET"
        || method == "HEAD"
        || method == "PUT"
        || method == "DELETE"
        || method == "OPTIONS"
        || method == "TRACE";
}

bool RetryPolicy::ShouldRetry(int attempt, const std::string& method,
                               RetryCondition condition,
                               bool headers_sent) const {
    // Cannot retry after response headers have been sent to client
    if (headers_sent) {
        return false;
    }

    // Exhausted retry budget
    if (attempt >= config_.max_retries) {
        return false;
    }

    // Check if the condition matches the policy
    bool condition_allowed = false;
    switch (condition) {
        case RetryCondition::CONNECT_FAILURE:
            condition_allowed = config_.retry_on_connect_failure;
            break;
        case RetryCondition::RESPONSE_5XX:
            condition_allowed = config_.retry_on_5xx;
            break;
        case RetryCondition::RESPONSE_TIMEOUT:
            condition_allowed = config_.retry_on_timeout;
            break;
        case RetryCondition::UPSTREAM_DISCONNECT:
            condition_allowed = config_.retry_on_disconnect;
            break;
    }

    if (!condition_allowed) {
        return false;
    }

    // Non-idempotent methods require explicit opt-in
    if (!IsIdempotent(method) && !config_.retry_non_idempotent) {
        return false;
    }

    return true;
}

std::chrono::milliseconds RetryPolicy::BackoffDelay(int attempt) const {
    // First retry (attempt 0): immediate
    if (attempt <= 0) {
        return std::chrono::milliseconds(0);
    }

    // Thread-local random engine for jitter
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> jitter_dist(0, BASE_BACKOFF_MS - 1);

    // Exponential backoff: BASE_BACKOFF_MS * 2^(attempt-1) + jitter
    int exponent = attempt - 1;
    int base_delay = BASE_BACKOFF_MS;

    // Guard against overflow. max_retries is capped at 10 (RetryPolicy::Config
    // validation), so the maximum exponent is 9. 25 * 2^9 = 12800, well within
    // int range. Use MAX_SAFE_SHIFT = 10 to provide headroom for any future
    // limit increase while still preventing overflow on pathological inputs.
    static constexpr int MAX_SAFE_SHIFT = 10;
    if (exponent < MAX_SAFE_SHIFT) {
        base_delay = BASE_BACKOFF_MS * (1 << exponent);
    } else {
        base_delay = MAX_BACKOFF_MS;
    }

    int jitter = jitter_dist(rng);
    int total = base_delay + jitter;

    // Cap at maximum
    if (total > MAX_BACKOFF_MS) {
        total = MAX_BACKOFF_MS;
    }

    return std::chrono::milliseconds(total);
}
