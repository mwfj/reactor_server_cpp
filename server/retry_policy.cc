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

    // Full jitter: random(0, min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2^attempt))
    // Industry-standard algorithm (AWS Architecture Blog, Envoy proxy).
    // Spreads retries uniformly across [0, upper_bound) to prevent
    // synchronized retry waves from multiple clients.
    int upper_bound;
    static constexpr int MAX_SAFE_SHIFT = 10;
    if (attempt < MAX_SAFE_SHIFT) {
        upper_bound = BASE_BACKOFF_MS * (1 << attempt);
        if (upper_bound > MAX_BACKOFF_MS) {
            upper_bound = MAX_BACKOFF_MS;
        }
    } else {
        upper_bound = MAX_BACKOFF_MS;
    }

    // Defensive guard: if constants were ever changed to make upper_bound
    // zero, dist(0, -1) would be undefined behavior.
    if (upper_bound <= 0) {
        return std::chrono::milliseconds(0);
    }

    std::uniform_int_distribution<int> dist(0, upper_bound - 1);
    return std::chrono::milliseconds(dist(rng));
}
