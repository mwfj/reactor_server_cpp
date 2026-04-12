#pragma once

#include "common.h"
// <string>, <chrono> provided by common.h

class RetryPolicy {
public:
    struct Config {
        int max_retries = 0;                    // 0 = no retries
        bool retry_on_connect_failure = true;   // Retry when pool checkout connect fails
        bool retry_on_5xx = false;              // Retry on 5xx response from upstream
        bool retry_on_timeout = false;          // Retry on response timeout
        bool retry_on_disconnect = true;        // Retry when upstream closes mid-response
        bool retry_non_idempotent = false;      // Retry POST/PATCH/DELETE (dangerous)
        // Retry conditions are ORed -- any matching condition triggers a retry.
    };

    // Retry condition enum
    enum class RetryCondition {
        CONNECT_FAILURE,      // Upstream connect failed or refused
        RESPONSE_5XX,         // Upstream returned 5xx status
        RESPONSE_TIMEOUT,     // Response not received within timeout
        UPSTREAM_DISCONNECT   // Upstream closed connection before full response
    };

    explicit RetryPolicy(const Config& config);

    // Check if a retry should be attempted.
    // attempt: current attempt number (0 = first attempt, 1 = first retry, ...)
    // method: HTTP method (for idempotency check)
    // condition: what happened (connect fail, 5xx, timeout, disconnect)
    // headers_sent: true if response headers were already sent to client (never retry)
    bool ShouldRetry(int attempt, const std::string& method,
                     RetryCondition condition, bool headers_sent) const;

    // Compute backoff delay for the given attempt number.
    // Uses full jitter with 1ms floor: random(1, min(MAX, BASE * 2^attempt)).
    // Returns 0 for attempt <= 0 (defensive guard; callers typically
    // implement their own first-retry policy and pass attempt >= 1).
    std::chrono::milliseconds BackoffDelay(int attempt) const;

    int MaxRetries() const { return config_.max_retries; }

private:
    Config config_;

    // RFC 7231 section 4.2.2: safe (idempotent) methods
    static bool IsIdempotent(const std::string& method);

    // Base and max backoff for jittered exponential backoff
    static constexpr int BASE_BACKOFF_MS = 25;
    static constexpr int MAX_BACKOFF_MS = 250;
};
