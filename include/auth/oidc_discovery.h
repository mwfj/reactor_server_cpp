#pragma once

#include "common.h"
// <string>, <memory>, <functional>, <atomic> via common.h

namespace AUTH_NAMESPACE {

class UpstreamHttpClient;

// ---------------------------------------------------------------------------
// OIDC `.well-known/openid-configuration` discovery. One per Issuer with
// `discovery: true`. On success, invokes `on_ready_cb(jwks_uri, introspection_endpoint)`
// which lets Issuer install the endpoints and mark itself ready. On
// failure, schedules a retry after `retry_sec` seconds (bounded; the
// caller controls cancellation via Stop()).
//
// JSON parsing is done with nlohmann::json inside a try/catch so
// attacker-controlled or corrupt discovery responses cannot crash the
// process (§4.5). jwt-cpp is NOT used here — discovery JSON is
// standards-defined but unrelated to JWT.
//
// Dispatcher affinity matches UpstreamHttpClient — completion callbacks
// run on the dispatcher Issue() was called from.
// ---------------------------------------------------------------------------
class OidcDiscovery {
 public:
    OidcDiscovery(std::string issuer_name,
                   std::string issuer_url,
                   std::shared_ptr<UpstreamHttpClient> client,
                   std::string upstream_pool_name,
                   int retry_sec);
    ~OidcDiscovery();

    OidcDiscovery(const OidcDiscovery&) = delete;
    OidcDiscovery& operator=(const OidcDiscovery&) = delete;

    // Start discovery. `dispatcher_index` selects the dispatcher. The
    // `on_ready_cb` is invoked on first successful discovery with the
    // jwks_uri and introspection_endpoint fields extracted from the
    // discovery document. `generation` lets the caller discard stale
    // completions — passed through to the callback so Issuer can gate
    // the installation behind its own generation counter.
    void Start(size_t dispatcher_index,
                uint64_t generation,
                std::function<void(uint64_t generation,
                                    const std::string& jwks_uri,
                                    const std::string& introspection_endpoint)> on_ready_cb);

    // Cancel in-flight discovery. Idempotent.
    void Cancel();

    // Update the retry interval used by the NEXT Start() cycle. Must be
    // called on the reload-driver thread (same synchronization envelope
    // as Issuer::ApplyReload — only Start/Cancel/this from that thread).
    // Issuer::ApplyReload calls this before re-kicking a non-ready
    // discovery cycle so `discovery_retry_sec` is actually live-
    // reloadable. Values <= 0 are clamped to the construction default.
    void SetRetrySec(int retry_sec) noexcept;

    bool IsReady() const noexcept {
        return ready_ && ready_->load(std::memory_order_acquire);
    }

 private:
    // Fwd-declared so header stays pure-data. CycleState owns the recursive
    // retry closure (`run`). OidcDiscovery holds the sole strong reference.
    struct CycleState;

    std::string issuer_name_;
    std::string issuer_url_;
    std::shared_ptr<UpstreamHttpClient> client_;
    std::string upstream_pool_name_;
    int retry_sec_;
    // Both flags are held as shared_ptr<atomic<bool>> so that delayed-retry
    // closures can safely access them after ~OidcDiscovery runs. Raw pointer
    // captures (e.g. `&ready_`) would be UAF if the object is destroyed while
    // a retry task is queued on a Dispatcher.
    std::shared_ptr<std::atomic<bool>> ready_;
    std::shared_ptr<std::atomic<bool>> cancel_token_;
    // Owns the recursive retry closure so delayed-retry callbacks can capture
    // weak_ptr<CycleState> without the closure holding a strong self-reference
    // (which would leak the CycleState forever). Cleared on Cancel() and
    // ~OidcDiscovery so pending weak captures lock null and no-op.
    std::shared_ptr<CycleState> cycle_state_;
};

}  // namespace AUTH_NAMESPACE
