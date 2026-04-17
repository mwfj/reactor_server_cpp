#pragma once

#include "config/server_config.h"
#include <string>
#include <stdexcept>
#include <unordered_set>

class ConfigLoader {
public:
    // Load configuration from a JSON file.
    // Throws std::runtime_error if the file cannot be read.
    static ServerConfig LoadFromFile(const std::string& path);

    // Load configuration from a JSON string.
    // Throws std::runtime_error on parse errors.
    static ServerConfig LoadFromString(const std::string& json_str);

    // Apply environment variable overrides to the configuration.
    // Recognized env vars:
    //   REACTOR_BIND_HOST, REACTOR_BIND_PORT,
    //   REACTOR_TLS_ENABLED, REACTOR_TLS_CERT, REACTOR_TLS_KEY,
    //   REACTOR_LOG_LEVEL, REACTOR_LOG_FILE,
    //   REACTOR_MAX_CONNECTIONS, REACTOR_IDLE_TIMEOUT,
    //   REACTOR_WORKER_THREADS, REACTOR_REQUEST_TIMEOUT
    static void ApplyEnvOverrides(ServerConfig& config);

    // Validate the configuration.
    // Throws std::invalid_argument if validation fails.
    //
    // `reload_copy` — set to `true` ONLY by the SIGHUP reload path
    // (HttpServer::Reload / main.cc::ReloadConfig), which passes a
    // ServerConfig with `upstreams` deliberately cleared so that
    // topology-restart-only checks don't run against a stripped copy.
    // When `true`, checks that cross-reference into `upstreams[]` are
    // skipped (the reload path revalidates topology separately via the
    // existing `proxy == o.proxy` equality mechanism).
    //
    // At startup, `reload_copy=false` so ALL cross-reference checks
    // fire — including on programmatic-only deployments (empty
    // `upstreams[]` is a legitimate startup shape, and typos in
    // `auth.issuers.*.upstream` must still surface loudly in that
    // context rather than silently accepting references to pools that
    // don't exist).
    static void Validate(const ServerConfig& config,
                         bool reload_copy = false);

    // Validate ONLY the fields that are live-reloadable without a
    // restart — today this is the per-upstream circuit_breaker block
    // plus a duplicate-name check.
    //
    // Used by the SIGHUP reload path, which downgrades the full
    // `Validate()` failure to a warn because most of its rules cover
    // restart-only fields. That downgrade is unsafe for live-
    // reloadable fields: an invalid breaker threshold would be
    // pushed into live slices even though the same value would be
    // rejected at startup. Call this BEFORE applying a reloaded
    // config and abort the reload if it throws.
    //
    // Scope of CB-field validation:
    //   `live_upstream_names` lists service names CURRENTLY known to
    //   the running server. CB fields are validated only for entries
    //   whose name is in this set, because
    //   `CircuitBreakerManager::Reload` only applies CB changes to
    //   pre-existing hosts (new/removed names are restart-only and
    //   skipped with a warn). Validating CB blocks for not-yet-
    //   running entries would block otherwise-safe reloads — e.g. a
    //   reload that stages a new upstream with an intentionally
    //   placeholder breaker block would abort even though the live
    //   server would never apply it. Pass an empty set when no
    //   upstreams are running yet (only the duplicate-name check
    //   runs in that case).
    //
    // Duplicate-name rejection runs unconditionally on the new
    // config's upstream list: even for new/renamed entries, the
    // file itself is malformed if names collide.
    //
    // Throws std::invalid_argument with a message identifying the
    // offending upstream and field.
    static void ValidateHotReloadable(
        const ServerConfig& config,
        const std::unordered_set<std::string>& live_upstream_names);

    // Validate inline per-proxy auth blocks (structural checks +
    // enforcement-not-yet-wired gate). Runs the SAME per-upstream auth
    // checks that ConfigLoader::Validate() applies inline, but exposed
    // as a separate entry point so callers can run them on the REAL
    // (non-stripped) `upstreams[]` list even when the full Validate is
    // called on a reload-stripped copy.
    //
    // Motivation: HttpServer::Reload() strips `upstreams[]` from its
    // validation copy to skip topology-restart-only checks
    // (UpstreamTlsConfig/Pool ranges/etc.). That stripping also skips
    // the per-upstream inline-auth loop, so an operator reload that
    // sets `proxy.auth.enabled=true` or a bad inline issuer reference
    // would slip through the strict reload gate. Reload calls this
    // helper explicitly against the original `new_config` to restore
    // those checks without reintroducing the topology-restart noise.
    //
    // Runs (against `config.upstreams`):
    //   - on_undetermined value check
    //   - issuer references resolve to `config.auth.issuers`
    //   - populated-inline-auth requires non-empty `proxy.route_prefix`
    //   - populated-inline-auth requires LITERAL byte-prefix
    //     (rejects route_trie patterns because the auth matcher is
    //     literal-only)
    //   - enforcement-not-yet-wired gate: rejects `proxy.auth.enabled=true`
    //     until request-time enforcement is wired (design spec §14 Phase 2)
    //
    // Does NOT run collision detection — that requires the cross-source
    // view (inline + top-level applies_to) which the full Validate owns.
    //
    // Idempotent with the inline-auth branch inside Validate(): at
    // startup the full Validate runs the same logic once; this helper
    // is safe to call a second time with the same config (all checks
    // are pure / side-effect-free / deterministic).
    //
    // Throws std::invalid_argument with an `upstreams['name'].proxy.auth...`
    // message on failure.
    static void ValidateProxyAuth(const ServerConfig& config);

    // Return a ServerConfig with all default values.
    static ServerConfig Default();

    // Serialize a ServerConfig to formatted JSON string.
    static std::string ToJson(const ServerConfig& config);
};
