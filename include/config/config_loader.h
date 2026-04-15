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
    static void Validate(const ServerConfig& config);

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

    // Return a ServerConfig with all default values.
    static ServerConfig Default();

    // Serialize a ServerConfig to formatted JSON string.
    static std::string ToJson(const ServerConfig& config);
};
