#pragma once
#include "common.h"
#include "inet_addr.h"

#include <future>

// Forward declaration keeps netdb.h out of consumers of this header. The
// .cc includes <netdb.h> to get the real definition.
struct addrinfo;

namespace net_dns {

// ---------------------------------------------------------------------------
// Lookup family selection
// ---------------------------------------------------------------------------
enum class LookupFamily {
    kV4Only,
    kV6Only,
    kV4Preferred,   // operator config default — try A, fall back to AAAA
    kV6Preferred,
    // Sentinel used ONLY as the ResolveRequest.family default. Mirror of
    // the ResolveRequest.timeout==0 sentinel: "fall back to the
    // DnsResolver's DnsConfig.lookup_family at submission time". Never
    // produced by ParseLookupFamily (operators cannot type it in config);
    // never stored in DnsConfig.lookup_family (which defaults to
    // kV4Preferred — a real policy). The substitution in ResolveAsync /
    // ResolveMany replaces kUnset with the resolver's configured policy
    // BEFORE any family-sensitive path runs (literal short-circuit's
    // family check, worker-side AiFamilyFor hint, address picker).
    kUnset,
};

// Parse lowercase strings accepted by the JSON config and env overrides
// ("v4_only", "v6_only", "v4_preferred", "v6_preferred"). Throws
// std::invalid_argument on unknown input so the loader can surface a
// named-field error to operators.
LookupFamily ParseLookupFamily(const std::string& s);

// Stable identifier for logging. Never throws.
const char* LookupFamilyName(LookupFamily f);

// ---------------------------------------------------------------------------
// DnsConfig — reloadable subset lives alongside ServerConfig (§6.1)
// ---------------------------------------------------------------------------
//
// Declared here so the DnsResolver API depends on the config struct
// directly. ServerConfig will own a `DnsConfig dns;` member (wired in
// step 6) and reuse this definition — avoids forward-declaration drift.
struct DnsConfig {
    LookupFamily lookup_family       = LookupFamily::kV4Preferred;
    int          resolve_timeout_ms  = 5000;    // per-entry deadline
    int          overall_timeout_ms  = 15000;   // batch ceiling
    bool         stale_on_error      = true;    // reload: keep last-good on failure
    int          resolver_max_inflight = 32;    // restart-only — §5.2.2
};

// ---------------------------------------------------------------------------
// Request / Response structs
// ---------------------------------------------------------------------------
struct ResolveRequest {
    std::string  host;         // hostname OR bare IP literal (no brackets)
    int          port = 0;
    // Family selector. The sentinel value `kUnset` means "fall back to
    // the DnsResolver's DnsConfig.lookup_family at submission time"
    // (review-round P2 fix). Same contract as the `timeout` sentinel
    // below: callers that need a tighter-than-config override can set
    // a real value (kV4Only / kV6Only / kV4Preferred / kV6Preferred);
    // callers that just want the operator's resolver-wide policy can
    // leave the field at its default. Without this sentinel, a caller
    // that constructs ResolveRequest and only fills host/port would
    // silently run under v4_preferred even when the resolver was
    // configured with v6_only.
    LookupFamily family = LookupFamily::kUnset;
    // Per-entry deadline. The sentinel value 0 ms means "fall back to the
    // DnsResolver's DnsConfig.resolve_timeout_ms at submission time".
    // P1 fix: lets operator-configured `dns.resolve_timeout_ms` propagate
    // without every caller having to read config and thread the value per
    // request. Non-zero values take precedence over the config default,
    // so callers that need a tighter-than-config bound can still opt in.
    std::chrono::milliseconds timeout{0};
    std::string  tag;          // opaque correlation tag ("bind" | "upstream:name")
};

struct ResolvedEndpoint {
    InetAddr                              addr;
    std::string                           host;          // echoed input (still bare)
    int                                   port = 0;
    std::string                           tag;
    std::chrono::steady_clock::time_point resolved_at;
    bool                                  error = false;
    int                                   error_code = 0;
    std::string                           error_message;
};
//
// v0.41 round-40 P2. ResolvedEndpoint carries NO `authority` field.
// Callers that need the RFC 3986 authority form compute it on demand
// via DnsResolver::FormatAuthority(addr.Ip(), addr.Port()). Matches the
// upstream pattern and avoids stale-cache bugs after port mutation
// (e.g. ephemeral-port refresh in §5.4a).

// Canonical map type for "upstream name → resolved endpoint". Shared
// between HttpServer::upstream_resolved_, UpstreamManager's production
// ctor, and UpdateResolvedEndpoints (v0.44 round-43 P1' consistency fix).
using ResolvedMap = std::unordered_map<
    std::string, std::shared_ptr<const ResolvedEndpoint>>;

// ---------------------------------------------------------------------------
// DnsResolver — per-instance pool + pure helpers
// ---------------------------------------------------------------------------
//
// Instance methods own a lazy persistent worker pool (§5.2.9): ctor
// allocates `PoolState` and stashes config but spawns NO threads. The
// first non-literal ResolveAsync triggers EnsurePoolStarted which
// creates `resolver_max_inflight` pthread workers with 256 KB stacks.
// Literal-only servers never trigger pool spawn — zero thread cost.
//
// Detach-not-join teardown (§5.2.4): ~DnsResolver sets shutdown, wakes
// queued futures with shutdown-error results, detaches every worker.
// Wedged workers (uncancellable getaddrinfo) leak 256 KB stack until
// process exit — accepted cost for teardown-latency safety.
//
// Pure static helpers (FormatAuthority, IsValidHostOrIpLiteral, etc.)
// are stateless and safe to call from any thread, including threads
// that don't own a DnsResolver instance.
class DnsResolver {
public:
    // Absolute queue limit (§5.2.2). NOT proportional to resolver_max_inflight
    // — realistic batches never approach 10 000; this is a pathological-
    // case safety fence only. Exceeding returns synchronous EAI_AGAIN
    // "resolver saturated" without enqueueing.
    static constexpr std::size_t kMaxQueuedItems = 10000;

    explicit DnsResolver(const DnsConfig& config);
    ~DnsResolver();

    DnsResolver(const DnsResolver&) = delete;
    DnsResolver& operator=(const DnsResolver&) = delete;
    DnsResolver(DnsResolver&&) = delete;
    DnsResolver& operator=(DnsResolver&&) = delete;

    // O(1) submission: literal short-circuit OR enqueue + return future.
    // Pool spawn (lazy) happens inside on first non-literal call.
    // Never throws — init failures surface as ready error futures
    // (EAI_SYSTEM with "resolver pool init failed: ...").
    std::future<ResolvedEndpoint> ResolveAsync(ResolveRequest req);

    // Dispatch all requests, wait on each up to its own timeout, AND
    // enforce a batch ceiling. Never throws — per-entry errors surface
    // via ResolvedEndpoint::error. Order of returned vector matches
    // order of `requests`.
    //
    // P2 fix (round-hostname-5): per-entry deadlines are measured from
    // BATCH DISPATCH TIME, not from when the wait loop reaches each
    // entry. An earlier implementation reset the budget per-entry at
    // wait time, which silently stretched later entries' effective
    // deadlines by the cumulative wait of earlier ones.
    //
    // Zero `ResolveRequest.timeout` falls back to
    // DnsConfig.resolve_timeout_ms at dispatch time (§5.2 P1).

    // One-arg form — uses DnsConfig.overall_timeout_ms as the batch
    // ceiling. P1 fix: operator-configured overall timeout propagates
    // automatically; callers no longer need to re-read config.
    std::vector<ResolvedEndpoint> ResolveMany(
        std::vector<ResolveRequest> requests);

    // Explicit-ceiling form — used by tests and callers that need a
    // tighter batch bound than DnsConfig.overall_timeout_ms.
    std::vector<ResolvedEndpoint> ResolveMany(
        std::vector<ResolveRequest> requests,
        std::chrono::milliseconds overall_timeout);

    // Per-instance test seam — replaces the getaddrinfo body. Ownership
    // rule (§5.2.3): the callable MUST own every piece of state it
    // references because it may outlive the resolver under detach-not-
    // join teardown. Capture by value or shared_ptr; raw references to
    // fixture state are FORBIDDEN.
    void SetResolverForTesting(
        std::function<ResolvedEndpoint(const ResolveRequest&)> fn);

    // Static pure helpers — stateless; safe from any thread.
    static bool IsValidHostOrIpLiteral(const std::string& s);
    static bool IsIpLiteral(const std::string& s);
    static bool ParseHostPort(const std::string& s,
                              std::string* host, int* port);
    static std::string FormatAuthority(const std::string& host_bare, int port,
                                       bool omit_port = false);
    static bool NormalizeHostToBare(const std::string& in, std::string* out);

    // Strips ONE trailing '.' if present; returns input otherwise unchanged.
    // Used by TLS SNI derivation (§5.10) AND Host-header derivation
    // (§5.5.1). DNS keeps the dot for absolute-FQDN semantics; TLS/HTTP
    // authority use the dotless form for cert / vhost compatibility.
    static std::string StripTrailingDot(const std::string& s);

private:
    struct WorkItem;
    struct PoolState;

    std::shared_ptr<PoolState> state_;
    std::vector<pthread_t>     workers_;   // detached at ~DnsResolver; empty
                                           // until EnsurePoolStarted runs.
    std::once_flag             pool_started_;
    DnsConfig                  config_;

    // Lazy pool spawn (§5.2.9). Called from ResolveAsync on the first
    // non-literal request. Throws std::runtime_error on pthread_create
    // failure AFTER cleaning up any workers already spawned (detach).
    void EnsurePoolStarted();

    // Worker entry. The trampoline takes a heap-allocated
    // shared_ptr<PoolState> by pointer so pthread_create's void* argument
    // can transfer ownership across the thread boundary.
    static void* WorkerTrampoline(void* raw);

    // Blocking getaddrinfo body. Runs on a worker thread.
    static ResolvedEndpoint DoBlockingResolve(const ResolveRequest& req);

    // Helper result builders.
    static ResolvedEndpoint MakeReadyLiteralResult(const ResolveRequest& req);
    static ResolvedEndpoint MakeReadyErrorResult(const ResolveRequest& req,
                                                  int error_code,
                                                  const std::string& msg);
    static ResolvedEndpoint MakeTimeoutResult(const ResolveRequest& req,
                                               const std::string& msg);
};

}  // namespace net_dns
