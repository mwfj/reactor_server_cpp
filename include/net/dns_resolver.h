#pragma once
#include "common.h"
#include "inet_addr.h"

#include <future>

// Forward declaration keeps netdb.h out of consumers of this header. The
// .cc includes <netdb.h> to get the real definition.
struct addrinfo;

namespace NET_DNS_NAMESPACE {

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
// DnsConfig — reloadable subset lives alongside ServerConfig
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
// ResolvedEndpoint carries NO `authority` field.
// Callers that need the RFC 3986 authority form compute it on demand
// via DnsResolver::FormatAuthority(addr.Ip(), addr.Port()). Matches the
// upstream pattern and avoids stale-cache bugs after port mutation

// Canonical map type for "upstream name → resolved endpoint". Shared
// between HttpServer::upstream_resolved_, UpstreamManager's production ctor, and UpdateResolvedEndpoints
using ResolvedMap = std::unordered_map<
    std::string, std::shared_ptr<const ResolvedEndpoint>>;

// ---------------------------------------------------------------------------
// ResolverSnapshot — point-in-time counter snapshot for /stats rendering.
//
// Resolver-internal counters only. Reload-mechanism counters (e.g.
// total_reload_stale_served) are owned by HttpServer, not DnsResolver.
// ---------------------------------------------------------------------------
struct ResolverSnapshot {
    int64_t total_resolutions         = 0;   // every completed resolve (success + fail + timeout)
    int64_t total_resolutions_failed  = 0;   // getaddrinfo returned error (non-saturation)
    int64_t total_resolutions_timeout = 0;   // queue-time or in-flight deadline expired
    int64_t queue_depth               = 0;   // current pending-queue size (instantaneous)
    int64_t in_flight                 = 0;   // current workers running getaddrinfo
    int64_t queued                    = 0;   // alias for queue_depth (schema back-compat)
    int64_t completed                 = 0;   // alias for total_resolutions (schema back-compat)
    int64_t eai_again                 = 0;   // saturation rejections (queue >= cap)
};

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
// Detach-not-join teardown: ~DnsResolver sets shutdown, wakes
// queued futures with shutdown-error results, detaches every worker.
// Wedged workers (uncancellable getaddrinfo) leak 256 KB stack until
// process exit — accepted cost for teardown-latency safety.
//
// Pure static helpers (FormatAuthority, IsValidHostOrIpLiteral, etc.)
// are stateless and safe to call from any thread, including threads
// that don't own a DnsResolver instance.
class DnsResolver {
public:
    // Absolute queue limit. NOT proportional to resolver_max_inflight
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

    // Per-instance test seam — replaces the getaddrinfo body.
    // Ownership rule: the callable MUST own every piece of state it
    // references because it may outlive the resolver under detach-not-
    // join teardown. Capture by value or shared_ptr; raw references to
    // fixture state are FORBIDDEN.
    void SetResolverForTesting(std::function<ResolvedEndpoint(const ResolveRequest&)> fn);

    // Test-only override for the queue cap. Production always uses
    // `kMaxQueuedItems` (10 000) — realistic deployments never approach
    // that value. Tests that need to exercise the saturation-sweep path
    // with a small synthetic queue (e.g. 4 items) set this before the
    // first ResolveAsync. Not exposed through DnsConfig — this is not
    // an operator knob, just a unit-test hook.
    void SetMaxQueuedItemsForTesting(std::size_t cap);

    // Static pure helpers — stateless; safe from any thread.
    static bool IsValidHostOrIpLiteral(const std::string& s);
    static bool IsIpLiteral(const std::string& s);
    static bool ParseHostPort(const std::string& s,
                              std::string* host, int* port);

    // Render an RFC 3986 §3.2.2 authority from a BARE host (no
    // surrounding brackets). IPv6 literals are bracketed automatically.
    // A defensive bracket-strip handles a pre-bracketed IPv6 input
    // gracefully so a caller cannot accidentally produce double
    // brackets — see implementation. Pass `omit_port=true` to elide
    // the `:port` suffix (e.g., for default-port rendering).
    static std::string FormatAuthority(const std::string& host_bare, int port,
                                       bool omit_port = false);

    // Strip surrounding IPv6 brackets and validate the result against
    // `IsValidHostOrIpLiteral`. Returns false on malformed bracketing,
    // embedded NUL, or any input that fails the bare host grammar.
    //
    // A single trailing dot on hostnames is PRESERVED (absolute-FQDN
    // marker for getaddrinfo search-domain suppression) — callers that
    // need a dotless form must pair this with `StripTrailingDot`.
    // TLS/HTTP authority sinks do exactly that; DNS sinks keep the dot.
    static bool NormalizeHostToBare(const std::string& in, std::string* out);

    // Strips ONE trailing '.' if present; returns input otherwise unchanged.
    // Used by TLS SNI derivation (§5.10) AND Host-header derivation
    // (§5.5.1). DNS keeps the dot for absolute-FQDN semantics; TLS/HTTP
    // authority use the dotless form for cert / vhost compatibility.
    static std::string StripTrailingDot(const std::string& s);

    // Return a point-in-time snapshot of resolver-internal counters.
    // Thread-safe: counters are atomics read with relaxed ordering;
    // queue_depth and in_flight are read under state_->mtx for consistency.
    ResolverSnapshot Snapshot() const;

private:
    struct WorkItem;
    struct PoolState;

    std::shared_ptr<PoolState> state_;
    std::vector<pthread_t>     workers_;   // detached at ~DnsResolver; empty
                                           // until EnsurePoolStarted runs.
    // Dedicated timeout-reaper thread. Spawned lazily alongside workers
    // so the "literal-only resolver = zero threads" property is preserved.
    // Wakes on cv.wait_until(earliest_deadline) and evicts any queue
    // item whose deadline has passed — without requiring follow-up
    // traffic or a non-wedged worker. Stored as 0 when not spawned.
    // Detached at ~DnsResolver (same contract as workers).
    pthread_t                  reaper_ = 0;
    std::once_flag             pool_started_;
    DnsConfig                  config_;
    // Instance override of kMaxQueuedItems. Defaults to the class
    // constant; only SetMaxQueuedItemsForTesting changes it. Read under
    // state_->mtx inside ResolveAsync, so the test-only setter acquires
    // the same lock to avoid a data race.
    std::size_t                max_queued_items_ = kMaxQueuedItems;

    // Lazy pool spawn. Called from ResolveAsync on the first
    // non-literal request. Throws std::runtime_error on pthread_create
    // failure AFTER cleaning up any workers already spawned (detach).
    void EnsurePoolStarted();

    // Shared submission path. Contains every step the public ResolveAsync
    // runs (host/port validation, literal short-circuit, pool spawn,
    // queue sweep, enqueue) EXCEPT deadline computation. The caller
    // supplies an absolute `item_deadline`, which is stored in the
    // queued WorkItem and consumed by both the submission-side sweep AND
    // the reaper thread — so caller-visible expiry and internal item
    // eviction are guaranteed to agree, even when the caller's dispatch
    // frame (e.g. ResolveMany's `dispatch_time`) is earlier than the
    // per-item `now()` at submission.
    //
    // Callers MUST have already applied LookupFamily::kUnset → config
    // and timeout == 0 → config substitutions on `req` before calling.
    // The public `ResolveAsync` does this and then computes an item
    // deadline anchored at its own `now()` (preserving the single-caller
    // budget contract); `ResolveMany` does it once per batch and then
    // passes dispatch-anchored deadlines per entry (so timed-out batch
    // entries are evicted from the resolver state at the same instant
    // the caller reports them as timed out — no orphaned queue/in-flight
    // items bleeding past the batch boundary).
    std::future<ResolvedEndpoint> ResolveAsyncImpl(
        ResolveRequest req,
        std::chrono::steady_clock::time_point item_deadline);

    // Worker entry. The trampoline takes a heap-allocated
    // shared_ptr<PoolState> by pointer so pthread_create's void* argument
    // can transfer ownership across the thread boundary.
    static void* WorkerTrampoline(void* raw);

    // Reaper entry. Same ownership transfer pattern as WorkerTrampoline.
    // Enforces per-request timeouts for items sitting in state_->queue
    // when no worker is available to pop them and no follow-up
    // ResolveAsync call has triggered the submission-side sweep. See
    // the comment at the member declaration above for the full contract.
    static void* TimeoutReaperTrampoline(void* raw);

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

// Reload-time merge of a fresh DNS batch against the current live ResolvedMap.
//
// For each entry in `batch`:
//   - On success: a fresh shared_ptr<const ResolvedEndpoint> enters the result.
//   - On failure + stale_on_error=true: the live entry is preserved; a warn
//     is emitted per stale fallback.
//   - On failure + stale_on_error=false: the caller is expected to have already
//     short-circuited before calling this. Defensively preserves the live entry
//     and logs an error so a programming error never propagates a half-formed map.
//
// Emits an info log per IP change: "Reload: IP changed for upstream=X A -> B".
// Live entries whose service name is NOT in `batch` are preserved (defensive).
//
// stale_counter: if non-null, incremented (relaxed) for each entry that falls
// back to the live map due to a resolve failure with stale_on_error=true.
// Owned by HttpServer; nullptr is accepted for test callers that don't track it.
ResolvedMap MergeResolvedForReload(const ResolvedMap& live,
                                    const std::vector<ResolvedEndpoint>& batch,
                                    bool stale_on_error,
                                    std::atomic<uint64_t>* stale_counter = nullptr);

}  // namespace NET_DNS_NAMESPACE
