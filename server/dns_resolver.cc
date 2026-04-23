#include "net/dns_resolver.h"
#include "log/logger.h"

#include <netdb.h>
#include <pthread.h>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <list>   // PoolState::in_flight (shared-owned WorkItems in flight)

namespace NET_DNS_NAMESPACE {

// ---------------------------------------------------------------------------
// Internal pool-state types. Defined in the .cc so the header stays tight.
// ---------------------------------------------------------------------------

struct DnsResolver::WorkItem {
    ResolveRequest                              req;
    std::chrono::steady_clock::time_point       deadline;
    std::promise<ResolvedEndpoint>              promise;
    // Guarded by PoolState::mtx. Set to true by whichever of {worker,
    // reaper, dtor} first calls promise.set_value on this item; the
    // others then skip their own set_value and skip any iterator erase
    // on the in-flight list (the winner handled it). Review-round P1:
    // enables the reaper to safely expire items that have already been
    // popped off the queue by a worker but are still in-flight in the
    // worker's blocking DoBlockingResolve / test seam.
    bool                                        done = false;
};

struct DnsResolver::PoolState {
    std::mutex                                            mtx;
    std::condition_variable                               cv;
    // Pending items awaiting a worker. Shared-owned so that once a
    // worker pops and moves into `in_flight`, both the worker's stack
    // reference and the in_flight list refer to the SAME WorkItem —
    // letting the reaper expire in-flight items via the `done` flag
    // without fighting the worker for promise ownership.
    std::deque<std::shared_ptr<WorkItem>>                 queue;
    // Items currently being processed by workers (popped from `queue`,
    // blocking in DoBlockingResolve / seam). Reaper scans this list for
    // expired items and races the worker via WorkItem::done — first to
    // flip done wins the promise. Review-round P1 addition.
    std::list<std::shared_ptr<WorkItem>>                  in_flight;
    std::atomic<bool>                                     shutting_down{false};
    std::function<ResolvedEndpoint(const ResolveRequest&)> test_seam;
};

// ---------------------------------------------------------------------------
// LookupFamily helpers
// ---------------------------------------------------------------------------

LookupFamily ParseLookupFamily(const std::string& s) {
    if (s == "v4_only")      return LookupFamily::kV4Only;
    if (s == "v6_only")      return LookupFamily::kV6Only;
    if (s == "v4_preferred") return LookupFamily::kV4Preferred;
    if (s == "v6_preferred") return LookupFamily::kV6Preferred;
    throw std::invalid_argument(
        "dns.lookup_family must be one of "
        "v4_only|v6_only|v4_preferred|v6_preferred, got '" + s + "'");
}

const char* LookupFamilyName(LookupFamily f) {
    switch (f) {
        case LookupFamily::kV4Only:      return "v4_only";
        case LookupFamily::kV6Only:      return "v6_only";
        case LookupFamily::kV4Preferred: return "v4_preferred";
        case LookupFamily::kV6Preferred: return "v6_preferred";
        case LookupFamily::kUnset:       return "unset";
    }
    return "unknown";
}

namespace {

// ---------------------------------------------------------------------------
// Static helpers — local to this TU
// ---------------------------------------------------------------------------

// Strict IPv4 dotted-quad pre-filter: exactly four dot-separated
// segments, each 1-3 ASCII digits, each value <= 255, and NO leading
// zero unless the octet is literally "0". Applied BEFORE inet_pton so
// the accept / reject decision is identical across glibc (strict) and
// BSD libc (lenient on leading zeros). Without this, macOS
// `inet_pton(AF_INET, "0127.0.0.1")` returns 1 while glibc returns 0,
// and the "reject legacy numeric-dotted forms" contract documented in
// IsValidHostnameLabeled (no letter or hyphen → reject) never gets a
// chance to run because ParseLiteral short-circuits first.
bool IsStrictIpv4Literal(const std::string& s) {
    if (s.empty() || s.size() > 15) return false;  // "255.255.255.255"
    int dots = 0;
    std::size_t seg_start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        const bool at_boundary = (i == s.size() || s[i] == '.');
        if (at_boundary) {
            const std::size_t len = i - seg_start;
            if (len < 1 || len > 3) return false;
            // Reject leading zero unless the segment is exactly "0".
            if (len > 1 && s[seg_start] == '0') return false;
            int value = 0;
            for (std::size_t k = seg_start; k < i; ++k) {
                const unsigned char c = static_cast<unsigned char>(s[k]);
                if (!std::isdigit(c)) return false;
                value = value * 10 + (c - '0');
            }
            if (value > 255) return false;
            if (i == s.size()) break;
            ++dots;
            seg_start = i + 1;
        }
    }
    return dots == 3;
}

// Accept an IPv6 literal. BSD `inet_pton(AF_INET6, ...)` accepts
// `%<zone>` suffixes per RFC 4007 (fe80::1%eth0 / fe80::1%5) and stores
// the scope_id in sin6_scope_id; glibc rejects them. Phase 1 of the
// IPv6 design explicitly rejects scope-id forms (§1.2.7) because they
// leak into `X-Forwarded-For` / ACL / rate-limit pipelines that cannot
// parse zone-id. Pre-filter `%` out before inet_pton so macOS and
// Linux agree.
bool ParseIpv6Literal(const std::string& s) {
    if (s.empty()) return false;
    if (s.find('%') != std::string::npos) return false;   // §1.2.7
    unsigned char buf[sizeof(struct in6_addr)];
    return ::inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

// Accept an IPv4 OR IPv6 literal. Strict cross-platform: uses
// `IsStrictIpv4Literal` for the v4 gate and `ParseIpv6Literal`
// (which rejects scope-id) for the v6 gate.
bool ParseLiteral(const std::string& s) {
    if (s.empty()) return false;
    if (IsStrictIpv4Literal(s)) return true;
    return ParseIpv6Literal(s);
}

// RFC 3986 §3.2.3 port = *DIGIT, capped by implementations at 16 bits.
// Strict parser: accepts 1-5 ASCII digits forming a value in [0, 65535]
// with no leading zeros (except the literal "0"). Rejects everything
// else.
//
// Review-round fix replaces std::stoi, which silently accepted:
//   - trailing non-digit junk ("443junk" -> 443)
//   - negative sign ("-1" -> -1)
//   - out-of-uint16_t range ("70000" -> 70000, later truncated)
//   - leading whitespace (" 80" -> 80)
// Any of those let malformed authority input reach InetAddr's uint16_t
// port field, silently targeting the wrong port instead of failing
// closed.
bool ParseUnsignedPort(const std::string& s, int* out) {
    if (s.empty() || s.size() > 5) return false;
    // Single "0" is OK; "01", "00443" are not (avoids ambiguity with
    // historical octal interpretation elsewhere in the toolchain).
    if (s.size() > 1 && s[0] == '0') return false;
    int value = 0;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        value = value * 10 + (c - '0');
        if (value > 65535) return false;
    }
    if (out) *out = value;
    return true;
}

// RFC 952 + 1123 hostname label grammar. Accepts one trailing '.' for
// absolute FQDN (v0.30 round-29 P2). Rejects two-or-more trailing dots,
// labels longer than 63 chars, totals longer than 253 chars, pure
// integers, leading dots, or invalid characters.
bool IsValidHostnameLabeled(const std::string& input) {
    if (input.empty()) return false;

    // Strip exactly one trailing '.' for the label grammar check. The
    // validator accepts "host.example.com." but rejects "host..".
    std::string s = input;
    bool had_trailing_dot = false;
    if (s.back() == '.') {
        s.pop_back();
        had_trailing_dot = true;
    }
    if (s.empty()) return false;   // input was just "."
    if (s.back() == '.') return false;   // two-or-more trailing dots
    (void)had_trailing_dot;

    if (s.size() > 253) return false;

    // Review-round fix: reject ANY string composed entirely of digits
    // and dots. Strict IPv4 literals are already handled by inet_pton
    // BEFORE this validator runs (see IsValidHostOrIpLiteral), so
    // anything that reaches here with only digits-and-dots is a legacy
    // numeric-dotted form ("1", "1.2.3", "0127.0.0.1", "1.1.1.1.1")
    // that glibc / BSD's NSS layer in getaddrinfo may reinterpret via
    // inet_aton's classful / octal parsing and resolve to an unintended
    // IP. Strictly subsumes the old "all-digits" check ("1" → 0.0.0.1)
    // and extends it to dotted forms ("1.2.3" → 1.2.0.3, "0127.0.0.1"
    // → 87.0.0.1 via octal). The distinguishing property of a real
    // hostname vs a numeric form is the presence of at least one
    // letter or hyphen — inet_aton rejects both, so any label with a
    // letter or hyphen cannot be reinterpreted numerically.
    bool has_letter_or_hyphen = false;
    for (char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (std::isalpha(u) || c == '-') {
            has_letter_or_hyphen = true;
            break;
        }
    }
    if (!has_letter_or_hyphen) return false;

    // Label-wise check. Labels are 1-63 chars; [A-Za-z0-9-]; cannot start
    // or end with '-'.
    std::size_t label_start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        const bool at_boundary = (i == s.size() || s[i] == '.');
        if (at_boundary) {
            if (i == label_start) return false;           // empty label
            if (i - label_start > 63) return false;       // label too long
            if (s[label_start] == '-' || s[i - 1] == '-') return false;
            label_start = i + 1;
            continue;
        }
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (!(std::isalnum(c) || c == '-')) return false;
    }
    return true;
}

// Build a getaddrinfo ai_family hint from LookupFamily. v4_preferred and
// v6_preferred both use AF_UNSPEC and pick by preference post-resolve.
// kUnset is treated like AF_UNSPEC as a defensive fallback — in the
// normal flow substitution in ResolveAsync / ResolveMany replaces kUnset
// with config_.lookup_family BEFORE reaching this helper, so the case
// here only runs if a caller manages to bypass the substitution path.
int AiFamilyFor(LookupFamily f) {
    switch (f) {
        case LookupFamily::kV4Only: return AF_INET;
        case LookupFamily::kV6Only: return AF_INET6;
        case LookupFamily::kV4Preferred:
        case LookupFamily::kV6Preferred:
        case LookupFamily::kUnset:
        default:                    return AF_UNSPEC;
    }
}

// Walk an addrinfo chain; return the InetAddr matching the preference
// (v4_preferred → prefer AF_INET; v6_preferred → prefer AF_INET6; *_only
// already constrained the chain). Falls back to the other family if the
// preferred one is absent.
InetAddr PickAddress(const struct addrinfo* ai, LookupFamily pref, int port) {
    const struct addrinfo* first_v4 = nullptr;
    const struct addrinfo* first_v6 = nullptr;
    for (const struct addrinfo* cur = ai; cur != nullptr; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET  && first_v4 == nullptr) first_v4 = cur;
        if (cur->ai_family == AF_INET6 && first_v6 == nullptr) first_v6 = cur;
    }
    const struct addrinfo* chosen = nullptr;
    switch (pref) {
        case LookupFamily::kV4Only:      chosen = first_v4; break;
        case LookupFamily::kV6Only:      chosen = first_v6; break;
        case LookupFamily::kV4Preferred: chosen = first_v4 ? first_v4 : first_v6; break;
        case LookupFamily::kV6Preferred: chosen = first_v6 ? first_v6 : first_v4; break;
        case LookupFamily::kUnset:
            // Defensive fallback only — substitution should have replaced
            // kUnset with config_.lookup_family upstream. Treat like
            // kV4Preferred so a bypassed path still returns an address
            // rather than nullptr.
            chosen = first_v4 ? first_v4 : first_v6;
            break;
    }
    if (chosen == nullptr) return InetAddr{};
    return InetAddr::FromAddrInfo(chosen, port);
}

}  // namespace

// ---------------------------------------------------------------------------
// DnsResolver static helpers
// ---------------------------------------------------------------------------

bool DnsResolver::IsIpLiteral(const std::string& s) {
    return ParseLiteral(s);
}

bool DnsResolver::IsValidHostOrIpLiteral(const std::string& s) {
    if (s.empty()) return false;
    if (ParseLiteral(s)) return true;
    return IsValidHostnameLabeled(s);
}

std::string DnsResolver::StripTrailingDot(const std::string& s) {
    if (!s.empty() && s.back() == '.') return s.substr(0, s.size() - 1);
    return s;
}

// Parse "host:port", "[ipv6]:port", or "host" (no port). Returns false
// on malformed input. Bracketed IPv6 forms are supported because they're
// what callers type; the brackets are stripped before returning so the
// caller gets a bare IP literal.
bool DnsResolver::ParseHostPort(const std::string& s,
                                 std::string* host, int* port) {
    if (s.empty() || host == nullptr) return false;
    if (s.front() == '[') {
        // RFC 3986 §3.2.2 strict form: IP-literal = "[" (IPv6address /
        // IPvFuture) "]". Hostnames AND IPv4 literals are not permitted
        // inside brackets. This is a stricter variant of the previous
        // round's fix — previously we used `ParseLiteral` (accepts both
        // AF_INET and AF_INET6), which incorrectly accepted
        // `[127.0.0.1]:443`. Callers using ParseHostPort as an authority
        // validator must be able to reject such malformed input.
        const auto rbracket = s.find(']');
        if (rbracket == std::string::npos) return false;
        const std::string inner = s.substr(1, rbracket - 1);
        if (!ParseIpv6Literal(inner)) return false;
        *host = inner;
        if (rbracket + 1 == s.size()) {
            if (port) *port = 0;
            return true;
        }
        if (s[rbracket + 1] != ':') return false;
        const std::string port_str = s.substr(rbracket + 2);
        int p = 0;
        if (!ParseUnsignedPort(port_str, &p)) return false;
        if (port) *port = p;
        return true;
    }
    // Bare IPv6 with colons → no port.
    if (s.find(':') != std::string::npos) {
        if (ParseLiteral(s)) {
            *host = s;
            if (port) *port = 0;
            return true;
        }
        // hostname:port form
        const auto colon = s.rfind(':');
        *host = s.substr(0, colon);
        // Review-round fix: reject empty host (":80" → host=""). Parser
        // must fail-closed on a missing host rather than emit an empty
        // string that downstream validators may or may not catch.
        if (host->empty()) return false;
        // Review-round fix: validate the host token against the full
        // host grammar (IPv4 literal, bare IPv6 literal, or RFC 1123
        // hostname) before declaring parse success. Previously the
        // bare branch returned any substring-before-colon verbatim,
        // letting inputs like "host..bad:80" or "0127.0.0.1:80" succeed
        // despite being rejected by this branch's own validator. Fail-
        // closed at the authority boundary — callers get a single
        // consistent notion of "valid authority host".
        if (!IsValidHostOrIpLiteral(*host)) return false;
        const std::string port_str = s.substr(colon + 1);
        int p = 0;
        if (!ParseUnsignedPort(port_str, &p)) return false;
        if (port) *port = p;
        return true;
    }
    // No colon → whole string is the host, no port.
    *host = s;
    // Review-round fix: same host validation as the colon branch. A
    // caller that passes "host..bad" or "0127.0.0.1" (no port) used to
    // get a successful parse with the malformed host returned verbatim.
    if (!IsValidHostOrIpLiteral(*host)) return false;
    if (port) *port = 0;
    return true;
}

std::string DnsResolver::FormatAuthority(const std::string& host_bare, int port,
                                          bool omit_port) {
    const bool is_v6 = (host_bare.find(':') != std::string::npos);
    std::string out;
    if (is_v6) out = "[" + host_bare + "]";
    else       out = host_bare;
    if (!omit_port) out += ":" + std::to_string(port);
    return out;
}

// Normalize ipv6-bracketed input to a bare form. Callers pass operator
// input ("[::1]") and receive the bare literal ("::1"). Returns false
// on malformed bracketing or on input that doesn't parse as an IP
// literal or a valid hostname.
bool DnsResolver::NormalizeHostToBare(const std::string& in, std::string* out) {
    if (out == nullptr) return false;
    if (in.empty()) return false;
    if (in.front() == '[') {
        // RFC 3986 §3.2.2 strict: brackets are ONLY for IPv6 literals.
        // Review-round fix: IPv4 literals in brackets (e.g.
        // `[127.0.0.1]`) are malformed operator input and must reject.
        // Previously used `ParseLiteral` (IPv4-or-IPv6) — swapped to
        // `ParseIpv6Literal` to match the authority-validation
        // tightening in `ParseHostPort`.
        const auto rbracket = in.find(']');
        if (rbracket == std::string::npos) return false;
        if (rbracket + 1 != in.size()) return false;   // no trailing content
        const std::string inner = in.substr(1, rbracket - 1);
        if (!ParseIpv6Literal(inner)) return false;
        *out = inner;
        return true;
    }
    *out = in;
    return IsValidHostOrIpLiteral(in);
}

// ---------------------------------------------------------------------------
// DnsResolver ctor / dtor / lifecycle
// ---------------------------------------------------------------------------

DnsResolver::DnsResolver(const DnsConfig& config) : config_(config) {
    // Review-round fix: reject non-positive resolver_max_inflight at
    // construction. A zero value means EnsurePoolStarted would run its
    // spawn loop for 0 iterations and succeed WITHOUT creating any
    // workers; every hostname ResolveAsync thereafter would append to
    // state_->queue with nothing to pop, so promises would never
    // complete and DNS resolution would hang permanently. A negative
    // value is even worse: the static_cast<size_t>(-1) in
    // workers_.reserve() yields SIZE_MAX and either throws bad_alloc
    // or attempts to spawn ~2^63 threads.
    //
    // ConfigLoader::Validate (step 6, §5.6) is where this is supposed
    // to be caught in the server's config-loading path. This guard is
    // defense-in-depth for DIRECT DnsResolver construction (tests,
    // future embedders) that bypasses ServerConfig — so the error
    // surfaces immediately at the ctor rather than manifesting as a
    // cryptic "all hostname lookups hang" at runtime.
    if (config.resolver_max_inflight <= 0) {
        throw std::invalid_argument(
            "DnsResolver: resolver_max_inflight must be > 0, got " +
            std::to_string(config.resolver_max_inflight));
    }
    state_ = std::make_shared<PoolState>();
    // NO worker spawn here. EnsurePoolStarted runs lazily on the first
    // non-literal resolve (§5.2.9). Literal-only servers never pay.
}

DnsResolver::~DnsResolver() {
    // Drain queued AND in-flight items under the mutex and wake their
    // futures with a shutdown-error result. Review-round P1: in-flight
    // items were previously NOT reachable from the dtor — the §5.2.4
    // contract narrowing said they relied on their own future.wait_for
    // bound. With the shared_ptr<WorkItem> + `done` flag machinery
    // introduced for the reaper (so it can expire in-flight items at
    // deadline), the dtor can safely set_value on in-flight items too:
    // workers that later return from getaddrinfo see done=true and skip
    // their own set_value. Net effect: every caller's future becomes
    // ready by the time ~DnsResolver returns, not just queued ones.
    {
        std::lock_guard<std::mutex> lk(state_->mtx);
        state_->shutting_down.store(true, std::memory_order_release);
        // Queue drain.
        while (!state_->queue.empty()) {
            auto& item = state_->queue.front();
            if (item && !item->done) {
                item->done = true;
                try {
                    item->promise.set_value(
                        MakeTimeoutResult(item->req, "resolver shutdown"));
                } catch (const std::future_error&) { /* future gone */ }
            }
            state_->queue.pop_front();
        }
        // In-flight drain — set value but leave the list entries so
        // workers can detect `done` when they eventually return and
        // skip their own set_value. The list itself is destroyed when
        // the last shared_ptr<PoolState> reference drops (detach-not-
        // join; may be arbitrarily later for wedged workers).
        for (auto& item : state_->in_flight) {
            if (item && !item->done) {
                item->done = true;
                try {
                    item->promise.set_value(
                        MakeTimeoutResult(item->req, "resolver shutdown"));
                } catch (const std::future_error&) { /* future gone */ }
            }
        }
    }
    state_->cv.notify_all();

    // Detach every worker — NEVER join. Joining a wedged getaddrinfo
    // would hang HttpServer::Stop indefinitely. Wedged workers leak
    // 256 KB stack until process exit (accepted §5.2.4 cost).
    for (pthread_t tid : workers_) {
        pthread_detach(tid);
    }
    workers_.clear();

    // Detach the timeout reaper — same detach-not-join contract. The
    // reaper sees shutting_down via the notify_all above and returns
    // promptly (it's never blocked in getaddrinfo); under normal
    // teardown this thread exits in microseconds.
    if (reaper_ != 0) {
        pthread_detach(reaper_);
        reaper_ = 0;
    }

    // state_ goes out of scope here. PoolState destructs when the last
    // shared_ptr reference is released — which may be inside this dtor
    // (all workers woke and returned) or arbitrarily later (wedged
    // workers still holding their copies). We do NOT promise destructor-
    // time destruction of PoolState; tests assert "no leak observed by
    // teardown", not "destructed at ~DnsResolver".
}

void DnsResolver::EnsurePoolStarted() {
    std::call_once(pool_started_, [this]() {
        workers_.reserve(static_cast<std::size_t>(config_.resolver_max_inflight));

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 256 * 1024);

        try {
            for (int i = 0; i < config_.resolver_max_inflight; ++i) {
                // Heap-allocate the shared_ptr copy so it survives across
                // the pthread_create boundary. Worker takes ownership in
                // WorkerTrampoline and delete's it.
                auto raw = new std::shared_ptr<PoolState>(state_);
                pthread_t tid;
                int rc = pthread_create(&tid, &attr, &WorkerTrampoline, raw);
                if (rc != 0) {
                    delete raw;
                    throw std::runtime_error(
                        "DnsResolver: pthread_create failed at worker " +
                        std::to_string(i) + "/" +
                        std::to_string(config_.resolver_max_inflight) +
                        ": " + std::string(std::strerror(rc)));
                }
                workers_.push_back(tid);
            }

            // Review-round fix: spawn the timeout reaper AFTER workers.
            // One reaper per pool. Same heap-allocated shared_ptr pattern
            // as workers; reaper_ is reset to 0 on spawn failure so the
            // partial-failure cleanup below doesn't try to detach a
            // pthread_t that was never created.
            auto reaper_raw = new std::shared_ptr<PoolState>(state_);
            int reaper_rc = pthread_create(
                &reaper_, &attr, &TimeoutReaperTrampoline, reaper_raw);
            if (reaper_rc != 0) {
                delete reaper_raw;
                reaper_ = 0;
                throw std::runtime_error(
                    "DnsResolver: pthread_create failed for timeout reaper: " +
                    std::string(std::strerror(reaper_rc)));
            }
        } catch (...) {
            // Partial-failure cleanup (§5.2.9). Signal shutdown on the
            // OLD state so already-started workers + reaper exit, then
            // detach them so throw doesn't hang on a wedged thread.
            {
                std::lock_guard<std::mutex> lk(state_->mtx);
                state_->shutting_down.store(true, std::memory_order_release);
            }
            state_->cv.notify_all();
            for (pthread_t tid : workers_) {
                pthread_detach(tid);
            }
            workers_.clear();
            if (reaper_ != 0) {
                pthread_detach(reaper_);
                reaper_ = 0;
            }

            // Replace state_ with a fresh PoolState so a subsequent
            // call_once retry (after transient failure like EAGAIN)
            // starts against a clean shutdown flag. Carry the test seam
            // so injected mocks survive the retry.
            auto carried_seam = std::move(state_->test_seam);
            state_ = std::make_shared<PoolState>();
            state_->test_seam = std::move(carried_seam);

            pthread_attr_destroy(&attr);
            throw;
        }

        pthread_attr_destroy(&attr);
    });
}

// ---------------------------------------------------------------------------
// Worker loop
// ---------------------------------------------------------------------------

void* DnsResolver::WorkerTrampoline(void* raw) {
    // Take ownership of the heap-allocated shared_ptr copy created by
    // EnsurePoolStarted. `state` keeps PoolState alive across the
    // thread's lifetime, outliving ~DnsResolver when needed.
    auto state = *static_cast<std::shared_ptr<PoolState>*>(raw);
    delete static_cast<std::shared_ptr<PoolState>*>(raw);

    while (true) {
        std::shared_ptr<WorkItem> item;
        std::list<std::shared_ptr<WorkItem>>::iterator in_flight_it;
        std::function<ResolvedEndpoint(const ResolveRequest&)> body;

        // Phase 1 (under mtx): pop from queue, splice to in_flight,
        // record the iterator so we can erase on completion. Copy the
        // seam out of PoolState so concurrent SetResolverForTesting
        // cannot mutate our reference mid-call. Do the queue-time
        // deadline short-circuit here too — if already expired, we can
        // shortcut without releasing the mutex.
        {
            std::unique_lock<std::mutex> lk(state->mtx);
            state->cv.wait(lk, [&] {
                return !state->queue.empty() ||
                       state->shutting_down.load(std::memory_order_acquire);
            });
            if (state->shutting_down.load(std::memory_order_acquire) &&
                state->queue.empty()) {
                return nullptr;
            }
            item = std::move(state->queue.front());
            state->queue.pop_front();

            // Review-round P1: move the popped item into the in_flight
            // list so the reaper can expire it at deadline even while
            // the worker is blocked in DoBlockingResolve. Worker holds
            // `item` (shared_ptr) to survive the reaper's erase of
            // `in_flight_it` if the race goes the reaper's way.
            state->in_flight.push_back(item);
            in_flight_it = std::prev(state->in_flight.end());

            // Queue-time deadline short-circuit.
            if (item && !item->done &&
                std::chrono::steady_clock::now() >= item->deadline) {
                item->done = true;
                try {
                    item->promise.set_value(MakeTimeoutResult(
                        item->req, "queue-time exceeded deadline"));
                } catch (const std::future_error&) {}
                state->in_flight.erase(in_flight_it);
                continue;
            }
            // Seam copy under the same lock.
            body = state->test_seam;
        }

        // Phase 2 (no lock): blocking resolve. Long-running.
        ResolvedEndpoint result = body ? body(item->req)
                                       : DoBlockingResolve(item->req);

        // Phase 3 (under mtx): race the reaper on `done`. Whoever
        // flipped `done` first is the unique owner of promise.set_value
        // and the in_flight erase. The loser (reaper already expired
        // this item) skips both — `in_flight_it` may have been
        // invalidated by the reaper's erase but is never dereferenced
        // here.
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            if (!item->done) {
                item->done = true;
                try {
                    item->promise.set_value(std::move(result));
                } catch (const std::future_error&) {}
                state->in_flight.erase(in_flight_it);
            }
            // else: reaper beat us to it and already erased
            // `in_flight_it`. Do nothing — our blocking work is
            // discarded; the caller got the timeout result.
        }
    }
}

// ---------------------------------------------------------------------------
// TimeoutReaperTrampoline — dedicated reaper thread
// ---------------------------------------------------------------------------
//
// Review-round fix: direct ResolveAsync callers need their future to
// transition to READY at req.timeout even when:
//   - the worker pool is stuck in getaddrinfo() (cap=1 + wedge case),
//   - AND no follow-up submission triggers the ResolveAsync sweep,
//   - AND no worker is available to run the post-pop deadline check,
//   - AND (review-round P1 extension) the item has ALREADY been popped
//     by a worker and is in-flight (blocked in getaddrinfo or a slow
//     test seam). Scan both state->queue AND state->in_flight.
//
// The reaper sleeps on cv.wait_until(earliest_deadline); on wake it
// scans both collections and evicts any item whose deadline has passed
// via promise.set_value(MakeTimeoutResult(...)). For in-flight items
// the reaper races the worker's Phase-3 completion via WorkItem::done;
// whichever thread flips `done` first is the unique owner of
// promise.set_value and the in_flight-list erase. Notifications from
// ResolveAsync use notify_all so the reaper also wakes on new items
// with deadlines earlier than its current wait target.
//
// Lifetime: captures shared_ptr<PoolState> by value (heap-allocated
// pointer transfer via pthread_create, same pattern as WorkerTrampoline),
// so the state outlives ~DnsResolver under detach-not-join teardown.
// Exits when state_->shutting_down becomes true.
void* DnsResolver::TimeoutReaperTrampoline(void* raw) {
    auto state = *static_cast<std::shared_ptr<PoolState>*>(raw);
    delete static_cast<std::shared_ptr<PoolState>*>(raw);

    while (true) {
        std::unique_lock<std::mutex> lk(state->mtx);

        if (state->shutting_down.load(std::memory_order_acquire)) {
            return nullptr;
        }

        // Find the earliest deadline across BOTH queue and in_flight.
        // Skip items whose `done` flag is already set — a completed
        // item cannot re-expire, and scanning it would busy-loop the
        // reaper if the worker hasn't yet acquired the mtx to erase it.
        auto earliest = std::chrono::steady_clock::time_point::max();
        for (const auto& item : state->queue) {
            if (item && !item->done && item->deadline < earliest) {
                earliest = item->deadline;
            }
        }
        for (const auto& item : state->in_flight) {
            if (item && !item->done && item->deadline < earliest) {
                earliest = item->deadline;
            }
        }

        // Wait until earliest deadline OR notify. Predicate-less waits
        // so ANY wakeup (notify from ResolveAsync push, deadline timeout,
        // spurious) re-enters the loop and re-computes earliest from the
        // current queue state.
        if (earliest == std::chrono::steady_clock::time_point::max()) {
            state->cv.wait(lk);
        } else {
            state->cv.wait_until(lk, earliest);
        }

        if (state->shutting_down.load(std::memory_order_acquire)) {
            return nullptr;
        }

        // Evict expired items from the queue. Same write/read
        // iteration pattern as the submission-side sweep in
        // ResolveAsync (unambiguous promise set_value semantics for
        // shared_ptr<WorkItem> elements).
        const auto now = std::chrono::steady_clock::now();
        auto write = state->queue.begin();
        for (auto read = state->queue.begin();
             read != state->queue.end(); ++read) {
            auto& sp = *read;
            if (sp && sp->deadline <= now) {
                if (!sp->done) {
                    sp->done = true;
                    try {
                        sp->promise.set_value(MakeTimeoutResult(
                            sp->req, "queue-time exceeded deadline"));
                    } catch (const std::future_error&) {}
                }
                // Skip: drop from the new queue.
            } else {
                if (write != read) {
                    *write = std::move(*read);
                }
                ++write;
            }
        }
        state->queue.erase(write, state->queue.end());

        // Evict expired items from in_flight. Here we ALSO erase on
        // winning the `done` CAS — worker's Phase-3 completion sees
        // done=true and skips its own erase (iterator would be invalid
        // anyway). If we LOSE the race (worker finished first and is
        // about to acquire the mtx), skip — worker will erase.
        for (auto it = state->in_flight.begin();
             it != state->in_flight.end(); ) {
            auto& sp = *it;
            if (sp && sp->deadline <= now) {
                if (!sp->done) {
                    sp->done = true;
                    try {
                        sp->promise.set_value(MakeTimeoutResult(
                            sp->req, "queue-time exceeded deadline"));
                    } catch (const std::future_error&) {}
                    it = state->in_flight.erase(it);
                } else {
                    // Worker already completed this item. Worker will
                    // erase under its own mtx acquisition. Skip.
                    ++it;
                }
            } else {
                ++it;
            }
        }
    }
}

ResolvedEndpoint DnsResolver::DoBlockingResolve(const ResolveRequest& req) {
    struct addrinfo hints{};
    hints.ai_family   = AiFamilyFor(req.family);
    hints.ai_socktype = SOCK_STREAM;
    // AI_NUMERICSERV: port is numeric; skip getservbyname.
    // AI_ADDRCONFIG deliberately NOT set (§5.2.5) — avoids CI fallibility.
    hints.ai_flags    = AI_NUMERICSERV;

    const std::string port_str = std::to_string(req.port);
    struct addrinfo* res = nullptr;
    const int rc = ::getaddrinfo(req.host.c_str(), port_str.c_str(),
                                  &hints, &res);
    if (rc != 0) {
        ResolvedEndpoint out;
        out.host = req.host;
        out.port = req.port;
        out.tag  = req.tag;
        out.error        = true;
        out.error_code   = rc;
        out.error_message = ::gai_strerror(rc);
        return out;
    }

    InetAddr addr = PickAddress(res, req.family, req.port);
    ::freeaddrinfo(res);

    ResolvedEndpoint out;
    out.host = req.host;
    out.port = req.port;
    out.tag  = req.tag;
    out.resolved_at = std::chrono::steady_clock::now();
    if (!addr.is_valid()) {
        out.error         = true;
        out.error_code    = EAI_NONAME;
        out.error_message = "no address matched requested family";
        return out;
    }
    out.addr = addr;
    return out;
}

ResolvedEndpoint DnsResolver::MakeReadyLiteralResult(const ResolveRequest& req) {
    ResolvedEndpoint out;
    out.host = req.host;
    out.port = req.port;
    out.tag  = req.tag;
    out.resolved_at = std::chrono::steady_clock::now();
    // Literal short-circuit: parse directly without getaddrinfo.
    InetAddr addr(req.host, req.port);
    if (!addr.is_valid()) {
        out.error         = true;
        out.error_code    = EAI_NONAME;
        out.error_message = "literal parse failed";
        return out;
    }
    // For literals we ignore LookupFamily's preference — the operator
    // typed an IP; we use that IP's family as-is. Family constraints
    // (v4_only + IPv6 literal, or vice versa) surface as an error.
    const bool v4 = (addr.family() == InetAddr::Family::kIPv4);
    if (req.family == LookupFamily::kV4Only && !v4) {
        out.error = true;
        out.error_code = EAI_ADDRFAMILY;
        out.error_message = "IPv6 literal rejected under v4_only";
        return out;
    }
    if (req.family == LookupFamily::kV6Only && v4) {
        out.error = true;
        out.error_code = EAI_ADDRFAMILY;
        out.error_message = "IPv4 literal rejected under v6_only";
        return out;
    }
    out.addr = addr;
    return out;
}

ResolvedEndpoint DnsResolver::MakeReadyErrorResult(const ResolveRequest& req,
                                                    int error_code,
                                                    const std::string& msg) {
    ResolvedEndpoint out;
    out.host = req.host;
    out.port = req.port;
    out.tag  = req.tag;
    out.error         = true;
    out.error_code    = error_code;
    out.error_message = msg;
    return out;
}

ResolvedEndpoint DnsResolver::MakeTimeoutResult(const ResolveRequest& req,
                                                 const std::string& msg) {
    return MakeReadyErrorResult(req, EAI_AGAIN, msg);
}

// ---------------------------------------------------------------------------
// ResolveAsync / ResolveMany / SetResolverForTesting
// ---------------------------------------------------------------------------

std::future<ResolvedEndpoint>
DnsResolver::ResolveAsync(ResolveRequest req) {
    // Review-round P2 fix: family sentinel falls back to DnsConfig.
    // lookup_family. Substitute BEFORE computing the deadline and before
    // the literal short-circuit inside ResolveAsyncImpl, so the
    // family-constraint branch inside MakeReadyLiteralResult
    // (kV4Only + IPv6 literal → reject, and the symmetric case) fires
    // against the CONFIGURED policy, not against the kUnset sentinel
    // (which those branches would silently ignore, accepting literals
    // that the operator-configured v4_only / v6_only policy intended to
    // reject).
    if (req.family == LookupFamily::kUnset) {
        req.family = config_.lookup_family;
    }

    // P1 fix: zero-timeout sentinel falls back to DnsConfig.resolve_timeout_ms.
    // Substitute BEFORE deadline computation so the WorkItem deadline
    // consistently reflects the effective timeout regardless of caller
    // pattern.
    if (req.timeout.count() == 0) {
        req.timeout = std::chrono::milliseconds(config_.resolve_timeout_ms);
    }

    // Review-round fix (start timeout accounting at submission time):
    // Capture `submission_time` BEFORE `EnsurePoolStarted()` (which runs
    // inside ResolveAsyncImpl) so the per-request budget reflects the
    // caller-visible `req.timeout` as measured from the call into
    // `ResolveAsync`. Without this, the cold-start pool spawn
    // (pthread_create × resolver_max_inflight + reaper; ~50-200 μs each
    // on Linux, up to ~50 ms for large resolver_max_inflight on busy
    // hosts) would silently eat into the caller's budget on the very
    // first hostname request. Only matters for the queue-path item's
    // deadline; literal/error paths return ready futures and don't
    // consume the budget.
    const auto item_deadline =
        std::chrono::steady_clock::now() + req.timeout;
    return ResolveAsyncImpl(std::move(req), item_deadline);
}

std::future<ResolvedEndpoint>
DnsResolver::ResolveAsyncImpl(
    ResolveRequest req,
    std::chrono::steady_clock::time_point item_deadline) {
    // Review-round fix: fail-closed host validation BEFORE any pool
    // interaction. This is the runtime gate; without it, legacy numeric-
    // dotted forms like "0127.0.0.1" or "1.2.3" (already rejected by
    // IsValidHostOrIpLiteral / ConfigLoader) could still reach
    // getaddrinfo via a caller that skipped pre-validation and be
    // reinterpreted by glibc / BSD NSS via inet_aton's classful / octal
    // parsing. Obviously-malformed hosts would also consume a queue slot
    // before failing at the worker. Keeping the runtime path in lockstep
    // with the validator closes both holes: invalid hosts produce a
    // ready error future, pool is untouched, kMaxQueuedItems is
    // preserved for genuine work.
    if (!IsValidHostOrIpLiteral(req.host)) {
        std::promise<ResolvedEndpoint> p;
        auto fut = p.get_future();
        p.set_value(MakeReadyErrorResult(
            req, EAI_NONAME,
            "invalid host '" + req.host +
            "' (must be a bare IP literal or RFC 1123 hostname; "
            "bracketed IPv6 / legacy numeric-dotted forms are not "
            "accepted at the resolver boundary)"));
        return fut;
    }

    // Review-round fix (port range validation at resolver boundary):
    // `InetAddr` silently truncates `port` via `static_cast<uint16_t>`,
    // so a literal caller that constructs a ResolveRequest with
    // port = -1 / 70000 / INT_MAX would otherwise resolve to an
    // unintended endpoint (e.g. -1 → 65535, 70000 → 4464). `ParseHostPort`
    // already rejects the same inputs from the parser path; the runtime
    // gate must match so the public API is self-consistent and
    // fail-closed. Accept [0, 65535]; port 0 is legitimate (ephemeral
    // binds, ResolveRequest default).
    if (req.port < 0 || req.port > 65535) {
        std::promise<ResolvedEndpoint> p;
        auto fut = p.get_future();
        p.set_value(MakeReadyErrorResult(
            req, EAI_NONAME,
            "invalid port " + std::to_string(req.port) +
            " (must be in [0, 65535])"));
        return fut;
    }

    // Literal short-circuit (§5.2.9): ready-future path without
    // spawning the pool. Keeps literal-only servers thread-free.
    if (IsIpLiteral(req.host)) {
        std::promise<ResolvedEndpoint> p;
        auto fut = p.get_future();
        p.set_value(MakeReadyLiteralResult(req));
        return fut;
    }

    // First non-literal resolve spawns the pool (idempotent via call_once).
    try {
        EnsurePoolStarted();
    } catch (const std::exception& e) {
        std::promise<ResolvedEndpoint> p;
        auto fut = p.get_future();
        p.set_value(MakeReadyErrorResult(
            req, EAI_SYSTEM,
            std::string("resolver pool init failed: ") + e.what()));
        return fut;
    }

    auto item = std::make_shared<WorkItem>();
    item->req      = std::move(req);
    // Review-round fix (ResolveMany's dispatch deadline propagates into
    // queued work): `item_deadline` is pinned by the caller. For single-
    // shot `ResolveAsync` this is submission_time + req.timeout (the
    // single-caller budget contract). For `ResolveMany` this is
    // dispatch_time + req.timeout so that caller-visible expiry (the
    // wait loop's `per_entry_deadlines[i]`) and internal item eviction
    // (submission-side sweep + reaper) converge on the same instant;
    // no orphaned items stay alive in state_->queue / state_->in_flight
    // past the batch's reported timeout, eliminating the saturation /
    // worker-starvation risk for the next batch on the same resolver.
    item->deadline = item_deadline;
    auto fut = item->promise.get_future();

    {
        std::lock_guard<std::mutex> lk(state_->mtx);

        // Full-queue expiry sweep on EVERY submission — see review-round
        // evolution notes below. Items are now `shared_ptr<WorkItem>`
        // for shared ownership with in-flight items (worker retains
        // its own shared_ptr while the reaper may erase the list entry);
        // iteration accesses fields via `(*read)->field`.
        //
        // Review-round evolution history:
        //   round 1 — front-only sweep (cheap, monotone-deadline only)
        //   round 2 — + full sweep gated on saturation (caught the
        //             mixed-deadline case, but only at cap)
        //   round 3 — full sweep unconditionally
        //   round 4 — shared_ptr<WorkItem> + `done` flag so the reaper
        //             can also safely expire in-flight items racing
        //             the worker (this version).
        //
        // Always-sweep fixes both the drift problem (expired slots
        // accumulating toward kMaxQueuedItems) AND the per-request
        // deadline contract. Cost O(N) per submission; for realistic
        // queue sizes, microseconds.
        const auto sweep_now = std::chrono::steady_clock::now();
        auto write = state_->queue.begin();
        for (auto read = state_->queue.begin();
             read != state_->queue.end(); ++read) {
            auto& sp = *read;
            if (sp && sp->deadline <= sweep_now) {
                if (!sp->done) {
                    sp->done = true;
                    try {
                        sp->promise.set_value(MakeTimeoutResult(
                            sp->req, "queue-time exceeded deadline"));
                    } catch (const std::future_error&) {}
                }
                // Skip — drop from the new queue.
            } else {
                if (write != read) {
                    *write = std::move(*read);
                }
                ++write;
            }
        }
        state_->queue.erase(write, state_->queue.end());

        if (state_->queue.size() >= max_queued_items_) {
            // Bounded queue — synchronous saturation per §5.2.2. The
            // sweep above has already removed every expired item, so
            // this path fires only when the queue is genuinely
            // backlogged with live work.
            std::promise<ResolvedEndpoint> p;
            auto saturated = p.get_future();
            p.set_value(MakeReadyErrorResult(
                item->req, EAI_AGAIN, "resolver saturated"));
            return saturated;
        }
        state_->queue.push_back(std::move(item));
    }
    // Review-round fix: notify_all (was notify_one). Wakes BOTH a
    // worker (to pick up the new item) AND the timeout reaper (so it
    // can re-compute earliest-deadline if this new item has a shorter
    // deadline than whatever the reaper was previously waiting on).
    // At cap=32 this is 33 wakeups per submission instead of 1; the
    // extra scheduler cost (~100 µs of wakeup overhead per submission
    // at realistic rates) is absorbed cheaply and is required to close
    // the API-contract hole where a direct ResolveAsync caller could
    // wait indefinitely for a future to become ready when traffic
    // stopped behind a wedged worker.
    state_->cv.notify_all();
    return fut;
}

std::vector<ResolvedEndpoint>
DnsResolver::ResolveMany(std::vector<ResolveRequest> requests) {
    // P1 fix: one-arg form uses the operator-configured batch ceiling
    // from DnsConfig, so callers do not have to re-read config.
    return ResolveMany(std::move(requests),
                        std::chrono::milliseconds(config_.overall_timeout_ms));
}

std::vector<ResolvedEndpoint>
DnsResolver::ResolveMany(std::vector<ResolveRequest> requests,
                          std::chrono::milliseconds overall_timeout) {
    // P2 fix: capture a SINGLE dispatch time at batch entry. Per-entry
    // absolute deadlines are derived from this anchor BEFORE the wait
    // loop starts — NOT from `now()` at the moment the loop reaches
    // each entry. The prior implementation reset each entry's budget
    // when the wait loop moved to it, which silently stretched later
    // entries' effective per-entry timeouts by the cumulative wait
    // time of earlier entries (worst case: last entry got overall-
    // budget worth of per-entry time).
    const auto dispatch_time = std::chrono::steady_clock::now();
    const auto batch_deadline = dispatch_time + overall_timeout;

    std::vector<std::future<ResolvedEndpoint>> futures;
    futures.reserve(requests.size());
    std::vector<ResolveRequest> snapshot;
    snapshot.reserve(requests.size());
    std::vector<std::chrono::steady_clock::time_point> per_entry_deadlines;
    per_entry_deadlines.reserve(requests.size());

    for (auto& req : requests) {
        // Review-round P2 fix: family sentinel → config (same pattern
        // as timeout below). Substitute in snapshot so error messages
        // and test assertions see the effective family the resolver
        // actually ran against.
        if (req.family == LookupFamily::kUnset) {
            req.family = config_.lookup_family;
        }
        // P1 fix: sentinel substitution done HERE (before snapshotting
        // and before the enqueue path would otherwise substitute).
        // Guarantees that `per_entry_deadlines[i]` and
        // `snapshot[i].timeout` both reflect the effective value,
        // keeping log messages and test assertions aligned with the
        // deadline we actually enforced.
        if (req.timeout.count() == 0) {
            req.timeout = std::chrono::milliseconds(config_.resolve_timeout_ms);
        }
        // Review-round P2 fix: pin the per-item deadline on
        // `dispatch_time`, not on each item's own `now()` at submission.
        // The single `item_deadline` here is used BOTH for the batch
        // wait loop (`per_entry_deadlines[i]`) AND as the WorkItem's
        // internal deadline via ResolveAsyncImpl. Without this, the
        // public `ResolveAsync` path re-anchors each WorkItem at
        // per-submission `now()`, so later entries in a large batch
        // (or the first batch on a cold resolver with non-trivial
        // `EnsurePoolStarted` burst) can remain in state_->queue /
        // state_->in_flight AFTER ResolveMany has already returned a
        // "resolve timeout exceeded" result for them — orphaned work
        // that consumes queue slots / worker capacity on the resolver,
        // causing `EAI_AGAIN "resolver saturated"` or worker starvation
        // for the next batch. Sharing one deadline between caller wait
        // and internal item expiry converges the two views.
        const auto item_deadline = dispatch_time + req.timeout;
        per_entry_deadlines.push_back(item_deadline);
        snapshot.push_back(req);
        // Bypass public ResolveAsync (which would re-anchor the deadline
        // on its own `now()`); call ResolveAsyncImpl directly. Family /
        // timeout substitution is already done above, so Impl's
        // precondition is satisfied.
        futures.push_back(ResolveAsyncImpl(std::move(req), item_deadline));
    }

    std::vector<ResolvedEndpoint> results;
    results.reserve(futures.size());
    for (std::size_t i = 0; i < futures.size(); ++i) {
        const auto now = std::chrono::steady_clock::now();
        // Clamp each wait to min(dispatch-time per-entry deadline,
        // batch deadline). See P2 comment at function top.
        const auto effective = std::min(per_entry_deadlines[i], batch_deadline);
        auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                effective - now);
        if (remaining.count() < 0) remaining = std::chrono::milliseconds{0};

        if (futures[i].wait_for(remaining) == std::future_status::timeout) {
            results.push_back(MakeTimeoutResult(
                snapshot[i], "resolve timeout exceeded"));
        } else {
            try {
                results.push_back(futures[i].get());
            } catch (const std::exception& e) {
                results.push_back(MakeReadyErrorResult(
                    snapshot[i], EAI_SYSTEM,
                    std::string("future exception: ") + e.what()));
            }
        }
    }
    return results;
}

void DnsResolver::SetResolverForTesting(
    std::function<ResolvedEndpoint(const ResolveRequest&)> fn) {
    std::lock_guard<std::mutex> lk(state_->mtx);
    state_->test_seam = std::move(fn);
}

void DnsResolver::SetMaxQueuedItemsForTesting(std::size_t cap) {
    // Acquire state_->mtx to mutually exclude with ResolveAsync's
    // queue-size check — `max_queued_items_` is a plain size_t, and
    // without the lock a concurrent read in ResolveAsync on another
    // thread would race. Tests call this before the first resolve, so
    // contention is zero in practice.
    std::lock_guard<std::mutex> lk(state_->mtx);
    max_queued_items_ = cap;
}

}  // namespace NET_DNS_NAMESPACE
