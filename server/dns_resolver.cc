#include "net/dns_resolver.h"
#include "log/logger.h"

#include <netdb.h>
#include <pthread.h>
#include <cctype>
#include <cstring>
#include <cstdlib>

namespace net_dns {

// ---------------------------------------------------------------------------
// Internal pool-state types. Defined in the .cc so the header stays tight.
// ---------------------------------------------------------------------------

struct DnsResolver::WorkItem {
    ResolveRequest                              req;
    std::chrono::steady_clock::time_point       deadline;
    std::promise<ResolvedEndpoint>              promise;
};

struct DnsResolver::PoolState {
    std::mutex                                            mtx;
    std::condition_variable                               cv;
    std::deque<WorkItem>                                  queue;
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

// Try inet_pton against AF_INET then AF_INET6. True on any match.
bool ParseLiteral(const std::string& s) {
    if (s.empty()) return false;
    unsigned char buf[sizeof(struct in6_addr)];
    if (::inet_pton(AF_INET,  s.c_str(), buf) == 1) return true;
    if (::inet_pton(AF_INET6, s.c_str(), buf) == 1) return true;
    return false;
}

// RFC 3986 §3.2.2 IP-literal grammar: brackets are reserved for IPv6
// (and IPvFuture — not supported here). IPv4 literals MUST appear
// unbracketed. Review-round fix: ParseHostPort and NormalizeHostToBare
// use THIS helper for the bracketed branch rather than the permissive
// ParseLiteral (which also accepted bracketed IPv4 like "[127.0.0.1]").
bool ParseIpv6Literal(const std::string& s) {
    if (s.empty()) return false;
    unsigned char buf[sizeof(struct in6_addr)];
    return ::inet_pton(AF_INET6, s.c_str(), buf) == 1;
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
    // Drain queued items under the mutex and wake their futures with a
    // shutdown-error result. In-flight items already on a worker's stack
    // are not reachable here — they rely on their own future.wait_for
    // bound per the §5.2.4 contract narrowing.
    {
        std::lock_guard<std::mutex> lk(state_->mtx);
        state_->shutting_down.store(true, std::memory_order_release);
        while (!state_->queue.empty()) {
            auto& item = state_->queue.front();
            try {
                item.promise.set_value(
                    MakeTimeoutResult(item.req, "resolver shutdown"));
            } catch (const std::future_error&) { /* future gone */ }
            state_->queue.pop_front();
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
        } catch (...) {
            // Partial-failure cleanup (§5.2.9). Signal shutdown on the
            // OLD state so already-started workers exit, then detach
            // them so throw doesn't hang on a wedged worker.
            {
                std::lock_guard<std::mutex> lk(state_->mtx);
                state_->shutting_down.store(true, std::memory_order_release);
            }
            state_->cv.notify_all();
            for (pthread_t tid : workers_) {
                pthread_detach(tid);
            }
            workers_.clear();

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
        WorkItem item;
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
        }

        // Queue-time deadline short-circuit: if the caller's timeout
        // already expired while this item waited, skip getaddrinfo.
        if (std::chrono::steady_clock::now() >= item.deadline) {
            try {
                item.promise.set_value(
                    MakeTimeoutResult(item.req, "queue-time exceeded deadline"));
            } catch (const std::future_error&) {}
            continue;
        }

        // Copy the seam callable out of PoolState so a concurrent
        // SetResolverForTesting doesn't mutate our reference mid-call.
        std::function<ResolvedEndpoint(const ResolveRequest&)> body;
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            body = state->test_seam;
        }
        ResolvedEndpoint result = body ? body(item.req)
                                       : DoBlockingResolve(item.req);

        try {
            item.promise.set_value(std::move(result));
        } catch (const std::future_error&) { /* future destroyed */ }
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
    // lookup_family. Substitute BEFORE the literal short-circuit so the
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
    // Substitute BEFORE the literal short-circuit so item.deadline
    // (computed below for queue-path items) consistently reflects the
    // effective timeout regardless of caller pattern.
    if (req.timeout.count() == 0) {
        req.timeout = std::chrono::milliseconds(config_.resolve_timeout_ms);
    }

    // Review-round fix: fail-closed host validation BEFORE any pool
    // interaction. ResolveAsync is the runtime gate; without this guard,
    // legacy numeric-dotted forms like "0127.0.0.1" or "1.2.3" (already
    // rejected by IsValidHostOrIpLiteral / ConfigLoader) could still
    // reach getaddrinfo via a caller that skipped pre-validation and be
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

    WorkItem item;
    item.req      = std::move(req);
    item.deadline = std::chrono::steady_clock::now() + item.req.timeout;
    auto fut = item.promise.get_future();

    {
        std::lock_guard<std::mutex> lk(state_->mtx);

        // Full-queue expiry sweep on EVERY submission. Review-round
        // evolution:
        //   round 1 — front-only sweep (cheap, monotone-deadline only)
        //   round 2 — + full sweep gated on saturation (caught the
        //             mixed-deadline case, but only at cap)
        //   round 3 — full sweep unconditionally (this version).
        //
        // The two-tier version missed the non-saturated mixed-timeout
        // case: `[5s_item, 30ms_item]` stays below the 10000-item
        // saturation bar, but the 30ms item waits behind a live 5s
        // head that the front-sweep refuses to evict. The caller's
        // per-request deadline contract (§5.2.3 `ResolveRequest.timeout`)
        // is silently violated whenever the worker pool is wedged.
        //
        // Always-sweep fixes both the drift problem (expired slots
        // accumulating toward kMaxQueuedItems) AND the individual
        // per-request deadline: any item whose deadline has passed
        // is evicted at the next submission, no matter where it sits
        // in the queue and no matter the queue size.
        //
        // Cost: O(N) per submission where N = queue size. Realistic
        // queues are small (dozens to low hundreds), making sweep cost
        // microseconds. Pathological 10000-item stall: ~1 ms per
        // submission — absorbed by the one code path that actually
        // wants sweep pressure. Workers pop one item under the same
        // lock; they do NOT iterate the queue, so there is no nested-
        // lock concern.
        //
        // Manual write/read iteration (not std::remove_if) so the
        // set_value side effect on each evicted promise is unambiguous
        // per the C++ standard for move-only WorkItem types.
        const auto sweep_now = std::chrono::steady_clock::now();
        auto write = state_->queue.begin();
        for (auto read = state_->queue.begin();
             read != state_->queue.end(); ++read) {
            if (read->deadline <= sweep_now) {
                try {
                    read->promise.set_value(MakeTimeoutResult(
                        read->req, "queue-time exceeded deadline"));
                } catch (const std::future_error&) {}
                // Skip — don't move to write position. read is left
                // moved-from / destructible at erase-time.
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
                item.req, EAI_AGAIN, "resolver saturated"));
            return saturated;
        }
        state_->queue.push_back(std::move(item));
    }
    state_->cv.notify_one();
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
        // and before ResolveAsync also substitutes). Guarantees that
        // `per_entry_deadlines[i]` and `snapshot[i].timeout` both
        // reflect the effective value, keeping log messages and test
        // assertions aligned with the deadline we actually enforced.
        if (req.timeout.count() == 0) {
            req.timeout = std::chrono::milliseconds(config_.resolve_timeout_ms);
        }
        per_entry_deadlines.push_back(dispatch_time + req.timeout);
        snapshot.push_back(req);
        futures.push_back(ResolveAsync(std::move(req)));
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

}  // namespace net_dns
