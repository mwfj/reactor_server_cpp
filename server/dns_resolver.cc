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

    // Reject all-digits (would be a pure integer like "1" that glibc
    // treats as 0.0.0.1) — §5.6 explicit test case.
    bool all_digits = true;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            all_digits = false;
            break;
        }
    }
    if (all_digits) return false;

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
int AiFamilyFor(LookupFamily f) {
    switch (f) {
        case LookupFamily::kV4Only: return AF_INET;
        case LookupFamily::kV6Only: return AF_INET6;
        case LookupFamily::kV4Preferred:
        case LookupFamily::kV6Preferred:
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
        // "[ipv6]" or "[ipv6]:port"
        const auto rbracket = s.find(']');
        if (rbracket == std::string::npos) return false;
        *host = s.substr(1, rbracket - 1);
        if (rbracket + 1 == s.size()) {
            if (port) *port = 0;
            return true;
        }
        if (s[rbracket + 1] != ':') return false;
        const std::string port_str = s.substr(rbracket + 2);
        if (port_str.empty()) return false;
        try {
            if (port) *port = std::stoi(port_str);
        } catch (...) { return false; }
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
        const std::string port_str = s.substr(colon + 1);
        try {
            if (port) *port = std::stoi(port_str);
        } catch (...) { return false; }
        return true;
    }
    *host = s;
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
        const auto rbracket = in.find(']');
        if (rbracket == std::string::npos) return false;
        if (rbracket + 1 != in.size()) return false;   // no trailing content
        const std::string inner = in.substr(1, rbracket - 1);
        if (!ParseLiteral(inner)) return false;
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
    // Literal short-circuit FIRST (§5.2.9): ready-future path without
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
        if (state_->queue.size() >= kMaxQueuedItems) {
            // Bounded queue — synchronous saturation per §5.2.2.
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
DnsResolver::ResolveMany(std::vector<ResolveRequest> requests,
                          std::chrono::milliseconds overall_timeout) {
    const auto batch_deadline =
        std::chrono::steady_clock::now() + overall_timeout;

    // Dispatch first — all calls are O(1). Futures land in the same
    // order as requests so the result vector preserves caller order.
    std::vector<std::future<ResolvedEndpoint>> futures;
    futures.reserve(requests.size());
    std::vector<ResolveRequest> snapshot;
    snapshot.reserve(requests.size());
    for (auto& req : requests) {
        snapshot.push_back(req);
        futures.push_back(ResolveAsync(std::move(req)));
    }

    std::vector<ResolvedEndpoint> results;
    results.reserve(futures.size());
    for (std::size_t i = 0; i < futures.size(); ++i) {
        // Clamp each wait to min(per-entry timeout, remaining batch budget).
        const auto now = std::chrono::steady_clock::now();
        const auto per_entry_deadline = now + snapshot[i].timeout;
        const auto effective = std::min(per_entry_deadline, batch_deadline);
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

}  // namespace net_dns
