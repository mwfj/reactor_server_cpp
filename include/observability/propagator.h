#pragma once

// Trace-context propagator interface + W3C Trace Context implementation.
//
//   Propagator       — virtual base. Concrete impls (W3CPropagator,
//                       JaegerPropagator, CompositePropagator) extract
//                       a SpanContext from inbound headers and inject a
//                       SpanContext into outbound headers, owning their
//                       own header keys (e.g. W3C owns "traceparent" /
//                       "tracestate"; Jaeger owns "uber-trace-id").
//
//   W3CPropagator    — W3C Trace Context Level 1 §3 implementation.
//                       Stateless; instance methods are the contract.
//
// Split-context model: `Extract` returns the REMOTE PARENT (immutable
// snapshot of the inbound header), and `Inject` writes a LOCAL
// SpanContext (e.g. AttemptTraceContext.attempt_local). Outbound callers
// MUST NOT inject `RequestTraceContext.current_local` directly — that
// would make downstream services attach to the SERVER hop instead of
// the gateway-internal CLIENT span.

#include "observability/span_context.h"
#include "observability/trace_state.h"

#include "../common.h"
#include <optional>
// <map>, <string>, <string_view>, <utility>, <vector> via common.h

namespace OBSERVABILITY_NAMESPACE {

// Recognised propagator-name tokens for `traces.propagators` config and
// CompositePropagator::Build. Single source of truth — every comparison
// site (config loader, composite builder, tests) routes through these.
inline constexpr const char* kPropagatorNameW3C    = "w3c";
inline constexpr const char* kPropagatorNameJaeger = "jaeger";

inline bool IsKnownPropagatorName(std::string_view name) noexcept {
    return name == kPropagatorNameW3C || name == kPropagatorNameJaeger;
}

// W3C Trace Context Level 1 §3.2 mandates LOWERCASE hex for trace-id,
// span-id, and trace-flags. Uppercase hex makes a header malformed —
// accepting it would let the gateway propagate an invalid context
// downstream. Jaeger applies the same rule for cross-format consistency.
inline bool IsHexCharLower(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

// Case-insensitive ASCII equality against a precomputed all-lowercase
// reference. Hot path: every inbound + outbound proxy request runs
// StripOwnedHeaders across every header — `tolower` per char dodges
// the per-iteration std::string allocation that ToLower() would incur.
inline bool EqualsLowerAscii(std::string_view name,
                             std::string_view lower) noexcept {
    if (name.size() != lower.size()) return false;
    for (size_t i = 0; i < lower.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(name[i]);
        const char l = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32)
                                              : static_cast<char>(c);
        if (l != lower[i]) return false;
    }
    return true;
}

class Propagator {
public:
    using HeadersMap = std::map<std::string, std::string>;
    using HeadersVec = std::vector<std::pair<std::string, std::string>>;

    virtual ~Propagator() = default;

    // Extract a SpanContext from inbound headers. Returns nullopt when no
    // valid context exists for this format. Must NOT mutate `headers`.
    virtual std::optional<SpanContext> Extract(const HeadersMap& headers) const = 0;

    // Inject `ctx` into outbound `headers`. Returns true when at least
    // one header was written. Strip-then-inject is the implementation
    // contract: every concrete impl strips its owned headers before
    // emitting fresh values.
    virtual bool Inject(const SpanContext& ctx, HeadersMap& headers) const = 0;

    // Vector overload — preserves the existing W3C contract for callers
    // that work with header-pair vectors (e.g. UpstreamHttpClient on the
    // wire path). Default impl writes into a temporary HeadersMap and
    // copies the entries back into the vector; concrete propagators may
    // override for speed.
    virtual bool Inject(const SpanContext& ctx,
                         HeadersVec& headers) const;

    // Strip every header this propagator owns. Idempotent. Used by the
    // composite to drop client-supplied trace headers before injecting
    // a fresh context (defends against header-spoofing).
    virtual void StripOwnedHeaders(HeadersMap& headers) const = 0;
    virtual void StripOwnedHeaders(HeadersVec& headers) const;

    // Identifier for logging / metric labels: "w3c", "jaeger", "composite".
    virtual const char* Name() const noexcept = 0;
};

class W3CPropagator final : public Propagator {
public:
    // Wire-format constants per W3C Trace Context §3.2.
    static constexpr size_t      kTraceparentLen = 55;
    static constexpr const char* kVersion00      = "00";

    // ---- Propagator instance API ----
    std::optional<SpanContext> Extract(
        const HeadersMap& headers) const override;
    bool Inject(const SpanContext& ctx,
                 HeadersMap& headers) const override;
    bool Inject(const SpanContext& ctx,
                 HeadersVec& headers) const override;
    void StripOwnedHeaders(HeadersMap& headers) const override;
    void StripOwnedHeaders(HeadersVec& headers) const override;
    const char* Name() const noexcept override { return "w3c"; }

    // ---- Format-specific helpers (instance) ----

    // Parse a `traceparent` header value. Returns the extracted
    // SpanContext when well-formed AND identifying a valid (non-zero)
    // trace_id + span_id (W3C §3.2.2.5 invalid forms are rejected).
    // Returns nullopt on:
    //   - Wrong length (anything but 55 chars).
    //   - Bad version (anything but "00").
    //   - Non-hex characters in any field.
    //   - All-zero trace_id or span_id.
    std::optional<SpanContext> ParseTraceparent(
        std::string_view header_value) const noexcept;

    // Parse a `tracestate` header value. Returns the parsed TraceState on
    // success (including empty header → empty TraceState); nullopt when
    // the header violates W3C list-member caps (>32 members or any
    // member >256 chars).
    std::optional<TraceState> ParseTracestate(
        std::string_view header_value) const;

    // Serialize a SpanContext into a `traceparent` header value. Returns
    // nullopt when the context is invalid (zero trace_id or span_id) —
    // callers MUST NOT inject an invalid context.
    std::optional<std::string> SerializeTraceparent(
        const SpanContext& ctx) const;
};

// Jaeger native propagator — `uber-trace-id` header.
//
//   uber-trace-id: {trace-id}:{span-id}:{parent-span-id}:{flags}
//
// trace-id is 16-hex (legacy 64-bit) or 32-hex (modern 128-bit); a
// 64-bit value is left-padded with zeros to the canonical 128-bit
// TraceId. span-id is 16-hex. parent-span-id is informational only
// (gateway does not reconstruct the parent chain) but the field MUST
// be present and hex (a literal "0" is the documented root-span
// sentinel; empty is rejected). flags is 1-2 hex chars; only the
// sampled bit (0x01) is honored — debug/firehose bits are dropped.
class JaegerPropagator final : public Propagator {
public:
    static constexpr const char* kHeader = "uber-trace-id";

    std::optional<SpanContext> Extract(
        const HeadersMap& headers) const override;
    bool Inject(const SpanContext& ctx,
                 HeadersMap& headers) const override;
    void StripOwnedHeaders(HeadersMap& headers) const override;
    // Vec-form override (mirrors W3C). Avoids the base default's
    // map-roundtrip + survivor-set rebuild — relevant when the
    // composite propagator's vec-form Strip fans out across children.
    void StripOwnedHeaders(HeadersVec& headers) const override;
    const char* Name() const noexcept override { return "jaeger"; }

private:
    static std::optional<SpanContext> Parse(std::string_view value);
};

// CompositePropagator — fans Extract / Inject / Strip across an ordered
// list of child propagators. Extract returns the first child that
// produced a valid context (precedence == config order). Inject calls
// every child, so a single SpanContext is emitted in every wire format
// the operator configured. StripOwnedHeaders drops every child-owned
// header, used by the proxy CLIENT path so client-supplied trace
// headers never leak through.
class CompositePropagator final : public Propagator {
public:
    using PropagatorList = std::vector<std::unique_ptr<Propagator>>;

    // Build from an ordered vector of propagator names. Recognised
    // tokens are `kPropagatorNameW3C` / `kPropagatorNameJaeger`. Throws
    // `std::invalid_argument` on an empty list or an unknown name.
    // Returns the base interface so callers cannot reach into children_.
    static std::shared_ptr<const Propagator> Build(
        const std::vector<std::string>& names);

    std::optional<SpanContext> Extract(
        const HeadersMap& headers) const override;
    bool Inject(const SpanContext& ctx,
                 HeadersMap& headers) const override;
    // Vector-form Inject is overridden so each child writes directly
    // into the real vector. The base default works through a temp
    // HeadersMap and one StripOwnedHeaders sweep — for the composite
    // that strip would only touch the composite's own owned set
    // (children-iterated), not give each child a chance to use its own
    // hot-path Vec form (W3C overrides Inject(HeadersVec&)). Direct
    // per-child fan-out is both faster and preserves the contract that
    // a child's Vec override is the authoritative serializer.
    bool Inject(const SpanContext& ctx,
                 HeadersVec& headers) const override;
    void StripOwnedHeaders(HeadersMap& headers) const override;
    // Vector-form Strip mirrors the Inject(HeadersVec&) override —
    // delegate to each child's Vec form so W3C's hot-path Vec strip is
    // used directly. Falls back to the base default per child for
    // children that don't override the Vec form.
    void StripOwnedHeaders(HeadersVec& headers) const override;
    const char* Name() const noexcept override { return "composite"; }

private:
    explicit CompositePropagator(PropagatorList children)
        : children_(std::move(children)) {}
    PropagatorList children_;
};

}  // namespace OBSERVABILITY_NAMESPACE
