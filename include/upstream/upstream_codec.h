#pragma once

#include "common.h"
#include "upstream/upstream_response.h"
#include "upstream/upstream_response_sink.h"
// <string>, <cstddef> provided by common.h (via upstream_response.h)

// Abstract codec interface for upstream-response parsers. The H1 parser
// (UpstreamHttpCodec) and the H2 codec (UpstreamH2Codec) both inherit
// from this base so ProxyTransaction can hold a single
// `std::unique_ptr<UpstreamCodec>` field and dispatch through the
// virtual surface without protocol-specific downcasts on the parsing
// hot path.
//
// Protocol-specific extensions (e.g., UpstreamH2Codec::SubmitH2Request)
// are reached via static_cast at the call site that knows the concrete
// type — by convention, the OnCheckoutReady branch in ProxyTransaction
// has just constructed the codec as the matching protocol type, so the
// cast is safe by construction.
class UpstreamCodec {
public:
    virtual ~UpstreamCodec() = default;

    UpstreamCodec(const UpstreamCodec&) = delete;
    UpstreamCodec& operator=(const UpstreamCodec&) = delete;

    // Reset parser state for the next response (connection reuse).
    virtual void Reset() = 0;

    // Set the request method that produced this response. H1 needs this
    // before Parse() so llhttp knows HEAD responses have no body. H2
    // codecs use it to set framing_hint_=NO_BODY at HEADERS dispatch.
    virtual void SetRequestMethod(const std::string& method) = 0;

    // Wire the response sink. The sink pointer must outlive Parse() /
    // Finish() calls — owning ProxyTransaction lifetime is the contract.
    virtual void SetSink(
        UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink) = 0;

    // Feed raw bytes from the upstream transport. Returns bytes consumed.
    // Callers check IsPaused() / HasError() / GetResponse().complete after.
    virtual size_t Parse(const char* data, size_t len) = 0;

    // Signal EOF from the transport. For connection-close framing (H1
    // with no Content-Length / Transfer-Encoding), the parser needs this
    // to finalize the response. Returns true if the response was
    // completed by EOF. H2 codecs no-op on Finish (transport EOF is
    // peer-side and surfaces via on_stream_close).
    virtual bool Finish() = 0;

    // Pause/resume parsing. Used by the retryable-5xx hold path so the
    // parser stops dispatching DATA chunks while ProxyTransaction
    // decides whether to retry. ResumeParsing flushes any buffered
    // bytes through the sink.
    virtual void PauseParsing() = 0;
    virtual void ResumeParsing() = 0;
    virtual bool IsPaused() const = 0;

    // Error state. HasError() returns true after a parse error;
    // GetError() returns a human-readable description for logging /
    // diagnostics (NOT propagated to clients per LOGGING_STANDARDS.md).
    virtual bool HasError() const = 0;
    virtual std::string GetError() const = 0;

    // Parsed response access. The reference is stable until Reset().
    virtual const UpstreamResponse& GetResponse() const = 0;
    virtual UpstreamResponse& GetResponse() = 0;

protected:
    UpstreamCodec() = default;
};
