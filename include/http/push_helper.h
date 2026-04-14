#pragma once

#include "http/http_response.h"
#include <string>

// Synchronous HTTP/2 server push helper.
//
// Async routes get a bound ResourcePusher closure as a parameter (see
// HttpRouter::AsyncHandler). Sync routes have a fixed signature and
// cannot be retrofitted with an extra parameter without churning every
// existing handler, so this free function reads a thread-local pointer
// installed by the framework around router_.Dispatch().
//
// Returns the promised HTTP/2 stream id (>0) on success, or -1 when:
//   - the call is made outside an active sync dispatch
//   - the underlying connection is HTTP/1.x (push is HTTP/2 only)
//   - the H2 connection has been torn down
//   - validation in Http2Session::SubmitPushPromise fails
//   - push is disabled (config or peer refusal)
//
// All -1 paths log a debug entry rather than throwing — push is best-
// effort by design; a failed push must never break the parent response.
//
// Namespace naming: follows the project convention (CODE_CONVENTIONS.md)
// of UPPER_SNAKE_CASE namespace identifiers, matching the sibling
// HTTP_CALLBACKS_NAMESPACE / HTTP2_CALLBACKS_NAMESPACE / UPSTREAM_CALLBACKS_NAMESPACE
// pattern. The name is HTTP2-specific (not generic "http") because
// server push is defined in RFC 9113 §8.4 and is not available on
// HTTP/1.x — calling the helper on an H1 connection returns -1.
namespace HTTP2_PUSH_NAMESPACE {

int32_t PushResource(const std::string& method,
                     const std::string& scheme,
                     const std::string& authority,
                     const std::string& path,
                     const HttpResponse& response);

}  // namespace HTTP2_PUSH_NAMESPACE
