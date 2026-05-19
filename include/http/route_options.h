#pragma once

namespace http {

// Per-route request-handling mode. Selected at route registration time;
// HttpRouter::ResolveOptionsAtHeaders surfaces it at headers-complete so the
// inbound layer can choose between buffering the body (default) and streaming
// it chunk-by-chunk through a BodyStream.
enum class RouteRequestMode {
    Buffered,
    Streaming
};

// Bundle of per-route options. Stored on the route trie node alongside the
// handler so route registration and option association are atomic. Future
// per-route knobs (timeouts, body-size caps, etc.) extend this struct.
struct RouteOptions {
    RouteRequestMode request_mode = RouteRequestMode::Buffered;
};

}  // namespace http
