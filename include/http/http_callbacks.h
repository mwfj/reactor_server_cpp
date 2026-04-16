#pragma once

#include "common.h"
// <functional>, <memory>, <string>, <cstdint> provided by common.h

// Forward declarations
class HttpConnectionHandler;
class ConnectionHandler;
class WebSocketConnection;
class Dispatcher;
struct HttpRequest;
class HttpResponse;

namespace HTTP_CALLBACKS_NAMESPACE {

    // ---- HttpConnectionHandler callbacks ------------------------------------
    using HttpConnRequestCallback = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request,
        HttpResponse& response
    )>;
    using HttpConnRouteCheckCallback = std::function<bool(const HttpRequest& request)>;
    using HttpConnMiddlewareCallback = std::function<bool(
        const HttpRequest& request,
        HttpResponse& response
    )>;
    using HttpConnUpgradeCallback = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request
    )>;

    // Fires for every completed HTTP parse (dispatched, rejected, or upgraded).
    // Used by HttpServer to count all requests, not just successfully dispatched ones.
    using HttpConnRequestCountCallback = std::function<void()>;

    // Returns true if the server is shutting down. Used as a late gate
    // in WS upgrade to prevent upgrades that slipped past the early check.
    using HttpConnShutdownCheckCallback = std::function<bool()>;

    struct HttpConnCallbacks {
        HttpConnRequestCallback       request_callback       = nullptr;
        HttpConnRouteCheckCallback    route_check_callback    = nullptr;
        HttpConnMiddlewareCallback    middleware_callback     = nullptr;
        HttpConnUpgradeCallback       upgrade_callback       = nullptr;
        HttpConnRequestCountCallback  request_count_callback  = nullptr;
        HttpConnShutdownCheckCallback shutdown_check_callback = nullptr;
    };

    // ---- HttpRouter async callbacks -------------------------------------------

    // Completion callback handed to async handlers. When invoked it delivers
    // the final HttpResponse to the client. Protocol-agnostic — the framework
    // binds protocol-specific plumbing (HTTP/1 client transport or HTTP/2
    // stream submission) at dispatch time so the user handler is the same
    // regardless of whether the request arrived over H1 or H2.
    //
    // Thread safety: the completion callback MUST be invoked on the
    // dispatcher thread that owns the request's connection. Async work
    // (e.g. upstream pool CheckoutAsync) naturally routes callbacks back
    // to that dispatcher. If your async work runs elsewhere, route the
    // completion via EnQueue.
    using AsyncCompletionCallback = std::function<void(HttpResponse)>;

    // Send a non-final 1xx response (RFC 8297 Early Hints, etc.).
    // May be called zero or more times BEFORE the final AsyncCompletionCallback.
    //
    // Thread-safe: off-dispatcher callers are auto-hopped internally so the
    // final drop/emit decision happens on the dispatcher thread, preserving
    // ordering against the eventual final response. Calls that arrive after
    // complete() has been invoked for the originating request are dropped
    // silently (request-scoped guard) so stale interims never leak into a
    // pipelined next request's response window. See design spec §4.2.
    using InterimResponseSender = std::function<void(
        int status_code,
        const std::vector<std::pair<std::string, std::string>>& headers
    )>;

    // Push an HTTP/2 resource alongside the current response.
    // Contract: success returns the promised stream_id (>0); failure
    // returns -1. Reasons for -1 include: config disabled, peer
    // refused via SETTINGS_ENABLE_PUSH=0, non-H2 transport, invalid
    // method/scheme/path/authority, session shutting down or GOAWAY
    // sent, parent stream closed OR its final response already
    // submitted, nghttp2 submit failure.
    //
    // Thread-safe: off-dispatcher callers are rejected safely with -1
    // and no side effects. Application code that needs a real push
    // MUST call from the dispatcher thread (sync handler or inline
    // during the async handler's dispatcher invocation, before
    // enqueuing complete()).
    // See design spec §2.2.
    using ResourcePusher = std::function<int32_t(
        const std::string& method,
        const std::string& scheme,
        const std::string& authority,
        const std::string& path,
        const HttpResponse& response
    )>;

    // Streaming final-response sender for async handlers.
    //
    // Contract:
    //   - `SendHeaders()` claims the final response and commits the
    //     downstream stream. After a successful call, the handler MUST
    //     finish with exactly one of `End()` or `Abort()`.
    //   - `SendData()` is always-accept: callers never hold rejected bytes.
    //     The return value reports downstream occupancy AFTER the chunk is
    //     consumed so the caller can apply backpressure upstream.
    //   - `ACCEPTED_ABOVE_HIGH_WATER` means the chunk was accepted AND the
    //     downstream buffer crossed the configured high-water mark. The caller
    //     should pause upstream reads until the drain listener fires.
    //   - `CLOSED` means the sender is no longer usable (client disconnect,
    //     terminal End/Abort already fired, or contract violation such as
    //     SendData/End before SendHeaders).
    //   - `Abort()` is idempotent. `Abort()` before `SendHeaders()` is legal
    //     and must not emit a successful final response.
    //   - Streaming senders are dispatcher-thread primitives. Off-dispatcher
    //     calls are rejected with `CLOSED` / `-1` and logged at error level.
    class StreamingResponseSender {
    public:
        enum class SendResult {
            ACCEPTED_BELOW_WATER = 0,
            ACCEPTED_ABOVE_HIGH_WATER = 1,
            CLOSED = 2,
        };

        enum class AbortReason {
            UPSTREAM_TRUNCATED,
            UPSTREAM_TIMEOUT,
            UPSTREAM_ERROR,
            CLIENT_DISCONNECT,
            TIMER_EXPIRED,
            SERVER_SHUTDOWN,
        };

        using DrainListener = std::function<void()>;

        class Impl {
        public:
            virtual ~Impl() = default;
            [[nodiscard]] virtual int SendHeaders(
                const HttpResponse& headers_only_response) = 0;
            [[nodiscard]] virtual SendResult SendData(
                const char* data, size_t len) = 0;
            [[nodiscard]] virtual SendResult End(
                const std::vector<std::pair<std::string, std::string>>& trailers) = 0;
            virtual void Abort(AbortReason reason) = 0;
            virtual void SetDrainListener(DrainListener listener) = 0;
            virtual void ConfigureWatermarks(size_t high_water_bytes) = 0;
            virtual Dispatcher* GetDispatcher() = 0;
            virtual void OnDownstreamWriteProgress(size_t /*remaining_bytes*/) {}
            virtual void OnDownstreamWriteComplete() {}
        };

        StreamingResponseSender() = default;
        explicit StreamingResponseSender(std::shared_ptr<Impl> impl)
            : impl_(std::move(impl)) {}

        [[nodiscard]] int SendHeaders(
            const HttpResponse& headers_only_response) const {
            return impl_ ? impl_->SendHeaders(headers_only_response) : -1;
        }
        [[nodiscard]] SendResult SendData(const char* data, size_t len) const {
            return impl_ ? impl_->SendData(data, len) : SendResult::CLOSED;
        }
        [[nodiscard]] SendResult End(
            const std::vector<std::pair<std::string, std::string>>& trailers = {}) const {
            return impl_ ? impl_->End(trailers) : SendResult::CLOSED;
        }
        void Abort(AbortReason reason) const {
            if (impl_) impl_->Abort(reason);
        }
        void SetDrainListener(DrainListener listener) const {
            if (impl_) impl_->SetDrainListener(std::move(listener));
        }
        void ConfigureWatermarks(size_t high_water_bytes) const {
            if (impl_) impl_->ConfigureWatermarks(high_water_bytes);
        }
        Dispatcher* GetDispatcher() const {
            return impl_ ? impl_->GetDispatcher() : nullptr;
        }
        explicit operator bool() const { return static_cast<bool>(impl_); }

    private:
        std::shared_ptr<Impl> impl_;
    };

    // Async handler for HTTP requests. Used when the request handler needs to
    // dispatch async work (e.g. upstream proxy via UpstreamManager::CheckoutAsync)
    // and deliver the response later. The handler receives the request plus
    // an interim sender, an H2 push helper, a streaming final-response sender,
    // and a completion callback. The handler either:
    //   - invokes `complete(resp)` exactly once for buffered completion, or
    //   - uses `stream_sender` (`SendHeaders` + `SendData*` + `End/Abort`)
    //     for protocol-native streaming completion.
    //
    // The framework:
    //   - Runs middleware before invoking the async handler (auth, CORS, etc.)
    //   - Blocks the HTTP/1 parser from accepting new requests until the
    //     final response completes, preserving response ordering on keep-alive
    //   - Marks the connection as shutdown-exempt while the async work is
    //     pending so graceful shutdown waits for the reply
    //   - Applies Connection: close / keep-alive / HEAD body-stripping to
    //     buffered completions using the original request's metadata
    //   - Binds protocol-specific streaming senders so the handler can use
    //     one API across HTTP/1.1 and HTTP/2
    // Invoked by HttpServer (NOT HttpRouter — the router has no transport
    // context). See design §2.2 and §4.2.
    using AsyncHandler = std::function<void(
        const HttpRequest& request,
        InterimResponseSender send_interim,
        ResourcePusher        push_resource,
        StreamingResponseSender stream_sender,
        AsyncCompletionCallback complete
    )>;

    // ---- WebSocketConnection callbacks --------------------------------------
    using WsMessageCallback = std::function<void(
        WebSocketConnection& ws, const std::string& message, bool is_binary
    )>;
    using WsCloseCallback = std::function<void(
        WebSocketConnection& ws, uint16_t code, const std::string& reason
    )>;
    using WsPingCallback = std::function<void(
        WebSocketConnection& ws, const std::string& payload
    )>;
    using WsErrorCallback = std::function<void(
        WebSocketConnection& ws, const std::string& error
    )>;

    struct WsCallbacks {
        WsMessageCallback message_callback = nullptr;
        WsCloseCallback   close_callback   = nullptr;
        WsPingCallback    ping_callback    = nullptr;
        WsErrorCallback   error_callback   = nullptr;
    };

} // namespace HTTP_CALLBACKS_NAMESPACE
