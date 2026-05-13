#pragma once

#include "http/http_callbacks.h"
#include "ws/websocket_parser.h"
#include "ws/websocket_frame.h"
#include "connection_handler.h"

// <memory>, <functional>, <string>, <unordered_map> provided by common.h (via connection_handler.h)

namespace OBSERVABILITY_NAMESPACE {
struct ObservabilitySnapshot;
class ObservabilityManager;
class Counter;
class UpDownCounter;
}

class WebSocketConnection {
public:
    explicit WebSocketConnection(std::shared_ptr<ConnectionHandler> conn);
    ~WebSocketConnection();

    // Public type aliases for backward compatibility
    using MessageCallback = HTTP_CALLBACKS_NAMESPACE::WsMessageCallback;
    using CloseCallback   = HTTP_CALLBACKS_NAMESPACE::WsCloseCallback;
    using PingCallback    = HTTP_CALLBACKS_NAMESPACE::WsPingCallback;
    using ErrorCallback   = HTTP_CALLBACKS_NAMESPACE::WsErrorCallback;

    void OnMessage(MessageCallback callback);
    void OnClose(CloseCallback callback);
    void OnPing(PingCallback callback);
    void OnError(ErrorCallback callback);

    // Send operations
    void SendText(const std::string& message);
    void SendBinary(const std::string& data);
    void SendClose(uint16_t code = 1000, const std::string& reason = "");
    void SendPing(const std::string& payload = "");
    void SendPong(const std::string& payload = "");

    // Connection info
    int fd() const;
    bool IsOpen() const { return is_open_ && !close_sent_; }
    // True if we sent a close frame and are waiting for the peer's reply.
    bool IsClosing() const { return is_open_ && close_sent_; }

    // Access parser (for setting max payload size)
    WebSocketParser& GetParser() { return parser_; }

    // Set maximum reassembled message size (0 = unlimited)
    void SetMaxMessageSize(size_t max) { max_message_size_ = max; }

    // Route parameters (populated during upgrade from pattern routes)
    const std::unordered_map<std::string, std::string>& GetParams() const { return params_; }
    void SetParams(std::unordered_map<std::string, std::string> params) { params_ = std::move(params); }

    // Feed raw data from the reactor
    void OnRawData(const std::string& data);

    // Optional observability hook — when set, text/binary frames
    // allocate short `ws.recv` / `ws.send` INTERNAL spans parented at
    // the upgrade SERVER span. Gated at the emission site by
    // `ObservabilityManager::WebSocketMessagesEnabled` (default false).
    // Caches the enabled-flag + instrument pointers so the disabled
    // fast path on per-frame emission is one relaxed atomic load.
    //
    // INSTALL-ONCE-AT-UPGRADE — rebind is unsupported. Called from
    // `HttpConnectionHandler::AttemptWebSocketUpgrade` on the
    // connection dispatcher. The cached pointers are read lock-free
    // from `MaybeEmitMessageSpan` / `BumpFrameCounter` on the data
    // path; a rebind site would race those reads.
    void SetObservabilitySnapshot(
        std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilitySnapshot> snap);

    // Called when the transport (TCP/TLS) disconnects without a WebSocket Close frame.
    // Fires the close handler so applications can clean up session state.
    void NotifyTransportClose();

private:
    std::shared_ptr<ConnectionHandler> conn_;
    WebSocketParser parser_;
    std::atomic<bool> is_open_{true};
    std::atomic<bool> close_sent_{false};  // We sent a close frame, waiting for peer's reply
    std::recursive_mutex send_mtx_;  // Serializes SendText/SendBinary/SendClose to prevent
                                     // data frames after Close (RFC 6455 §5.5.1).
                                     // Recursive: SendFrame can synchronously fail → CallCloseCb
                                     // → NotifyTransportClose → user close callback → re-entrant
                                     // send (which is a no-op due to is_open_ guard).
    uint16_t sent_close_code_ = 0;     // Close code we sent (for NotifyTransportClose)
    std::string sent_close_reason_;    // Close reason we sent

    HTTP_CALLBACKS_NAMESPACE::WsCallbacks callbacks_;

    // Fragmentation reassembly
    std::string fragment_buffer_;
    WebSocketOpcode fragment_opcode_ = WebSocketOpcode::Text;
    bool in_fragment_ = false;
    size_t max_message_size_ = 0;  // 0 = unlimited

    // Route parameters extracted during WebSocket upgrade
    std::unordered_map<std::string, std::string> params_;

    // Optional observability snapshot — provides parent SERVER span
    // and ObservabilityManager handle for per-message child spans.
    std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilitySnapshot>
        obs_snapshot_;
    // Cached pointer to manager's `websocket_messages_enabled_` atomic.
    // Set by SetObservabilitySnapshot when the snapshot's manager
    // weak_ptr can be locked at install time. nullptr when not bound;
    // disabled fast-path checks this with a single relaxed load before
    // doing any other work. Pointer stays valid for the lifetime of
    // obs_snapshot_, which holds a shared_ptr that keeps the manager
    // alive via the snapshot's own manager.lock() chain.
    const std::atomic<bool>* ws_messages_enabled_flag_ = nullptr;
    // Cached catalog instrument pointers — set at install time so
    // hot-path frame emission is a single null-check + one virtual
    // call when observability is unbound. Without this cache every
    // frame would pay a manager.catalog() member-access + Counter*
    // field load per direction. Lifetime is the same as obs_manager_:
    // valid until the next SetObservabilitySnapshot or destruction.
    OBSERVABILITY_NAMESPACE::Counter* frames_counter_ = nullptr;
    OBSERVABILITY_NAMESPACE::UpDownCounter*
        active_connections_counter_ = nullptr;
    // Cached pointer to the labeled HTTP-protocol gauge so the WS
    // connection can emit `protocol=websocket` independently of the
    // ConnectionHandler-owned `http/1.1` / `h2` gauges. dtor issues
    // the matching -1 under `ws_protocol_active_counted_`.
    OBSERVABILITY_NAMESPACE::UpDownCounter*
        http_connections_active_counter_ = nullptr;
    // Manager kept alive for the connection's lifetime so the atomic
    // pointed to by ws_messages_enabled_flag_ stays valid even when
    // the snapshot's `manager` weak_ptr would otherwise allow the
    // manager to expire.
    std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilityManager>
        obs_manager_;
    // Latch — set by SetObservabilitySnapshot when the
    // reactor.websocket.active_connections UpDownCounter was bumped
    // by +1; the dtor checks this to issue the matching -1 exactly
    // once. Cleared after the decrement so a later snapshot reset
    // can't double-decrement.
    bool active_counted_ = false;
    // Latch — set by SetObservabilitySnapshot when the +1 on
    // reactor.http.connections.active{protocol=websocket} fires; dtor
    // checks this to issue the matching -1 exactly once.
    bool ws_protocol_active_counted_ = false;
    // Install-once latch — set on the FIRST call to
    // SetObservabilitySnapshot regardless of whether the manager
    // lock succeeded or any cached pointer was populated. The lock-
    // free reads from MaybeEmitMessageSpan / BumpFrameCounter use
    // the cached pointers; a second call would race those reads.
    // Checking active_counted_/obs_manager_/cached-pointer truthiness
    // as the guard leaves a corner-case rebind window when the first
    // call's manager.lock() returned null — `bound_once_` closes it.
    bool bound_once_ = false;

    void ProcessFrame(const WebSocketFrame& frame);
    void SendFrame(const WebSocketFrame& frame);
    // Emit a ws.recv / ws.send INTERNAL span. No-op when obs unbound.
    // Called from dispatcher (ProcessFrame) and off-dispatcher under
    // send_mtx_ (SendFrame); Tracer / Span / BSP own internal mutexes.
    //
    // The parent SERVER span is already Ended by the time these spans
    // emit (finalized at upgrade-101 by HttpConnectionHandler). Children
    // attach via trace_id, not parent liveness — Tempo/Jaeger render the
    // ordering as "children after parent end". See
    // .claude/rules/pitfalls/OBSERVABILITY.md.
    void MaybeEmitMessageSpan(const char* name, WebSocketOpcode opcode,
                              size_t payload_size);
    // Bump reactor.websocket.frames {op, direction}. Same call-site /
    // threading invariants as MaybeEmitMessageSpan; Counter::Add is
    // thread-safe.
    void BumpFrameCounter(WebSocketOpcode opcode, const char* direction);
};
