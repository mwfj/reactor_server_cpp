#pragma once

// h2_trailer_test.h — Phase J: G2+G3 coverage for HTTP/2 trailer sanitization
// and downstream trailer emission.
//
// Test dimensions:
//   Unit (in-process, no sockets):
//     T1  SanitizeHttp2TrailerFieldsForOutboundEmit end-to-end: allowed pass,
//         forbidden stripped
//     T2  IsForbiddenH2TrailerName exhaustive coverage of every forbidden name
//     T3  SanitizeHttp2TrailerField per-field classification
//     T4  Empty trailer vector in/out — no-op, no crash
//     T5  Mixed allowed + forbidden fields — only allowed survive
//     T6  Field name case-insensitive normalization: uppercase → lowercase output
//     T7  Pseudo-header names rejected (colon prefix)
//     T8  Content-related forbidden names (content-length, content-type, etc.)
//     T9  Connection-control forbidden names (connection, keep-alive, te, upgrade)
//     T10 Allowed custom header round-trip through sanitizer (x-*, custom-*)
//   Integration (real HttpServer + HTTP/2 client):
//     T11 H2 downstream trailer emit via StreamingResponseSender::End(trailers)
//     T12 Forbidden trailers stripped before emit — only allowed reach client
//     T13 Empty trailer list with End() produces no trailing HEADERS frame
//         (stream completes normally without trailer frame)

#include "test_framework.h"
#include "test_server_runner.h"
#include "http/http_server.h"
#include "http/http2_trailer_sanitizer.h"
#include "http/http_callbacks.h"
#include "http/http_request.h"
#include "config/server_config.h"

#include <nghttp2/nghttp2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

#include <thread>
#include <chrono>
#include <atomic>
#include <future>
#include <optional>
#include <map>

namespace H2TrailerTests {

// ---------------------------------------------------------------------------
// TrailerAwareHttp2Client — minimal H2 test client that captures trailing
// HEADERS frames into a separate trailers vector.
//
// Http2TestClient (http2_test.h) only marks a stream done via NGHTTP2_HCAT_RESPONSE.
// Trailing HEADERS have category NGHTTP2_HCAT_HEADERS — this client handles both.
// ---------------------------------------------------------------------------

class TrailerAwareHttp2Client {
public:
    struct Response {
        int         status  = 0;
        std::string body;
        bool        rst     = false;
        bool        error   = false;
        // Regular response headers (non-pseudo, non-trailer)
        std::vector<std::pair<std::string, std::string>> headers;
        // Trailing HEADERS fields received after body END_STREAM
        std::vector<std::pair<std::string, std::string>> trailers;
    };

    TrailerAwareHttp2Client() = default;
    ~TrailerAwareHttp2Client() { Disconnect(); }

    TrailerAwareHttp2Client(const TrailerAwareHttp2Client&) = delete;
    TrailerAwareHttp2Client& operator=(const TrailerAwareHttp2Client&) = delete;

    bool Connect(const std::string& host, int port) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(static_cast<uint16_t>(port));
        addr.sin_addr.s_addr = inet_addr(host.c_str());

        if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)) < 0) {
            ::close(fd_); fd_ = -1;
            return false;
        }

        struct timeval tv{};
        tv.tv_sec  = 5;
        tv.tv_usec = 0;
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        nghttp2_session_callbacks* cbs = nullptr;
        nghttp2_session_callbacks_new(&cbs);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, OnFrameRecv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, OnDataChunkRecv);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, OnStreamClose);
        nghttp2_session_callbacks_set_on_header_callback(cbs, OnHeader);

        int rv = nghttp2_session_client_new(&session_, cbs, this);
        nghttp2_session_callbacks_del(cbs);
        if (rv != 0) { ::close(fd_); fd_ = -1; return false; }

        rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0);
        if (rv != 0) { Disconnect(); return false; }
        if (!FlushOutput()) { Disconnect(); return false; }
        if (!ReadAndProcess(5000)) { Disconnect(); return false; }

        return true;
    }

    void Disconnect() {
        if (session_) {
            nghttp2_session_del(session_);
            session_ = nullptr;
        }
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        streams_.clear();
    }

    Response Get(const std::string& path,
                 const std::vector<std::pair<std::string,std::string>>& extra = {}) {
        return SendRequest("GET", path, "", extra);
    }

    Response Post(const std::string& path, const std::string& body,
                  const std::vector<std::pair<std::string,std::string>>& extra = {}) {
        return SendRequest("POST", path, body, extra);
    }

    Response SendRequest(
        const std::string& method,
        const std::string& path,
        const std::string& req_body = "",
        const std::vector<std::pair<std::string,std::string>>& extra = {})
    {
        if (!session_ || fd_ < 0) {
            Response r; r.error = true; return r;
        }

        std::vector<std::pair<std::string, std::string>> hpairs;
        hpairs.reserve(4 + extra.size());
        hpairs.emplace_back(":method",    method);
        hpairs.emplace_back(":path",      path);
        hpairs.emplace_back(":scheme",    "http");
        hpairs.emplace_back(":authority", "localhost");
        for (const auto& h : extra) hpairs.push_back(h);

        std::vector<nghttp2_nv> nva;
        nva.reserve(hpairs.size());
        for (const auto& hp : hpairs) {
            nva.push_back({
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hp.first.c_str())),
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hp.second.c_str())),
                hp.first.size(), hp.second.size(), NGHTTP2_NV_FLAG_NONE
            });
        }

        int32_t stream_id = -1;
        if (req_body.empty()) {
            stream_id = nghttp2_submit_request2(
                session_, nullptr, nva.data(), nva.size(), nullptr, this);
        } else {
            pending_body_   = req_body;
            pending_offset_ = 0;
            nghttp2_data_provider2 dp;
            dp.source.ptr    = this;
            dp.read_callback = DataSourceRead;
            stream_id = nghttp2_submit_request2(
                session_, nullptr, nva.data(), nva.size(), &dp, this);
        }

        if (stream_id < 0) {
            Response r; r.error = true; return r;
        }

        streams_[stream_id] = StreamState{};
        if (!FlushOutput()) {
            Response r; r.error = true; return r;
        }

        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(8000);

        while (true) {
            auto it = streams_.find(stream_id);
            if (it != streams_.end() && it->second.closed) {
                Response resp;
                resp.status   = it->second.status;
                resp.body     = it->second.body;
                resp.rst      = it->second.rst;
                resp.headers  = std::move(it->second.response_headers);
                resp.trailers = std::move(it->second.trailer_headers);
                streams_.erase(it);
                return resp;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                Response r; r.error = true; return r;
            }
            if (!ReadAndProcess(100)) {
                // Connection closed — collect whatever we have
                auto jt = streams_.find(stream_id);
                if (jt != streams_.end()) {
                    Response resp;
                    resp.status   = jt->second.status;
                    resp.body     = jt->second.body;
                    resp.rst      = jt->second.rst;
                    resp.headers  = std::move(jt->second.response_headers);
                    resp.trailers = std::move(jt->second.trailer_headers);
                    streams_.erase(jt);
                    return resp;
                }
                Response r; r.error = true; return r;
            }
        }
    }

private:
    int fd_ = -1;
    nghttp2_session* session_ = nullptr;

    std::string pending_body_;
    size_t      pending_offset_ = 0;

    struct StreamState {
        int         status = 0;
        std::string body;
        bool        closed = false;
        bool        rst    = false;
        bool        saw_data_end_stream = false;
        std::vector<std::pair<std::string, std::string>> response_headers;
        std::vector<std::pair<std::string, std::string>> trailer_headers;
        // Track which HEADERS block we are in:
        //   RESPONSE = waiting for initial :status block
        //   DATA     = body phase (between initial HEADERS and trailing HEADERS)
        //   TRAILER  = receiving trailing HEADERS
        enum class Phase { RESPONSE, DATA, TRAILER } phase = Phase::RESPONSE;
    };
    std::map<int32_t, StreamState> streams_;

    bool SendRaw(const char* data, size_t len) {
        while (len > 0) {
            ssize_t n = ::send(fd_, data, len, 0);
            if (n <= 0) return false;
            data += n; len -= static_cast<size_t>(n);
        }
        return true;
    }

    bool FlushOutput() {
        for (;;) {
            const uint8_t* out = nullptr;
            ssize_t len = nghttp2_session_mem_send2(session_, &out);
            if (len < 0) return false;
            if (len == 0) break;
            if (!SendRaw(reinterpret_cast<const char*>(out),
                         static_cast<size_t>(len))) return false;
        }
        return true;
    }

    bool ReadAndProcess(int timeout_ms) {
        struct pollfd pfd{};
        pfd.fd = fd_; pfd.events = POLLIN;
        int ret = ::poll(&pfd, 1, timeout_ms);
        if (ret < 0) return false;
        if (ret == 0) return true;
        if (pfd.revents & (POLLHUP | POLLERR)) return false;
        char buf[16384];
        ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        ssize_t consumed = nghttp2_session_mem_recv2(
            session_, reinterpret_cast<const uint8_t*>(buf),
            static_cast<size_t>(n));
        if (consumed < 0) return false;
        return FlushOutput();
    }

    // ---- nghttp2 callbacks ----

    static int OnFrameRecv(nghttp2_session* /*session*/,
                           const nghttp2_frame* frame,
                           void* user_data) {
        auto* self = static_cast<TrailerAwareHttp2Client*>(user_data);
        int32_t sid = frame->hd.stream_id;
        auto it = self->streams_.find(sid);
        if (it == self->streams_.end()) return 0;
        StreamState& s = it->second;

        if (frame->hd.type == NGHTTP2_HEADERS) {
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                // Initial response HEADERS
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                    s.closed = true;
                }
                // Phase transitions to DATA after first response HEADERS
                s.phase = StreamState::Phase::DATA;
            } else if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
                // Trailing HEADERS frame
                s.phase = StreamState::Phase::TRAILER;
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                    s.closed = true;
                }
            }
        } else if (frame->hd.type == NGHTTP2_DATA) {
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                s.closed = true;
            }
        } else if (frame->hd.type == NGHTTP2_RST_STREAM) {
            s.rst    = true;
            s.closed = true;
        }
        return 0;
    }

    static int OnHeader(nghttp2_session* /*session*/,
                        const nghttp2_frame* frame,
                        const uint8_t* name,   size_t namelen,
                        const uint8_t* value,  size_t valuelen,
                        uint8_t /*flags*/, void* user_data) {
        auto* self = static_cast<TrailerAwareHttp2Client*>(user_data);
        int32_t sid = frame->hd.stream_id;
        auto it = self->streams_.find(sid);
        if (it == self->streams_.end()) return 0;
        StreamState& s = it->second;

        std::string n(reinterpret_cast<const char*>(name),  namelen);
        std::string v(reinterpret_cast<const char*>(value), valuelen);

        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
            if (n == ":status") {
                try { s.status = std::stoi(v); } catch (...) {}
            } else {
                s.response_headers.emplace_back(std::move(n), std::move(v));
            }
        } else if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
            // Trailing HEADERS — capture everything (no :status expected)
            s.trailer_headers.emplace_back(std::move(n), std::move(v));
        }
        return 0;
    }

    static int OnDataChunkRecv(nghttp2_session* /*session*/,
                               uint8_t /*flags*/,
                               int32_t stream_id,
                               const uint8_t* data, size_t len,
                               void* user_data) {
        auto* self = static_cast<TrailerAwareHttp2Client*>(user_data);
        auto it = self->streams_.find(stream_id);
        if (it != self->streams_.end()) {
            it->second.body.append(
                reinterpret_cast<const char*>(data), len);
        }
        return 0;
    }

    static int OnStreamClose(nghttp2_session* /*session*/,
                             int32_t stream_id,
                             uint32_t /*error_code*/,
                             void* user_data) {
        auto* self = static_cast<TrailerAwareHttp2Client*>(user_data);
        auto it = self->streams_.find(stream_id);
        if (it != self->streams_.end()) {
            it->second.closed = true;
        }
        return 0;
    }

    static ssize_t DataSourceRead(nghttp2_session* /*session*/,
                                  int32_t /*stream_id*/,
                                  uint8_t* buf, size_t length,
                                  uint32_t* data_flags,
                                  nghttp2_data_source* source,
                                  void* /*user_data*/) {
        auto* self = static_cast<TrailerAwareHttp2Client*>(source->ptr);
        size_t remaining = self->pending_body_.size() - self->pending_offset_;
        size_t to_copy   = std::min(remaining, length);
        if (to_copy > 0) {
            std::memcpy(buf,
                        self->pending_body_.data() + self->pending_offset_,
                        to_copy);
            self->pending_offset_ += to_copy;
        }
        if (self->pending_offset_ >= self->pending_body_.size()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return static_cast<ssize_t>(to_copy);
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static ServerConfig MakeH2TrailerTestConfig() {
    ServerConfig cfg;
    cfg.bind_host       = "127.0.0.1";
    cfg.bind_port       = 0;
    cfg.worker_threads  = 2;
    cfg.http2.enabled   = true;
    return cfg;
}

// Find a trailer by name (case-sensitive on already-lowercased names).
static const std::string* FindTrailer(
    const std::vector<std::pair<std::string, std::string>>& trailers,
    const std::string& name) {
    for (const auto& t : trailers) {
        if (t.first == name) return &t.second;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// T1: SanitizeHttp2TrailerFieldsForOutboundEmit end-to-end
//     Allowed fields pass through; every forbidden name is stripped.
// ---------------------------------------------------------------------------
void TestT1_SanitizeOutboundEndToEnd() {
    std::cout << "\n[TEST] T1: SanitizeHttp2TrailerFieldsForOutboundEmit — allowed pass, forbidden stripped..."
              << std::endl;
    try {
        // Mix of allowed and forbidden fields
        std::vector<std::pair<std::string, std::string>> input = {
            {"x-checksum",        "abc123"},       // allowed
            {"content-length",    "42"},            // forbidden
            {"x-custom-field",    "hello"},         // allowed
            {"transfer-encoding", "chunked"},       // forbidden
            {"grpc-status",       "0"},             // allowed
            {"connection",        "keep-alive"},    // forbidden
            {"x-trace-id",        "deadbeef"},     // allowed
        };

        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(input);

        bool pass = true;
        std::string err;

        // Allowed fields must be present
        auto find = [&](const std::string& name) -> bool {
            for (const auto& p : output)
                if (p.first == name) return true;
            return false;
        };
        if (!find("x-checksum"))     { pass = false; err += "x-checksum missing; "; }
        if (!find("x-custom-field")) { pass = false; err += "x-custom-field missing; "; }
        if (!find("grpc-status"))    { pass = false; err += "grpc-status missing; "; }
        if (!find("x-trace-id"))     { pass = false; err += "x-trace-id missing; "; }

        // Forbidden fields must be absent
        if (find("content-length"))    { pass = false; err += "content-length survived; "; }
        if (find("transfer-encoding")) { pass = false; err += "transfer-encoding survived; "; }
        if (find("connection"))        { pass = false; err += "connection survived; "; }

        // Count: 4 allowed, 3 forbidden stripped
        if (output.size() != 4) {
            pass = false;
            err += "output size=" + std::to_string(output.size()) + " want 4; ";
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: outbound end-to-end allowed/forbidden",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: outbound end-to-end allowed/forbidden",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T2: IsForbiddenH2TrailerName — exhaustive coverage of every forbidden name
// ---------------------------------------------------------------------------
void TestT2_IsForbiddenH2TrailerName() {
    std::cout << "\n[TEST] T2: IsForbiddenH2TrailerName — exhaustive forbidden names..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        // All explicitly forbidden names
        const std::vector<std::string> forbidden_names = {
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
            "te",
            "trailer",
            "content-length",
            "host",
            "authorization",
            "content-type",
            "content-encoding",
            "content-range",
        };

        for (const auto& name : forbidden_names) {
            if (!http::IsForbiddenH2TrailerName(name)) {
                pass = false;
                err += "'" + name + "' not detected as forbidden; ";
            }
        }

        // Pseudo-header prefix (':') is always forbidden
        if (!http::IsForbiddenH2TrailerName(":status"))    { pass = false; err += ":status not forbidden; "; }
        if (!http::IsForbiddenH2TrailerName(":path"))      { pass = false; err += ":path not forbidden; "; }
        if (!http::IsForbiddenH2TrailerName(":method"))    { pass = false; err += ":method not forbidden; "; }
        if (!http::IsForbiddenH2TrailerName(":authority")) { pass = false; err += ":authority not forbidden; "; }
        if (!http::IsForbiddenH2TrailerName(":scheme"))    { pass = false; err += ":scheme not forbidden; "; }

        // Empty string is forbidden
        if (!http::IsForbiddenH2TrailerName("")) {
            pass = false; err += "empty name not forbidden; ";
        }

        // Allowed custom headers must NOT be forbidden
        const std::vector<std::string> allowed_names = {
            "x-checksum",
            "x-custom-field",
            "grpc-status",
            "grpc-message",
            "x-trace-id",
            "x-request-id",
            "etag",
            "expires",
            "vary",
        };
        for (const auto& name : allowed_names) {
            if (http::IsForbiddenH2TrailerName(name)) {
                pass = false;
                err += "'" + name + "' falsely marked forbidden; ";
            }
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: IsForbiddenH2TrailerName exhaustive",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: IsForbiddenH2TrailerName exhaustive",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T3: SanitizeHttp2TrailerField per-field classification
//     Contract: caller lowercases the name before passing it. The function
//     stores the name as-is in lower_name and classifies via IsForbiddenH2TrailerName.
// ---------------------------------------------------------------------------
void TestT3_SanitizeHttp2TrailerField() {
    std::cout << "\n[TEST] T3: SanitizeHttp2TrailerField per-field classification..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Forbidden field (caller lowercases first — that is the documented contract)
        auto r1 = http::SanitizeHttp2TrailerField("content-length", "42");
        if (r1.classification != http::H2TrailerClassification::Forbidden) {
            pass = false; err += "content-length not Forbidden; ";
        }
        if (r1.lower_name != "content-length") {
            pass = false; err += "content-length lower_name wrong: " + r1.lower_name + "; ";
        }

        // Allowed field (already lowercase)
        auto r2 = http::SanitizeHttp2TrailerField("x-checksum", "abc");
        if (r2.classification != http::H2TrailerClassification::Accept) {
            pass = false; err += "x-checksum not Accept; ";
        }
        if (r2.lower_name != "x-checksum") {
            pass = false; err += "x-checksum lower_name wrong: " + r2.lower_name + "; ";
        }

        // Pseudo-header (colon prefix is forbidden regardless of case)
        auto r3 = http::SanitizeHttp2TrailerField(":status", "200");
        if (r3.classification != http::H2TrailerClassification::Forbidden) {
            pass = false; err += ":status not Forbidden; ";
        }

        // Empty name is forbidden
        auto r4 = http::SanitizeHttp2TrailerField("", "value");
        if (r4.classification != http::H2TrailerClassification::Forbidden) {
            pass = false; err += "empty name not Forbidden; ";
        }

        // grpc-status is allowed
        auto r5 = http::SanitizeHttp2TrailerField("grpc-status", "0");
        if (r5.classification != http::H2TrailerClassification::Accept) {
            pass = false; err += "grpc-status not Accept; ";
        }
        if (r5.lower_name != "grpc-status") {
            pass = false; err += "grpc-status lower_name wrong: " + r5.lower_name + "; ";
        }

        // transfer-encoding is forbidden
        auto r6 = http::SanitizeHttp2TrailerField("transfer-encoding", "chunked");
        if (r6.classification != http::H2TrailerClassification::Forbidden) {
            pass = false; err += "transfer-encoding not Forbidden; ";
        }

        // authorization is forbidden
        auto r7 = http::SanitizeHttp2TrailerField("authorization", "Bearer tok");
        if (r7.classification != http::H2TrailerClassification::Forbidden) {
            pass = false; err += "authorization not Forbidden; ";
        }

        // host is forbidden
        auto r8 = http::SanitizeHttp2TrailerField("host", "example.com");
        if (r8.classification != http::H2TrailerClassification::Forbidden) {
            pass = false; err += "host not Forbidden; ";
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: SanitizeHttp2TrailerField per-field",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: SanitizeHttp2TrailerField per-field",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T4: Empty trailer vector in → empty vector out, no crash
// ---------------------------------------------------------------------------
void TestT4_EmptyTrailerVectorPassthrough() {
    std::cout << "\n[TEST] T4: Empty trailer vector passthrough..."
              << std::endl;
    try {
        std::vector<std::pair<std::string, std::string>> empty;
        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(empty);

        bool pass = output.empty();
        std::string err;
        if (!pass) {
            err = "non-empty output for empty input, size=" +
                  std::to_string(output.size());
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: empty input → empty output",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: empty input → empty output",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T5: Mixed allowed + forbidden — only allowed survive, order preserved
// ---------------------------------------------------------------------------
void TestT5_MixedAllowedAndForbidden() {
    std::cout << "\n[TEST] T5: Mixed allowed + forbidden — only allowed survive..."
              << std::endl;
    try {
        std::vector<std::pair<std::string, std::string>> input = {
            {"x-a",               "1"},   // allowed
            {"connection",        "x"},   // forbidden
            {"x-b",               "2"},   // allowed
            {"host",              "y"},   // forbidden
            {"x-c",               "3"},   // allowed
            {"authorization",     "z"},   // forbidden
            {"x-d",               "4"},   // allowed
        };

        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(input);

        bool pass = true;
        std::string err;

        if (output.size() != 4) {
            pass = false;
            err += "size=" + std::to_string(output.size()) + " want 4; ";
        }

        // Order must be preserved: x-a, x-b, x-c, x-d
        if (output.size() == 4) {
            if (output[0].first != "x-a" || output[0].second != "1") {
                pass = false; err += "output[0] wrong; ";
            }
            if (output[1].first != "x-b" || output[1].second != "2") {
                pass = false; err += "output[1] wrong; ";
            }
            if (output[2].first != "x-c" || output[2].second != "3") {
                pass = false; err += "output[2] wrong; ";
            }
            if (output[3].first != "x-d" || output[3].second != "4") {
                pass = false; err += "output[3] wrong; ";
            }
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: mixed allowed+forbidden, order preserved",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: mixed allowed+forbidden, order preserved",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T6: SanitizeHttp2TrailerFieldsForOutboundEmit normalizes names to lowercase.
//     IsForbiddenH2TrailerName requires pre-lowercased input per its contract.
//     This test verifies the outbound sanitizer handles mixed-case input correctly.
// ---------------------------------------------------------------------------
void TestT6_CaseInsensitiveNormalization() {
    std::cout << "\n[TEST] T6: SanitizeHttp2TrailerFieldsForOutboundEmit normalizes names to lowercase..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        // IsForbiddenH2TrailerName contract: caller must pass lowercase.
        // Verify lowercase forbidden names work.
        if (!http::IsForbiddenH2TrailerName("content-length")) {
            pass = false; err += "content-length not forbidden; ";
        }
        if (!http::IsForbiddenH2TrailerName("connection")) {
            pass = false; err += "connection not forbidden; ";
        }
        if (http::IsForbiddenH2TrailerName("x-checksum")) {
            pass = false; err += "x-checksum falsely forbidden; ";
        }

        // SanitizeHttp2TrailerFieldsForOutboundEmit normalizes mixed-case input.
        std::vector<std::pair<std::string, std::string>> input = {
            {"X-My-Trailer",      "value1"},       // allowed (mixed case)
            {"GRPC-STATUS",       "0"},             // allowed (uppercase)
            {"Transfer-Encoding", "chunked"},       // forbidden (mixed case)
            {"CONTENT-LENGTH",    "100"},           // forbidden (uppercase)
            {"x-trace-id",        "trace-001"},    // allowed (already lowercase)
        };
        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(input);

        // 3 allowed survive (X-My-Trailer, GRPC-STATUS, x-trace-id); 2 forbidden stripped
        if (output.size() != 3) {
            pass = false;
            err += "outbound size=" + std::to_string(output.size()) + " want 3; ";
        }

        // All output names must be lowercase
        for (const auto& p : output) {
            for (char c : p.first) {
                if (c >= 'A' && c <= 'Z') {
                    pass = false;
                    err += "uppercase char in output name '" + p.first + "'; ";
                    break;
                }
            }
        }

        // Verify forbidden names are absent in output
        for (const auto& p : output) {
            if (p.first == "transfer-encoding" || p.first == "content-length") {
                pass = false;
                err += "forbidden field '" + p.first + "' survived; ";
            }
        }

        // Verify allowed names are present in output (lowercased)
        auto has_name = [&output](const std::string& n) {
            for (const auto& p : output) if (p.first == n) return true;
            return false;
        };
        if (!has_name("x-my-trailer"))  { pass = false; err += "x-my-trailer missing; "; }
        if (!has_name("grpc-status"))   { pass = false; err += "grpc-status missing; "; }
        if (!has_name("x-trace-id"))    { pass = false; err += "x-trace-id missing; "; }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: outbound normalizes names to lowercase",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: outbound normalizes names to lowercase",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T7: Pseudo-header names are always rejected (colon prefix rule)
// ---------------------------------------------------------------------------
void TestT7_PseudoHeadersRejected() {
    std::cout << "\n[TEST] T7: Pseudo-header names rejected (colon prefix)..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        const std::vector<std::string> pseudos = {
            ":status", ":path", ":method", ":scheme", ":authority",
            ":protocol", ":custom",
        };
        for (const auto& name : pseudos) {
            if (!http::IsForbiddenH2TrailerName(name)) {
                pass = false;
                err += "'" + name + "' not forbidden; ";
            }
        }

        // Verify via the full sanitizer too
        std::vector<std::pair<std::string, std::string>> input;
        for (const auto& name : pseudos) {
            input.emplace_back(name, "value");
        }
        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(input);
        if (!output.empty()) {
            pass = false;
            err += "pseudo-headers survived sanitizer, count=" +
                   std::to_string(output.size()) + "; ";
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: pseudo-headers always rejected",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: pseudo-headers always rejected",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T8: Content-related forbidden names (content-length, content-type, etc.)
// ---------------------------------------------------------------------------
void TestT8_ContentRelatedForbidden() {
    std::cout << "\n[TEST] T8: Content-related forbidden trailer names..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        const std::vector<std::string> content_forbidden = {
            "content-length",
            "content-type",
            "content-encoding",
            "content-range",
            "host",
            "authorization",
        };
        for (const auto& name : content_forbidden) {
            if (!http::IsForbiddenH2TrailerName(name)) {
                pass = false;
                err += "'" + name + "' not forbidden; ";
            }
        }

        std::vector<std::pair<std::string, std::string>> input;
        for (const auto& name : content_forbidden) {
            input.emplace_back(name, "dummy");
        }
        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(input);
        if (!output.empty()) {
            pass = false;
            err += "content-related fields survived sanitizer, count=" +
                   std::to_string(output.size()) + "; ";
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: content-related names forbidden",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: content-related names forbidden",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T9: Connection-control forbidden names
// ---------------------------------------------------------------------------
void TestT9_ConnectionControlForbidden() {
    std::cout << "\n[TEST] T9: Connection-control forbidden trailer names..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        const std::vector<std::string> conn_forbidden = {
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
            "te",
            "trailer",
        };
        for (const auto& name : conn_forbidden) {
            if (!http::IsForbiddenH2TrailerName(name)) {
                pass = false;
                err += "'" + name + "' not forbidden; ";
            }
        }

        std::vector<std::pair<std::string, std::string>> input;
        for (const auto& name : conn_forbidden) {
            input.emplace_back(name, "dummy");
        }
        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(input);
        if (!output.empty()) {
            pass = false;
            err += "connection-control fields survived sanitizer, count=" +
                   std::to_string(output.size()) + "; ";
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: connection-control names forbidden",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: connection-control names forbidden",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T10: Allowed custom headers round-trip through sanitizer (x-*, grpc-*)
// ---------------------------------------------------------------------------
void TestT10_AllowedCustomHeaders() {
    std::cout << "\n[TEST] T10: Allowed custom headers pass through sanitizer..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        const std::vector<std::pair<std::string, std::string>> allowed = {
            {"x-checksum",    "crc32:abc123"},
            {"x-request-id",  "req-42"},
            {"grpc-status",   "0"},
            {"grpc-message",  "ok"},
            {"etag",          "\"v1\""},
            {"expires",       "Thu, 01 Jan 1970 00:00:00 GMT"},
            {"vary",          "Accept-Encoding"},
            {"x-trace-id",    "trace-001"},
        };

        auto output = http::SanitizeHttp2TrailerFieldsForOutboundEmit(allowed);

        if (output.size() != allowed.size()) {
            pass = false;
            err += "size=" + std::to_string(output.size()) +
                   " want " + std::to_string(allowed.size()) + "; ";
        }

        // Each allowed field must appear in output with correct value
        for (const auto& kv : allowed) {
            // Name in output is lowercased
            std::string lower_name = kv.first;
            for (char& c : lower_name) c = static_cast<char>(std::tolower(c));
            bool found = false;
            for (const auto& out : output) {
                if (out.first == lower_name && out.second == kv.second) {
                    found = true; break;
                }
            }
            if (!found) {
                pass = false;
                err += "'" + kv.first + "' missing or value changed; ";
            }
        }

        TestFramework::RecordTest(
            "H2 trailer sanitizer: allowed custom headers round-trip",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 trailer sanitizer: allowed custom headers round-trip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T11: H2 downstream trailer emit — trailers from End(trailers) reach client
// ---------------------------------------------------------------------------
void TestT11_H2DownstreamTrailerEmit() {
    std::cout << "\n[TEST] T11: H2 downstream trailer emit via StreamingResponseSender..."
              << std::endl;
    try {
        HttpServer server(MakeH2TrailerTestConfig());

        server.GetAsync(
            "/stream-with-trailers",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender /*interim*/,
               HttpRouter::ResourcePusher /*push*/,
               HttpRouter::StreamingResponseSender stream_sender,
               HttpRouter::AsyncCompletionCallback /*complete*/) {
                HttpResponse head;
                head.Status(200).Header("Content-Type", "text/plain");
                if (stream_sender.SendHeaders(head) < 0) return;

                auto sr = stream_sender.SendData("hello", 5);
                if (sr == HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED)
                    return;

                // Emit trailers with End()
                (void)stream_sender.End({
                    {"x-checksum",  "crc32:abc"},
                    {"grpc-status", "0"},
                });
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        TrailerAwareHttp2Client client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false;
            err  = "connect failed";
        } else {
            auto resp = client.Get("/stream-with-trailers");
            if (resp.error) {
                pass = false; err += "client error; ";
            }
            if (resp.rst) {
                pass = false; err += "unexpected RST_STREAM; ";
            }
            if (resp.status != 200) {
                pass = false;
                err += "status=" + std::to_string(resp.status) + "; ";
            }
            if (resp.body != "hello") {
                pass = false;
                err += "body='" + resp.body + "' want 'hello'; ";
            }
            // Verify trailers are present
            auto* v_checksum = FindTrailer(resp.trailers, "x-checksum");
            if (!v_checksum) {
                pass = false; err += "x-checksum trailer missing; ";
            } else if (*v_checksum != "crc32:abc") {
                pass = false; err += "x-checksum value wrong: " + *v_checksum + "; ";
            }
            auto* v_grpc = FindTrailer(resp.trailers, "grpc-status");
            if (!v_grpc) {
                pass = false; err += "grpc-status trailer missing; ";
            } else if (*v_grpc != "0") {
                pass = false; err += "grpc-status value wrong: " + *v_grpc + "; ";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 downstream trailer emit via StreamingResponseSender::End",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 downstream trailer emit via StreamingResponseSender::End",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T12: Forbidden trailers stripped before emit — only allowed reach client
// ---------------------------------------------------------------------------
void TestT12_ForbiddenTrailersStrippedBeforeEmit() {
    std::cout << "\n[TEST] T12: Forbidden trailers stripped before H2 emit..."
              << std::endl;
    try {
        HttpServer server(MakeH2TrailerTestConfig());

        server.GetAsync(
            "/stream-mixed-trailers",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender /*interim*/,
               HttpRouter::ResourcePusher /*push*/,
               HttpRouter::StreamingResponseSender stream_sender,
               HttpRouter::AsyncCompletionCallback /*complete*/) {
                HttpResponse head;
                head.Status(200).Header("Content-Type", "text/plain");
                if (stream_sender.SendHeaders(head) < 0) return;

                auto sr = stream_sender.SendData("data", 4);
                if (sr == HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED)
                    return;

                // Mix of allowed and forbidden trailer fields
                (void)stream_sender.End({
                    {"x-allowed",         "yes"},          // allowed
                    {"content-length",    "999"},          // forbidden
                    {"grpc-status",       "1"},            // allowed
                    {"transfer-encoding", "identity"},    // forbidden
                    {"x-trace-id",        "trace-123"},   // allowed
                });
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        TrailerAwareHttp2Client client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false;
            err  = "connect failed";
        } else {
            auto resp = client.Get("/stream-mixed-trailers");
            if (resp.error) {
                pass = false; err += "client error; ";
            }
            if (resp.status != 200) {
                pass = false;
                err += "status=" + std::to_string(resp.status) + "; ";
            }

            // Allowed trailers must be present
            if (!FindTrailer(resp.trailers, "x-allowed")) {
                pass = false; err += "x-allowed trailer missing; ";
            }
            if (!FindTrailer(resp.trailers, "grpc-status")) {
                pass = false; err += "grpc-status trailer missing; ";
            }
            if (!FindTrailer(resp.trailers, "x-trace-id")) {
                pass = false; err += "x-trace-id trailer missing; ";
            }

            // Forbidden trailers must be absent
            if (FindTrailer(resp.trailers, "content-length")) {
                pass = false; err += "content-length trailer survived; ";
            }
            if (FindTrailer(resp.trailers, "transfer-encoding")) {
                pass = false; err += "transfer-encoding trailer survived; ";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 downstream trailer emit: forbidden stripped before emit",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 downstream trailer emit: forbidden stripped before emit",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// T13: Empty trailer list with End() — stream completes normally
//      The client receives the response body without a trailing HEADERS frame.
// ---------------------------------------------------------------------------
void TestT13_EmptyTrailersEndNoFrame() {
    std::cout << "\n[TEST] T13: End() with empty trailers — stream completes normally..."
              << std::endl;
    try {
        HttpServer server(MakeH2TrailerTestConfig());

        server.GetAsync(
            "/stream-no-trailers",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender /*interim*/,
               HttpRouter::ResourcePusher /*push*/,
               HttpRouter::StreamingResponseSender stream_sender,
               HttpRouter::AsyncCompletionCallback /*complete*/) {
                HttpResponse head;
                head.Status(200).Header("Content-Type", "text/plain");
                if (stream_sender.SendHeaders(head) < 0) return;

                auto sr = stream_sender.SendData("world", 5);
                if (sr == HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED)
                    return;

                // End with no trailers — must not produce a trailing HEADERS frame
                (void)stream_sender.End({});
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        TrailerAwareHttp2Client client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false;
            err  = "connect failed";
        } else {
            auto resp = client.Get("/stream-no-trailers");
            if (resp.error) {
                pass = false; err += "client error; ";
            }
            if (resp.rst) {
                pass = false; err += "unexpected RST_STREAM; ";
            }
            if (resp.status != 200) {
                pass = false;
                err += "status=" + std::to_string(resp.status) + "; ";
            }
            if (resp.body != "world") {
                pass = false;
                err += "body='" + resp.body + "' want 'world'; ";
            }
            // No trailing HEADERS expected
            if (!resp.trailers.empty()) {
                pass = false;
                err += "unexpected trailers, count=" +
                       std::to_string(resp.trailers.size()) + "; ";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 downstream: End() with empty trailers completes normally",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 downstream: End() with empty trailers completes normally",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

void RunAllH2TrailerTests() {
    std::cout << "\n=== H2 Trailer Tests ===" << std::endl;

    // Unit tests — pure in-process sanitizer logic
    TestT1_SanitizeOutboundEndToEnd();
    TestT2_IsForbiddenH2TrailerName();
    TestT3_SanitizeHttp2TrailerField();
    TestT4_EmptyTrailerVectorPassthrough();
    TestT5_MixedAllowedAndForbidden();
    TestT6_CaseInsensitiveNormalization();
    TestT7_PseudoHeadersRejected();
    TestT8_ContentRelatedForbidden();
    TestT9_ConnectionControlForbidden();
    TestT10_AllowedCustomHeaders();

    // Integration tests — real HttpServer + H2 client
    TestT11_H2DownstreamTrailerEmit();
    TestT12_ForbiddenTrailersStrippedBeforeEmit();
    TestT13_EmptyTrailersEndNoFrame();

    std::cout << "=== H2 Trailer Tests Done ===" << std::endl;
}

}  // namespace H2TrailerTests
