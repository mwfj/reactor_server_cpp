#pragma once

// MockIntrospectionServer — header-only TCP test fixture that emulates an
// RFC 7662 introspection IdP. Spawns a worker thread on Start(), accepts
// one connection per configured response, reads the request, records its
// fields (Authorization header, body), and writes back the operator-
// configured status + JSON body. Used by the introspection integration
// tests (auth_introspection_integration_test.h, etc).
//
// This is a TEST-ONLY helper — not used by production code. Lives in the
// `test/` tree alongside other fixtures.

#include "common.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace MockIntrospectionServerNS {

// Configurable script for the next response the mock will send. Each
// Start() call consumes the script in order; once exhausted, the worker
// closes additional connections without responding.
struct ResponseScript {
    int status_code = 200;
    std::string body;                        // JSON body (verbatim)
    std::string content_type = "application/json";
    int delay_ms = 0;                        // Sleep before responding (timeout tests)
    bool close_without_response = false;     // For upstream_disconnect tests
};

class MockIntrospectionServer {
 public:
    MockIntrospectionServer() = default;

    ~MockIntrospectionServer() {
        Stop();
    }

    MockIntrospectionServer(const MockIntrospectionServer&) = delete;
    MockIntrospectionServer& operator=(const MockIntrospectionServer&) = delete;

    // Append a scripted response. Multiple appended responses are consumed
    // in order on successive incoming connections.
    void EnqueueResponse(ResponseScript r) {
        std::lock_guard<std::mutex> lk(mu_);
        scripts_.push_back(std::move(r));
    }

    // Convenience helper for the common success case.
    void EnqueueActiveTrue(const std::string& sub,
                           const std::vector<std::string>& scopes = {},
                           int64_t exp = 0) {
        std::string body = R"({"active":true,"sub":")" + sub + R"(")";
        if (!scopes.empty()) {
            std::string sc;
            for (const auto& s : scopes) {
                if (!sc.empty()) sc += ' ';
                sc += s;
            }
            body += R"(,"scope":")" + sc + R"(")";
        }
        if (exp > 0) {
            body += ",\"exp\":" + std::to_string(exp);
        }
        body += "}";
        ResponseScript r;
        r.body = std::move(body);
        EnqueueResponse(std::move(r));
    }

    void EnqueueActiveFalse() {
        ResponseScript r;
        r.body = R"({"active":false})";
        EnqueueResponse(std::move(r));
    }

    void EnqueueStatus(int status_code, const std::string& body = "") {
        ResponseScript r;
        r.status_code = status_code;
        r.body = body;
        EnqueueResponse(std::move(r));
    }

    // Bind to 127.0.0.1:0, start the worker thread, and return true on
    // success. Sets host_, port_, endpoint_url_ for caller introspection.
    bool Start() {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;
        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
        socklen_t len = sizeof(addr);
        if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
        port_ = ntohs(addr.sin_port);
        host_ = "127.0.0.1";
        endpoint_url_ = "http://" + host_ + ":" + std::to_string(port_)
            + "/introspect";

        if (::listen(listen_fd_, 16) != 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        running_.store(true, std::memory_order_release);
        worker_ = std::thread([this]() { RunLoop(); });
        return true;
    }

    void Stop() {
        bool was_running = running_.exchange(false, std::memory_order_acq_rel);
        if (listen_fd_ >= 0) {
            ::shutdown(listen_fd_, SHUT_RDWR);
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
        if (was_running && worker_.joinable()) {
            worker_.join();
        }
    }

    const std::string& host() const { return host_; }
    uint16_t port() const { return port_; }
    const std::string& endpoint_url() const { return endpoint_url_; }

    // The Authorization header value seen on the most recent request, or
    // empty if no request seen yet / no header present.
    std::string received_authorization_header() const {
        std::lock_guard<std::mutex> lk(mu_);
        return last_authorization_;
    }

    // The body bytes of the most recent request.
    std::string received_body() const {
        std::lock_guard<std::mutex> lk(mu_);
        return last_body_;
    }

    // Number of fully-handled requests since Start().
    size_t request_count() const {
        return request_count_.load(std::memory_order_acquire);
    }

 private:
    static const char* StatusReason(int status) {
        switch (status) {
            case 200: return "OK";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            default:   return "Status";
        }
    }

    void RunLoop() {
        while (running_.load(std::memory_order_acquire)) {
            sockaddr_in caddr{};
            socklen_t clen = sizeof(caddr);
            int cfd = ::accept(
                listen_fd_, reinterpret_cast<sockaddr*>(&caddr), &clen);
            if (cfd < 0) {
                if (!running_.load(std::memory_order_acquire)) return;
                continue;
            }
            HandleConnection(cfd);
            ::close(cfd);
        }
    }

    void HandleConnection(int cfd) {
        ResponseScript script;
        bool have_script = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!scripts_.empty()) {
                script = std::move(scripts_.front());
                scripts_.erase(scripts_.begin());
                have_script = true;
            }
        }

        // Read until we have full headers + body (Content-Length-bounded).
        std::string buf;
        buf.reserve(2048);
        size_t header_end = std::string::npos;
        size_t content_length = 0;
        bool have_headers = false;
        char chunk[1024];
        while (true) {
            ssize_t n = ::recv(cfd, chunk, sizeof(chunk), 0);
            if (n <= 0) break;
            buf.append(chunk, static_cast<size_t>(n));
            if (!have_headers) {
                header_end = buf.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    have_headers = true;
                    content_length = ParseContentLength(buf.substr(0, header_end));
                }
            }
            if (have_headers) {
                size_t expected = header_end + 4 + content_length;
                if (buf.size() >= expected) break;
            }
            if (buf.size() > 256 * 1024) break;     // Hard guard against runaway
        }

        if (have_headers) {
            std::string body;
            if (header_end + 4 <= buf.size()) {
                body = buf.substr(header_end + 4,
                                    std::min(content_length,
                                              buf.size() - (header_end + 4)));
            }
            std::string auth = ExtractHeader(buf.substr(0, header_end), "authorization");
            {
                std::lock_guard<std::mutex> lk(mu_);
                last_body_ = std::move(body);
                last_authorization_ = std::move(auth);
            }
            request_count_.fetch_add(1, std::memory_order_acq_rel);
        }

        if (!have_script) {
            // Drop the connection silently — caller asked for "no scripted
            // response" or scripts have been exhausted.
            return;
        }

        if (script.delay_ms > 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(script.delay_ms));
        }
        if (script.close_without_response) {
            return;
        }

        std::string resp;
        resp += "HTTP/1.1 ";
        resp += std::to_string(script.status_code);
        resp += ' ';
        resp += StatusReason(script.status_code);
        resp += "\r\n";
        resp += "Content-Type: ";
        resp += script.content_type;
        resp += "\r\n";
        resp += "Content-Length: ";
        resp += std::to_string(script.body.size());
        resp += "\r\n";
        resp += "Connection: close\r\n\r\n";
        resp += script.body;

        size_t off = 0;
        while (off < resp.size()) {
            ssize_t n = ::send(cfd, resp.data() + off, resp.size() - off,
                                MSG_NOSIGNAL);
            if (n <= 0) break;
            off += static_cast<size_t>(n);
        }
    }

    // Lower-case scan; returns the value of the first matching header, or
    // empty if absent.
    static std::string ExtractHeader(const std::string& headers,
                                       const std::string& name) {
        size_t pos = 0;
        while (pos < headers.size()) {
            size_t eol = headers.find("\r\n", pos);
            if (eol == std::string::npos) eol = headers.size();
            std::string line = headers.substr(pos, eol - pos);
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string h = line.substr(0, colon);
                for (auto& c : h) c = static_cast<char>(std::tolower(
                    static_cast<unsigned char>(c)));
                if (h == name) {
                    std::string v = line.substr(colon + 1);
                    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) {
                        v.erase(v.begin());
                    }
                    while (!v.empty() && (v.back() == ' ' || v.back() == '\t' ||
                                            v.back() == '\r')) {
                        v.pop_back();
                    }
                    return v;
                }
            }
            if (eol == headers.size()) break;
            pos = eol + 2;
        }
        return std::string();
    }

    static size_t ParseContentLength(const std::string& headers) {
        std::string v = ExtractHeader(headers, "content-length");
        if (v.empty()) return 0;
        try {
            long long n = std::stoll(v);
            return n > 0 ? static_cast<size_t>(n) : 0;
        } catch (...) {
            return 0;
        }
    }

    int listen_fd_ = -1;
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<size_t> request_count_{0};

    mutable std::mutex mu_;
    std::vector<ResponseScript> scripts_;
    std::string last_authorization_;
    std::string last_body_;

    std::string host_;
    uint16_t port_ = 0;
    std::string endpoint_url_;
};

}  // namespace MockIntrospectionServerNS
