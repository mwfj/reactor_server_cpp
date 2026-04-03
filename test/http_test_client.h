#pragma once

#include "common.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include <poll.h>
// <sys/socket.h>, <netinet/in.h>, <arpa/inet.h>, <unistd.h>,
// <chrono>, <string> provided by common.h

// Shared HTTP test client helpers used by multiple test suites.
// Replaces the legacy length-prefix Client class with HTTP-based helpers.

namespace TestHttpClient {

    static constexpr const char* TEST_IP = "127.0.0.1";

    // Register standard echo routes on an HttpServer for testing.
    inline void SetupEchoRoutes(HttpServer& server) {
        server.Get("/health", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Body("ok", "text/plain");
        });
        server.Post("/echo", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Body(req.body, "text/plain");
        });
    }

    // Build a ServerConfig with custom idle timeout for timer/timeout tests.
    inline ServerConfig MakeTestConfig(int idle_timeout_sec) {
        ServerConfig config;
        config.bind_host = "127.0.0.1";
        config.bind_port = 0;
        config.idle_timeout_sec = idle_timeout_sec;
        config.request_timeout_sec = 0;  // Disable request timeout
        config.worker_threads = 3;
        return config;
    }

    // Connect a raw TCP socket to the given port. Returns the fd, or -1 on failure.
    // Caller is responsible for closing the fd.
    inline int ConnectRawSocket(int port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return -1;

#ifdef SO_NOSIGPIPE
        int set = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
        // Set close-on-exec to prevent fd leaks into exec'd children
        fcntl(sockfd, F_SETFD, FD_CLOEXEC);

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(TEST_IP);

        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sockfd);
            return -1;
        }
        return sockfd;
    }

    // Set a receive timeout on a socket.
    inline void SetReceiveTimeout(int sockfd, int seconds, int microseconds = 0) {
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = microseconds;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    // Connect, send an HTTP request, read the response. Returns the full
    // response string. Uses poll() for reliable non-blocking I/O.
    inline std::string SendHttpRequest(int port, const std::string& request,
                                       int timeout_ms = 3000) {
        int sockfd = ConnectRawSocket(port);
        if (sockfd < 0) return "";

        int send_flags = 0;
#ifdef MSG_NOSIGNAL
        send_flags |= MSG_NOSIGNAL;
#endif
        // Send loop to handle partial writes under load
        size_t total_sent = 0;
        while (total_sent < request.size()) {
            ssize_t sent = send(sockfd, request.data() + total_sent,
                                request.size() - total_sent, send_flags);
            if (sent < 0) {
                if (errno == EINTR) continue;
                close(sockfd);
                return "";
            }
            total_sent += sent;
        }

        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;

        std::string response;
        char buf[4096];

        auto start = std::chrono::steady_clock::now();

        while (true) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            int remaining = timeout_ms - static_cast<int>(elapsed);
            if (remaining <= 0) break;

            int ret = poll(&pfd, 1, remaining);
            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
                if (n > 0) {
                    response.append(buf, n);
                    auto hdr_end = response.find("\r\n\r\n");
                    if (hdr_end != std::string::npos) {
                        size_t body_start = hdr_end + 4;
                        // Case-insensitive Content-Length search (RFC 9110: headers are case-insensitive)
                        std::string headers = response.substr(0, hdr_end);
                        for (auto& c : headers) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                        auto cl_pos = headers.find("content-length: ");
                        if (cl_pos != std::string::npos) {
                            size_t content_length = 0;
                            try {
                                content_length = std::stoul(headers.substr(cl_pos + 16));
                            } catch (const std::exception&) {
                                // Malformed Content-Length — fall through to Connection: close EOF
                                continue;
                            }
                            if (response.size() >= body_start + content_length) {
                                break;  // Full response received
                            }
                        }
                        // No Content-Length — continue reading until EOF or timeout
                    }
                } else {
                    break;  // Connection closed or error
                }
            } else {
                break;  // Timeout or error
            }
        }
        close(sockfd);
        return response;
    }

    // Send a GET request and return the response.
    inline std::string HttpGet(int port, const std::string& path,
                               int timeout_ms = 3000) {
        std::string request = "GET " + path + " HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Connection: close\r\n"
                              "\r\n";
        return SendHttpRequest(port, request, timeout_ms);
    }

    // Send a POST request with body and return the response.
    inline std::string HttpPost(int port, const std::string& path,
                                const std::string& body, int timeout_ms = 3000) {
        std::string request = "POST " + path + " HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Content-Length: " + std::to_string(body.size()) + "\r\n"
                              "Connection: close\r\n"
                              "\r\n" + body;
        return SendHttpRequest(port, request, timeout_ms);
    }

    // Extract the HTTP response body (everything after \r\n\r\n).
    inline std::string ExtractBody(const std::string& response) {
        auto pos = response.find("\r\n\r\n");
        if (pos == std::string::npos) return "";
        return response.substr(pos + 4);
    }

    // Check if the HTTP/1.x status line contains the given status code.
    // Assumes HTTP/1.x format: "HTTP/1.x NNN Reason\r\n" — status code
    // at fixed offset 9, length 3. Not applicable to HTTP/2 (binary framing).
    inline bool HasStatus(const std::string& response, int status_code) {
        auto line_end = response.find("\r\n");
        if (line_end == std::string::npos) return false;
        std::string status_line = response.substr(0, line_end);
        if (status_line.size() < 12) return false;
        return status_line.substr(9, 3) == std::to_string(status_code);
    }

    // Wait for the server to close a connection. Returns true if recv() == 0
    // (clean EOF) within timeout_ms. Uses poll() + recv().
    inline bool WaitForServerClose(int fd, int timeout_ms) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
            char buf[16];
            return (recv(fd, buf, sizeof(buf), 0) == 0);
        }
        return false;
    }

} // namespace TestHttpClient
