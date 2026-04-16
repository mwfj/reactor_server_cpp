#pragma once

#include "common.h"
#include "http/http_request.h"

#define private public
#include "connection_handler.h"
#include "socket_handler.h"
#include "upstream/upstream_connection.h"
#include "upstream/proxy_transaction.h"
#undef private

#include "test_framework.h"
#include "http/http_status.h"

namespace ProxyTransactionInternalTests {

void TestHeldRetryable5xxResumeCompletesBodylessResponse() {
    std::cout << "\n[TEST] ProxyTransaction internal: held 5xx resume completes bodyless response..."
              << std::endl;
    try {
        HttpRequest request;
        request.method = "GET";
        request.url = "/held-5xx";
        request.path = "/held-5xx";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        ProxyConfig proxy_config;
        HeaderRewriter::Config rewriter_config;
        HeaderRewriter header_rewriter(rewriter_config);
        RetryPolicy::Config retry_config;
        RetryPolicy retry_policy(retry_config);

        bool delivered = false;
        int delivered_status = 0;
        std::string delivered_body;
        auto tx = std::make_shared<ProxyTransaction>(
            "svc",
            request,
            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender(),
            [&delivered, &delivered_status, &delivered_body](HttpResponse response) {
                delivered = true;
                delivered_status = response.GetStatusCode();
                delivered_body = response.GetBody();
            },
            nullptr,
            proxy_config,
            header_rewriter,
            retry_policy,
            false,
            "127.0.0.1",
            8080,
            "",
            "",
            "");

        tx->state_ = ProxyTransaction::State::RECEIVING_BODY;
        tx->relay_mode_ = ProxyTransaction::RelayMode::BUFFERED;
        tx->response_headers_seen_ = true;
        tx->body_complete_ = false;
        tx->holding_retryable_5xx_response_ = true;
        tx->response_head_.status_code = HttpStatus::SERVICE_UNAVAILABLE;
        tx->response_head_.status_reason = "Service Unavailable";
        tx->response_head_.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH;
        tx->response_head_.expected_length = 0;
        tx->codec_.PauseParsing();

        bool resumed = tx->ResumeHeldRetryable5xxResponse("unit_test");

        bool pass = resumed &&
                    delivered &&
                    delivered_status == HttpStatus::SERVICE_UNAVAILABLE &&
                    delivered_body.empty() &&
                    tx->state_ == ProxyTransaction::State::COMPLETE;
        std::string err;
        if (!resumed) err += "resume returned false; ";
        if (!delivered) err += "complete callback not invoked; ";
        if (delivered_status != HttpStatus::SERVICE_UNAVAILABLE) {
            err += "status=" + std::to_string(delivered_status) + "; ";
        }
        if (!delivered_body.empty()) err += "body should be empty; ";
        if (tx->state_ != ProxyTransaction::State::COMPLETE) {
            err += "state not COMPLETE; ";
        }

        TestFramework::RecordTest(
            "ProxyTransaction internal: held 5xx resume completes bodyless response",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: held 5xx resume completes bodyless response",
            false, e.what());
    }
}

void TestCheckoutCapsAndCleanupClearsUpstreamTransportInputBuffer() {
    std::cout << "\n[TEST] ProxyTransaction internal: checkout caps upstream transport input buffer..."
              << std::endl;
    try {
        int fds[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            throw std::runtime_error("socketpair failed");
        }

        auto dispatcher = std::make_shared<Dispatcher>();
        auto transport = std::shared_ptr<ConnectionHandler>(new ConnectionHandler(
            dispatcher,
            std::unique_ptr<SocketHandler>(
                new SocketHandler(fds[0], "127.0.0.1", 8080))));
        auto upstream_conn =
            std::make_unique<UpstreamConnection>(transport, "127.0.0.1", 8080);

        HttpRequest request;
        request.method = "GET";
        request.url = "/relay-cap";
        request.path = "/relay-cap";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        ProxyConfig proxy_config;
        proxy_config.relay_buffer_limit_bytes = 32768;
        HeaderRewriter::Config rewriter_config;
        HeaderRewriter header_rewriter(rewriter_config);
        RetryPolicy::Config retry_config;
        RetryPolicy retry_policy(retry_config);

        auto tx = std::make_shared<ProxyTransaction>(
            "svc",
            request,
            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender(),
            [](HttpResponse) {},
            nullptr,
            proxy_config,
            header_rewriter,
            retry_policy,
            false,
            "127.0.0.1",
            8080,
            "",
            "",
            "");

        tx->state_ = ProxyTransaction::State::CHECKOUT_PENDING;
        UpstreamLease lease(upstream_conn.get(), nullptr, nullptr);
        tx->OnCheckoutReady(std::move(lease));

        bool pass = true;
        std::string err;
        if (transport->max_input_size_ != proxy_config.relay_buffer_limit_bytes) {
            pass = false;
            err += "transport cap not applied; ";
        }

        tx->Cleanup();
        if (transport->max_input_size_ != 0) {
            pass = false;
            err += "transport cap not cleared on cleanup; ";
        }
        tx->complete_cb_invoked_ = true;
        tx->complete_cb_ = nullptr;

        if (fds[1] >= 0) {
            ::close(fds[1]);
        }

        TestFramework::RecordTest(
            "ProxyTransaction internal: checkout caps upstream transport input buffer",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: checkout caps upstream transport input buffer",
            false, e.what());
    }
}

void RunAllTests() {
    TestHeldRetryable5xxResumeCompletesBodylessResponse();
    TestCheckoutCapsAndCleanupClearsUpstreamTransportInputBuffer();
}

}  // namespace ProxyTransactionInternalTests
