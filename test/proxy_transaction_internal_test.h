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

std::shared_ptr<ProxyTransaction> MakeInternalProxyTransaction(
    const HttpRequest& request,
    HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete_cb =
        [](HttpResponse) {},
    HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender stream_sender =
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender()) {
    ProxyConfig proxy_config;
    HeaderRewriter::Config rewriter_config;
    HeaderRewriter header_rewriter(rewriter_config);
    RetryPolicy::Config retry_config;
    RetryPolicy retry_policy(retry_config);

    return std::make_shared<ProxyTransaction>(
        "svc",
        request,
        std::move(stream_sender),
        std::move(complete_cb),
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
}

class AbortTrackingStreamSenderImpl final
    : public HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::Impl {
public:
    using SendResult =
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult;
    using AbortReason =
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason;
    using DrainListener =
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::DrainListener;

    explicit AbortTrackingStreamSenderImpl(int send_headers_result)
        : send_headers_result_(send_headers_result) {}

    int SendHeaders(const HttpResponse&) override {
        ++send_headers_calls_;
        return send_headers_result_;
    }

    SendResult SendData(const char*, size_t) override {
        return SendResult::ACCEPTED_BELOW_WATER;
    }

    SendResult End(
        const std::vector<std::pair<std::string, std::string>>&) override {
        return SendResult::ACCEPTED_BELOW_WATER;
    }

    void Abort(AbortReason reason) override {
        ++abort_calls_;
        last_abort_reason_ = reason;
    }

    void SetDrainListener(DrainListener) override {}
    void ConfigureWatermarks(size_t) override {}
    Dispatcher* GetDispatcher() override { return nullptr; }

    int send_headers_calls_ = 0;
    int abort_calls_ = 0;
    AbortReason last_abort_reason_ = AbortReason::UPSTREAM_ERROR;

private:
    int send_headers_result_ = -1;
};

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

        bool delivered = false;
        int delivered_status = 0;
        std::string delivered_body;
        auto tx = MakeInternalProxyTransaction(
            request,
            [&delivered, &delivered_status, &delivered_body](HttpResponse response) {
                delivered = true;
                delivered_status = response.GetStatusCode();
                delivered_body = response.GetBody();
            });

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

void TestHeldRetryable5xxResumeCompletesNoBodyHeadResponse() {
    std::cout << "\n[TEST] ProxyTransaction internal: held HEAD 5xx resume completes no-body response..."
              << std::endl;
    try {
        HttpRequest request;
        request.method = "HEAD";
        request.url = "/held-head-5xx";
        request.path = "/held-head-5xx";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        bool delivered = false;
        int delivered_status = 0;
        std::string delivered_body;
        auto tx = MakeInternalProxyTransaction(
            request,
            [&delivered, &delivered_status, &delivered_body](HttpResponse response) {
                delivered = true;
                delivered_status = response.GetStatusCode();
                delivered_body = response.GetBody();
            });

        tx->state_ = ProxyTransaction::State::RECEIVING_BODY;
        tx->relay_mode_ = ProxyTransaction::RelayMode::BUFFERED;
        tx->response_headers_seen_ = true;
        tx->body_complete_ = false;
        tx->holding_retryable_5xx_response_ = true;
        tx->response_head_.status_code = HttpStatus::SERVICE_UNAVAILABLE;
        tx->response_head_.status_reason = "Service Unavailable";
        tx->response_head_.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::NO_BODY;
        tx->codec_.PauseParsing();

        bool resumed = tx->ResumeHeldRetryable5xxResponse("unit_test_head");

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
        if (!delivered_body.empty()) err += "HEAD response body should be empty; ";
        if (tx->state_ != ProxyTransaction::State::COMPLETE) {
            err += "state not COMPLETE; ";
        }

        TestFramework::RecordTest(
            "ProxyTransaction internal: held HEAD 5xx resume completes no-body response",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: held HEAD 5xx resume completes no-body response",
            false, e.what());
    }
}

void TestEarlyResponseHeadersExitSendPhase() {
    std::cout << "\n[TEST] ProxyTransaction internal: early upstream headers exit send phase..."
              << std::endl;
    try {
        HttpRequest request;
        request.method = "POST";
        request.url = "/early-response";
        request.path = "/early-response";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        auto tx = MakeInternalProxyTransaction(request);
        tx->state_ = ProxyTransaction::State::SENDING_REQUEST;

        UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead head;
        head.status_code = HttpStatus::OK;
        head.status_reason = "OK";
        head.keep_alive = true;
        head.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH;
        head.expected_length = 5;
        head.headers.push_back({"content-length", "5"});

        bool accepted = tx->OnHeaders(head);
        tx->OnUpstreamWriteComplete(nullptr);

        bool pass = accepted &&
                    tx->state_ == ProxyTransaction::State::AWAITING_RESPONSE &&
                    tx->poison_connection_ &&
                    tx->response_headers_seen_;
        std::string err;
        if (!accepted) err += "headers rejected; ";
        if (tx->state_ != ProxyTransaction::State::AWAITING_RESPONSE) {
            err += "state should leave SENDING_REQUEST; ";
        }
        if (!tx->poison_connection_) {
            err += "connection should be poisoned for early response; ";
        }
        if (!tx->response_headers_seen_) {
            err += "response_headers_seen not set; ";
        }

        // This test intentionally stops after validating the send->response
        // state transition; suppress the destructor's undelivered-response
        // warning for that incomplete synthetic transaction.
        tx->complete_cb_invoked_ = true;
        tx->complete_cb_ = nullptr;

        TestFramework::RecordTest(
            "ProxyTransaction internal: early upstream headers exit send phase",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: early upstream headers exit send phase",
            false, e.what());
    }
}

void TestBufferedOverflowPoisonsConnection() {
    std::cout << "\n[TEST] ProxyTransaction internal: buffered overflow poisons connection..."
              << std::endl;
    try {
        HttpRequest request;
        request.method = "GET";
        request.url = "/overflow";
        request.path = "/overflow";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        bool delivered = false;
        int delivered_status = 0;
        auto tx = MakeInternalProxyTransaction(
            request,
            [&delivered, &delivered_status](HttpResponse response) {
                delivered = true;
                delivered_status = response.GetStatusCode();
            });

        tx->state_ = ProxyTransaction::State::RECEIVING_BODY;
        tx->relay_mode_ = ProxyTransaction::RelayMode::BUFFERED;
        tx->response_headers_seen_ = true;
        tx->response_head_.status_code = HttpStatus::OK;
        tx->response_head_.status_reason = "OK";
        tx->response_body_.resize(UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE);

        bool accepted = tx->OnBodyChunk("x", 1);

        bool pass = !accepted &&
                    delivered &&
                    delivered_status == HttpStatus::BAD_GATEWAY &&
                    tx->poison_connection_ &&
                    tx->state_ == ProxyTransaction::State::FAILED;
        std::string err;
        if (accepted) err += "overflow chunk should be rejected; ";
        if (!delivered) err += "error response not delivered; ";
        if (delivered_status != HttpStatus::BAD_GATEWAY) {
            err += "status=" + std::to_string(delivered_status) + "; ";
        }
        if (!tx->poison_connection_) {
            err += "overflow should poison connection; ";
        }
        if (tx->state_ != ProxyTransaction::State::FAILED) {
            err += "state should be FAILED; ";
        }

        TestFramework::RecordTest(
            "ProxyTransaction internal: buffered overflow poisons connection",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: buffered overflow poisons connection",
            false, e.what());
    }
}

void TestCheckoutCapsAndCleanupRestoresIdleUpstreamTransportInputCap() {
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
        if (transport->max_input_size_ != MAX_BUFFER_SIZE) {
            pass = false;
            err += "idle transport cap not restored on cleanup; ";
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

void TestRetryable5xxRetryReleasesLeaseBeforeBackoff() {
    std::cout << "\n[TEST] ProxyTransaction internal: retryable 5xx releases lease before backoff..."
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
        request.url = "/retry-5xx-release";
        request.path = "/retry-5xx-release";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        ProxyConfig proxy_config;
        HeaderRewriter::Config rewriter_config;
        HeaderRewriter header_rewriter(rewriter_config);
        RetryPolicy::Config retry_config;
        retry_config.max_retries = 1;
        retry_config.retry_on_5xx = true;
        retry_config.retry_on_connect_failure = false;
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

        tx->dispatcher_ = dispatcher.get();
        tx->state_ = ProxyTransaction::State::RECEIVING_BODY;
        tx->lease_ = UpstreamLease(upstream_conn.get(), nullptr, nullptr);
        tx->poison_connection_ = true;
        tx->response_headers_seen_ = true;
        tx->response_head_.status_code = HttpStatus::SERVICE_UNAVAILABLE;
        tx->response_head_.status_reason = "Service Unavailable";
        tx->response_head_.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH;
        tx->response_head_.expected_length = 11;
        tx->response_body_ = "backend-503";

        tx->MaybeRetry(RetryPolicy::RetryCondition::RESPONSE_5XX);

        bool pass = !tx->lease_ &&
                    tx->attempt_ == 1 &&
                    tx->pending_retryable_5xx_response_ &&
                    tx->pending_retryable_5xx_body_ == "backend-503" &&
                    !tx->holding_retryable_5xx_response_ &&
                    upstream_conn->IsClosing();
        std::string err;
        if (tx->lease_) err += "lease should be released during backoff; ";
        if (tx->attempt_ != 1) err += "attempt not incremented; ";
        if (!tx->pending_retryable_5xx_response_) err += "stored 5xx missing; ";
        if (tx->pending_retryable_5xx_body_ != "backend-503") {
            err += "stored body mismatch; ";
        }
        if (tx->holding_retryable_5xx_response_) {
            err += "transport should not remain held across backoff; ";
        }
        if (!upstream_conn->IsClosing()) {
            err += "failed upstream connection should be poisoned; ";
        }

        tx->complete_cb_invoked_ = true;
        tx->complete_cb_ = nullptr;
        if (fds[1] >= 0) {
            ::close(fds[1]);
        }

        TestFramework::RecordTest(
            "ProxyTransaction internal: retryable 5xx releases lease before backoff",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: retryable 5xx releases lease before backoff",
            false, e.what());
    }
}

void TestCheckoutLocalFailureRelaysStoredRetryable5xx() {
    std::cout << "\n[TEST] ProxyTransaction internal: checkout local failure relays stored retryable 5xx..."
              << std::endl;
    try {
        HttpRequest request;
        request.method = "GET";
        request.url = "/checkout-fallback";
        request.path = "/checkout-fallback";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        bool delivered = false;
        int delivered_status = 0;
        std::string delivered_body;
        bool saw_upstream_header = false;
        auto tx = MakeInternalProxyTransaction(
            request,
            [&delivered, &delivered_status, &delivered_body, &saw_upstream_header](
                HttpResponse response) {
                delivered = true;
                delivered_status = response.GetStatusCode();
                delivered_body = response.GetBody();
                for (const auto& [key, value] : response.GetHeaders()) {
                    if (key == "X-Upstream-Source" && value == "backend") {
                        saw_upstream_header = true;
                        break;
                    }
                }
            });

        tx->state_ = ProxyTransaction::State::CHECKOUT_PENDING;
        tx->attempt_ = 1;
        tx->pending_retryable_5xx_response_ = true;
        tx->pending_retryable_5xx_head_.status_code = HttpStatus::SERVICE_UNAVAILABLE;
        tx->pending_retryable_5xx_head_.status_reason = "Service Unavailable";
        tx->pending_retryable_5xx_head_.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH;
        tx->pending_retryable_5xx_head_.expected_length = 11;
        tx->pending_retryable_5xx_head_.headers.push_back(
            {"X-Upstream-Source", "backend"});
        tx->pending_retryable_5xx_body_ = "backend-503";

        tx->OnCheckoutError(-1);

        bool pass = delivered &&
                    delivered_status == HttpStatus::SERVICE_UNAVAILABLE &&
                    delivered_body == "backend-503" &&
                    saw_upstream_header &&
                    tx->state_ == ProxyTransaction::State::COMPLETE;
        std::string err;
        if (!delivered) err += "stored response not delivered; ";
        if (delivered_status != HttpStatus::SERVICE_UNAVAILABLE) {
            err += "status=" + std::to_string(delivered_status) + "; ";
        }
        if (delivered_body != "backend-503") err += "stored body not relayed; ";
        if (!saw_upstream_header) err += "stored upstream headers missing; ";
        if (tx->state_ != ProxyTransaction::State::COMPLETE) {
            err += "state should be COMPLETE; ";
        }

        TestFramework::RecordTest(
            "ProxyTransaction internal: checkout local failure relays stored retryable 5xx",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: checkout local failure relays stored retryable 5xx",
            false, e.what());
    }
}

void TestStreamingCommitFailureAbortsSenderOnHeaders() {
    std::cout << "\n[TEST] ProxyTransaction internal: streaming header commit failure aborts sender..."
              << std::endl;
    try {
        HttpRequest request;
        request.method = "GET";
        request.url = "/stream-fail";
        request.path = "/stream-fail";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        auto impl = std::make_shared<AbortTrackingStreamSenderImpl>(-1);
        auto tx = MakeInternalProxyTransaction(
            request,
            [](HttpResponse) {},
            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender(impl));

        tx->state_ = ProxyTransaction::State::AWAITING_RESPONSE;
        tx->config_.buffering = "never";

        UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead head;
        head.status_code = HttpStatus::OK;
        head.status_reason = "OK";
        head.keep_alive = true;
        head.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH;
        head.expected_length = 2;
        head.headers.push_back({"content-length", "2"});

        bool accepted = tx->OnHeaders(head);

        bool pass = !accepted &&
                    impl->send_headers_calls_ == 1 &&
                    impl->abort_calls_ == 1 &&
                    impl->last_abort_reason_ ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                            AbortReason::UPSTREAM_ERROR &&
                    tx->state_ == ProxyTransaction::State::FAILED;
        std::string err;
        if (accepted) err += "headers should be rejected; ";
        if (impl->send_headers_calls_ != 1) err += "SendHeaders not called exactly once; ";
        if (impl->abort_calls_ != 1) err += "Abort not called exactly once; ";
        if (tx->state_ != ProxyTransaction::State::FAILED) err += "state should be FAILED; ";

        TestFramework::RecordTest(
            "ProxyTransaction internal: streaming header commit failure aborts sender",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: streaming header commit failure aborts sender",
            false, e.what());
    }
}

void TestHeldRetryable5xxCommitFailureAbortsSender() {
    std::cout << "\n[TEST] ProxyTransaction internal: held 5xx commit failure aborts sender..."
              << std::endl;
    try {
        HttpRequest request;
        request.method = "GET";
        request.url = "/held-stream-fail";
        request.path = "/held-stream-fail";
        request.headers["host"] = "example.test";
        request.client_fd = 42;

        auto impl = std::make_shared<AbortTrackingStreamSenderImpl>(-1);
        auto tx = MakeInternalProxyTransaction(
            request,
            [](HttpResponse) {},
            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender(impl));

        tx->state_ = ProxyTransaction::State::RECEIVING_BODY;
        tx->relay_mode_ = ProxyTransaction::RelayMode::STREAMING;
        tx->response_headers_seen_ = true;
        tx->holding_retryable_5xx_response_ = true;
        tx->response_head_.status_code = HttpStatus::BAD_GATEWAY;
        tx->response_head_.status_reason = "Bad Gateway";
        tx->response_head_.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH;
        tx->response_head_.expected_length = 3;
        tx->response_head_.headers.push_back({"content-length", "3"});

        bool resumed = tx->ResumeHeldRetryable5xxResponse("unit_test_stream_fail");

        bool pass = resumed &&
                    impl->send_headers_calls_ == 1 &&
                    impl->abort_calls_ == 1 &&
                    impl->last_abort_reason_ ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                            AbortReason::UPSTREAM_ERROR &&
                    tx->state_ == ProxyTransaction::State::FAILED;
        std::string err;
        if (!resumed) err += "resume should return true; ";
        if (impl->send_headers_calls_ != 1) err += "SendHeaders not called exactly once; ";
        if (impl->abort_calls_ != 1) err += "Abort not called exactly once; ";
        if (tx->state_ != ProxyTransaction::State::FAILED) err += "state should be FAILED; ";

        TestFramework::RecordTest(
            "ProxyTransaction internal: held 5xx commit failure aborts sender",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyTransaction internal: held 5xx commit failure aborts sender",
            false, e.what());
    }
}

void RunAllTests() {
    TestHeldRetryable5xxResumeCompletesBodylessResponse();
    TestHeldRetryable5xxResumeCompletesNoBodyHeadResponse();
    TestEarlyResponseHeadersExitSendPhase();
    TestBufferedOverflowPoisonsConnection();
    TestCheckoutCapsAndCleanupRestoresIdleUpstreamTransportInputCap();
    TestRetryable5xxRetryReleasesLeaseBeforeBackoff();
    TestCheckoutLocalFailureRelaysStoredRetryable5xx();
    TestStreamingCommitFailureAbortsSenderOnHeaders();
    TestHeldRetryable5xxCommitFailureAbortsSender();
}

}  // namespace ProxyTransactionInternalTests
