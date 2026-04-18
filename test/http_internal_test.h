#pragma once

#include "common.h"
#include "dispatcher.h"
#include "connection_handler.h"
#include "socket_handler.h"

#define private public
#include "http/http_callbacks.h"
#undef private

#include "http/http_connection_handler.h"
#include "http/http_status.h"
#include "test_framework.h"

#include <future>

namespace HttpInternalTests {

namespace {

std::thread StartDispatcher(const std::shared_ptr<Dispatcher>& dispatcher) {
    dispatcher->Init();

    std::promise<void> ready;
    auto ready_future = ready.get_future();

    std::thread loop([dispatcher, ready = std::move(ready)]() mutable {
        dispatcher->EnQueue([&ready]() { ready.set_value(); });
        dispatcher->RunEventLoop();
    });

    ready_future.wait_for(std::chrono::seconds(5));
    return loop;
}

}  // namespace

void TestH1StreamingRejectsInterimStatusInFinalApi() {
    std::cout << "\n[TEST] H1 streaming internal: SendHeaders rejects 1xx final status..."
              << std::endl;
    std::shared_ptr<Dispatcher> dispatcher;
    std::thread loop;
    int peer_fd = -1;
    try {
        int fds[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            throw std::runtime_error("socketpair failed");
        }
        peer_fd = fds[1];

        ::fcntl(fds[0], F_SETFL, O_NONBLOCK);
        ::fcntl(fds[1], F_SETFL, O_NONBLOCK);
        dispatcher = std::make_shared<Dispatcher>();
        loop = StartDispatcher(dispatcher);

        std::atomic<int> claim_calls{0};
        std::atomic<int> finalize_calls{0};

        auto transport = std::shared_ptr<ConnectionHandler>(new ConnectionHandler(
            dispatcher,
            std::unique_ptr<SocketHandler>(
                new SocketHandler(fds[0], "127.0.0.1", 8080))));
        auto handler = std::make_shared<HttpConnectionHandler>(transport);
        auto sender = handler->CreateStreamingResponseSender(
            [&claim_calls]() {
                claim_calls.fetch_add(1, std::memory_order_relaxed);
                return true;
            },
            [&finalize_calls]() {
                finalize_calls.fetch_add(1, std::memory_order_relaxed);
            });

        std::promise<std::string> result_promise;
        auto result_future = result_promise.get_future();

        dispatcher->EnQueue(
            [sender, &claim_calls, &finalize_calls,
             &result_promise]() mutable {
                std::string err;
                try {
                    HttpResponse invalid_final;
                    invalid_final.Status(HttpStatus::EARLY_HINTS)
                        .Header("Link", "</style.css>; rel=preload");
                    if (sender.SendHeaders(invalid_final) != -1) {
                        err += "1xx final SendHeaders should be rejected; ";
                    }

                    HttpResponse ok_final;
                    ok_final.Status(HttpStatus::OK)
                        .Header("Content-Type", "text/plain");
                    if (sender.SendHeaders(ok_final) != 0) {
                        err += "valid 200 SendHeaders failed after 1xx rejection; ";
                    }

                    auto end_result = sender.End();
                    if (end_result ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED) {
                        err += "End returned CLOSED after valid final response; ";
                    }

                    if (claim_calls.load(std::memory_order_acquire) != 1) {
                        err += "claim_response count mismatch; ";
                    }
                    if (finalize_calls.load(std::memory_order_acquire) != 1) {
                        err += "finalize_request count mismatch; ";
                    }
                } catch (const std::exception& e) {
                    err += e.what();
                    err += "; ";
                }
                result_promise.set_value(std::move(err));
            });

        bool pass = true;
        std::string err;
        if (result_future.wait_for(std::chrono::seconds(5)) !=
            std::future_status::ready) {
            pass = false;
            err += "timed out waiting for dispatcher result; ";
        } else {
            err = result_future.get();
            if (!err.empty()) {
                pass = false;
            }
        }

        dispatcher->StopEventLoop();
        if (loop.joinable()) {
            loop.join();
        }
        if (peer_fd >= 0) {
            ::close(peer_fd);
            peer_fd = -1;
        }

        TestFramework::RecordTest(
            "H1 streaming internal: SendHeaders rejects 1xx final status",
            pass, err);
    } catch (const std::exception& e) {
        if (dispatcher) {
            dispatcher->StopEventLoop();
        }
        if (loop.joinable()) {
            loop.join();
        }
        if (peer_fd >= 0) {
            ::close(peer_fd);
        }
        TestFramework::RecordTest(
            "H1 streaming internal: SendHeaders rejects 1xx final status",
            false, e.what());
    }
}

void RunAllTests() {
    TestH1StreamingRejectsInterimStatusInFinalApi();
}

}  // namespace HttpInternalTests
