#pragma once

#include "common.h"
#include "connection_handler.h"
#include "socket_handler.h"

#define private public
#include "http2/http2_connection_handler.h"
#undef private

#include "test_framework.h"

namespace Http2InternalTests {

void TestStreamClosePrunesActiveSenderEntry() {
    std::cout << "\n[TEST] Http2ConnectionHandler internal: stream close prunes sender entry..."
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
        Http2Session::Settings settings;
        auto handler =
            std::make_shared<Http2ConnectionHandler>(transport, settings);

        bool close_cb_invoked = false;
        handler->SetStreamCloseCallback(
            [&close_cb_invoked](std::shared_ptr<Http2ConnectionHandler>,
                                int32_t /*stream_id*/,
                                uint32_t /*error_code*/) {
                close_cb_invoked = true;
            });

        auto sender = handler->CreateStreamingResponseSender(
            1,
            []() { return true; },
            []() {},
            []() {});

        bool pass = true;
        std::string err;
        if (!sender) {
            pass = false;
            err += "sender not created; ";
        }
        if (!handler->pending_stream_close_cb_) {
            pass = false;
            err += "wrapped close callback missing; ";
        }
        if (handler->active_stream_sender_impls_.count(1) != 1) {
            pass = false;
            err += "sender entry not registered; ";
        }

        if (handler->pending_stream_close_cb_) {
            handler->pending_stream_close_cb_(handler, 1, 0);
        }

        if (handler->active_stream_sender_impls_.count(1) != 0) {
            pass = false;
            err += "sender entry not pruned on close; ";
        }
        if (!close_cb_invoked) {
            pass = false;
            err += "original close callback not invoked; ";
        }

        if (fds[1] >= 0) {
            ::close(fds[1]);
        }

        TestFramework::RecordTest(
            "Http2ConnectionHandler internal: stream close prunes sender entry",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Http2ConnectionHandler internal: stream close prunes sender entry",
            false, e.what());
    }
}

void RunAllTests() {
    TestStreamClosePrunesActiveSenderEntry();
}

}  // namespace Http2InternalTests
