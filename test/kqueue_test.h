#pragma once
#include "test_framework.h"
#include "test_server_runner.h"
#include "reactor_server.h"
#include "client.h"
#include "dispatcher.h"
#include "channel.h"
#include "socket_handler.h"
#include "inet_addr.h"

#include <thread>
#include <atomic>
#include <poll.h>
#include <sys/socket.h>

// macOS kqueue-specific tests (KQ-TEST-1 through KQ-TEST-7).
// These exercise kqueue behaviors that have no epoll equivalent.
// On Linux, the entire suite is skipped.
//
// Uses ephemeral ports (port 0) via TestServerRunner harness.
namespace KqueueTests {

#if defined(__APPLE__) || defined(__MACH__)

// Wait for the server to close a connection. Returns true if recv() == 0
// (clean EOF) within timeout_ms. Uses poll() + recv() — the deterministic
// TCP close detection pattern (no send-buffer races).
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

// ---------------------------------------------------------------------------
// KQ-TEST-1: EVFILT_TIMER Drives Idle Timeout Correctly
// ---------------------------------------------------------------------------
void TestTimerDrivesIdleTimeout() {
    std::cout << "\n[TEST] KQ-TEST-1: EVFILT_TIMER drives idle timeout..." << std::endl;
    try {
        // Short idle timeout (3s), scan interval 1s
        ReactorServer server("127.0.0.1", 0, 1, std::chrono::seconds(3));
        TestServerRunner<ReactorServer> runner(server);
        int port = runner.GetPort();

        // Connect, send data, receive echo
        Client client(port, "127.0.0.1", "hello");
        client.SetQuietMode(true);
        client.Init();
        client.Connect();
        client.Send();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        client.Receive();

        // Hold idle — wait for server-initiated close via poll+recv
        auto start = std::chrono::steady_clock::now();
        bool close_detected = WaitForServerClose(client.GetFd(), 6000);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        bool timing_ok = (elapsed.count() >= 2000 && elapsed.count() <= 5500);

        client.Close();

        bool pass = close_detected && timing_ok;
        std::string err;
        if (!close_detected) err += "server did not close idle connection; ";
        if (!timing_ok) err += "elapsed=" + std::to_string(elapsed.count()) + "ms (expected 2000-5500); ";

        TestFramework::RecordTest("KQ: EVFILT_TIMER drives idle timeout",
            pass, err, TestFramework::TestCategory::BASIC);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("KQ: EVFILT_TIMER drives idle timeout",
            false, e.what(), TestFramework::TestCategory::BASIC);
    }
}

// ---------------------------------------------------------------------------
// KQ-TEST-2: EV_EOF on Write Filter (Low-Level Socket Test)
// ---------------------------------------------------------------------------
void TestEvEofOnWriteFilter() {
    std::cout << "\n[TEST] KQ-TEST-2: EV_EOF on write filter..." << std::endl;
    int fds[2] = {-1, -1};
    try {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            throw std::runtime_error("socketpair failed");
        }
        // Set non-blocking
        fcntl(fds[0], F_SETFL, O_NONBLOCK);
        fcntl(fds[1], F_SETFL, O_NONBLOCK);

        auto dispatcher = std::make_shared<Dispatcher>();
        dispatcher->Init();

        auto channel = std::make_shared<Channel>(dispatcher, fds[0]);
        std::atomic<bool> close_fired{false};
        std::atomic<bool> write_fired{false};

        channel->SetWriteCallBackFn([&write_fired]() {
            write_fired.store(true);
        });
        channel->SetCloseCallBackFn([&close_fired]() {
            close_fired.store(true);
        });
        // Enable ONLY write mode — no read mode
        channel->EnableWriteMode();

        // Close the peer end — should trigger EV_EOF on EVFILT_WRITE
        ::close(fds[1]);
        fds[1] = -1;  // Mark closed for exception-path cleanup

        // Run event loop briefly in a thread
        std::thread loop_thread([&dispatcher]() {
            dispatcher->RunEventLoop();
        });

        // Wait up to 2 seconds for the close to be detected
        for (int i = 0; i < 40 && !close_fired.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        dispatcher->StopEventLoop();
        if (loop_thread.joinable()) loop_thread.join();

        // Clean up the channel before closing fd
        if (!channel->is_channel_closed()) {
            channel->CloseChannel();
        }

        bool pass = close_fired.load();
        TestFramework::RecordTest("KQ: EV_EOF detected on write filter",
            pass, pass ? "" : "close callback not fired within 2s",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        // Clean up fds that may not have been closed in the happy path.
        // fds[0] is owned by Channel after construction; fds[1] is closed
        // at line 113 in the happy path but may still be open on early throw.
        if (fds[1] >= 0) ::close(fds[1]);
        TestFramework::RecordTest("KQ: EV_EOF detected on write filter",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// KQ-TEST-3: Pipe Wakeup Under Load
// ---------------------------------------------------------------------------
void TestPipeWakeupUnderLoad() {
    std::cout << "\n[TEST] KQ-TEST-3: Pipe wakeup under load..." << std::endl;
    try {
        auto dispatcher = std::make_shared<Dispatcher>();
        dispatcher->Init();

        static constexpr int NUM_THREADS = 10;
        static constexpr int TASKS_PER_THREAD = 100;
        std::atomic<int> task_count{0};

        std::thread loop_thread([&dispatcher]() {
            dispatcher->RunEventLoop();
        });

        // Give event loop time to start
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Enqueue tasks from multiple threads concurrently
        std::vector<std::thread> threads;
        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&dispatcher, &task_count]() {
                for (int i = 0; i < TASKS_PER_THREAD; ++i) {
                    dispatcher->EnQueue([&task_count]() {
                        task_count.fetch_add(1, std::memory_order_relaxed);
                    });
                }
            });
        }

        for (auto& t : threads) t.join();

        // Wait for all tasks to drain
        for (int i = 0; i < 40 && task_count.load() < NUM_THREADS * TASKS_PER_THREAD; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        dispatcher->StopEventLoop();
        if (loop_thread.joinable()) loop_thread.join();

        int executed = task_count.load();
        bool pass = (executed == NUM_THREADS * TASKS_PER_THREAD);
        std::string err = pass ? "" :
            "executed " + std::to_string(executed) + "/" +
            std::to_string(NUM_THREADS * TASKS_PER_THREAD);

        TestFramework::RecordTest("KQ: Pipe wakeup under concurrent load",
            pass, err, TestFramework::TestCategory::STRESS);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("KQ: Pipe wakeup under concurrent load",
            false, e.what(), TestFramework::TestCategory::STRESS);
    }
}

// ---------------------------------------------------------------------------
// KQ-TEST-4: Filter Consolidation Correctness (Low-Level Socket Test)
// ---------------------------------------------------------------------------
void TestFilterConsolidation() {
    std::cout << "\n[TEST] KQ-TEST-4: Filter consolidation..." << std::endl;
    int fds[2] = {-1, -1};
    std::shared_ptr<Channel> channel;
    try {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            throw std::runtime_error("socketpair failed");
        }
        fcntl(fds[0], F_SETFL, O_NONBLOCK);
        fcntl(fds[1], F_SETFL, O_NONBLOCK);

        auto dispatcher = std::make_shared<Dispatcher>();
        dispatcher->Init();

        channel = std::make_shared<Channel>(dispatcher, fds[0]);
        std::string event_log;
        std::mutex log_mutex;

        channel->SetReadCallBackFn([&event_log, &log_mutex]() {
            std::lock_guard<std::mutex> lk(log_mutex);
            event_log += "R";
        });
        channel->SetWriteCallBackFn([&event_log, &log_mutex]() {
            std::lock_guard<std::mutex> lk(log_mutex);
            event_log += "W";
        });

        // Write data to fd[1] to make fd[0] readable
        const char* msg = "test";
        ::write(fds[1], msg, 4);

        // Enable both read and write — fd[0] is both readable (data pending)
        // and writable (empty send buffer)
        channel->EnableReadMode();
        channel->EnableWriteMode();

        std::thread loop_thread([&dispatcher]() {
            dispatcher->RunEventLoop();
        });

        // Wait for both events to fire
        for (int i = 0; i < 20; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            std::lock_guard<std::mutex> lk(log_mutex);
            if (event_log.find('R') != std::string::npos &&
                event_log.find('W') != std::string::npos) {
                break;
            }
        }

        dispatcher->StopEventLoop();
        if (loop_thread.joinable()) loop_thread.join();

        // Clean up
        if (!channel->is_channel_closed()) {
            channel->CloseChannel();
        }
        ::close(fds[1]);

        std::lock_guard<std::mutex> lk(log_mutex);
        bool has_both = event_log.find('R') != std::string::npos &&
                        event_log.find('W') != std::string::npos;
        // Tests Channel::HandleEvent ordering (channel.cc:86-99): read before write.
        // kqueue may return filters in any order, but consolidation merges them
        // into one Channel, and HandleEvent enforces read-before-write dispatch.
        bool correct_order = !event_log.empty() && event_log[0] == 'R';

        bool pass = has_both && correct_order;
        std::string err;
        if (!has_both) err += "event_log='" + event_log + "' missing R or W; ";
        if (!correct_order) err += "read should come before write, got '" + event_log + "'; ";

        TestFramework::RecordTest("KQ: Filter consolidation R+W",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        // Channel owns fds[0] after construction — only close if not yet created
        if (!channel && fds[0] >= 0) ::close(fds[0]);
        if (fds[1] >= 0) ::close(fds[1]);
        TestFramework::RecordTest("KQ: Filter consolidation R+W",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// KQ-TEST-5: Rapid Connect/Disconnect Churn Stability
// ---------------------------------------------------------------------------
void TestChurnStability() {
    std::cout << "\n[TEST] KQ-TEST-5: Churn stability..." << std::endl;
    try {
        ReactorServer server("127.0.0.1", 0);
        TestServerRunner<ReactorServer> runner(server);
        int port = runner.GetPort();

        // Rapidly connect and disconnect 100 clients
        int connect_count = 0;
        for (int i = 0; i < 100; ++i) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                ++connect_count;
                ::write(sock, "X", 1);
            }
            ::close(sock);
        }

        // Wait for cleanup
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Verify server is healthy: 5 sequential full requests
        int success_count = 0;
        for (int i = 0; i < 5; ++i) {
            try {
                Client client(port, "127.0.0.1", "PostChurn");
                client.SetQuietMode(true);
                client.Init();
                client.SetReceiveTimeout(3);
                client.Connect();
                client.Send();
                client.Receive();
                client.Close();
                ++success_count;
            } catch (...) {}
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        bool pass = (success_count == 5);
        std::string err = pass ? "" :
            "only " + std::to_string(success_count) + "/5 post-churn requests succeeded"
            " (" + std::to_string(connect_count) + "/100 churn connects succeeded)";

        TestFramework::RecordTest("KQ: Churn stability after rapid connects",
            pass, err, TestFramework::TestCategory::STRESS);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("KQ: Churn stability after rapid connects",
            false, e.what(), TestFramework::TestCategory::STRESS);
    }
}

// ---------------------------------------------------------------------------
// KQ-TEST-6: Timer Re-arm Keeps Scanning After First Timeout
// ---------------------------------------------------------------------------
void TestTimerRearm() {
    std::cout << "\n[TEST] KQ-TEST-6: Timer re-arm..." << std::endl;
    try {
        // idle timeout = 3s, scan interval = 1s
        ReactorServer server("127.0.0.1", 0, 1, std::chrono::seconds(3));
        TestServerRunner<ReactorServer> runner(server);
        int port = runner.GetPort();

        // Connect client A at t=0
        Client client_a(port, "127.0.0.1", "ClientA");
        client_a.SetQuietMode(true);
        client_a.Init();
        client_a.Connect();
        client_a.Send();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        client_a.Receive();

        // Wait 1.5s, connect client B
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        Client client_b(port, "127.0.0.1", "ClientB");
        client_b.SetQuietMode(true);
        client_b.Init();
        client_b.Connect();
        client_b.Send();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        client_b.Receive();

        // Wait for both clients to timeout via poll+recv EOF
        bool a_closed = WaitForServerClose(client_a.GetFd(), 6000);
        bool b_closed = WaitForServerClose(client_b.GetFd(), 6000);

        // Verify server is still alive
        bool server_alive = false;
        try {
            Client client_c(port, "127.0.0.1", "ClientC");
            client_c.SetQuietMode(true);
            client_c.Init();
            client_c.SetReceiveTimeout(3);
            client_c.Connect();
            client_c.Send();
            client_c.Receive();
            client_c.Close();
            server_alive = true;
        } catch (...) {}

        client_a.Close();
        client_b.Close();

        bool pass = a_closed && b_closed && server_alive;
        std::string err;
        if (!a_closed) err += "client A not closed by timeout; ";
        if (!b_closed) err += "client B not closed (timer did not re-arm); ";
        if (!server_alive) err += "server not accepting after timeouts; ";

        TestFramework::RecordTest("KQ: Timer re-arm after first timeout",
            pass, err, TestFramework::TestCategory::BASIC);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("KQ: Timer re-arm after first timeout",
            false, e.what(), TestFramework::TestCategory::BASIC);
    }
}

// ---------------------------------------------------------------------------
// KQ-TEST-7: SO_NOSIGPIPE Set on Accepted Sockets
// ---------------------------------------------------------------------------
void TestSoNosigpipe() {
    std::cout << "\n[TEST] KQ-TEST-7: SO_NOSIGPIPE on accepted sockets..." << std::endl;
    try {
        // Create listening socket via SocketHandler (already non-blocking
        // from CreateSocket() → SetNonBlocking())
        SocketHandler listener;
        InetAddr addr("127.0.0.1", 0);
        listener.SetReuseAddr(true);
        listener.Bind(addr);
        listener.Listen(5);
        int port = listener.GetBoundPort();

        // Phase 1: Verify getsockopt on listener
        int optval = 0;
        socklen_t optlen = sizeof(optval);
        getsockopt(listener.fd(), SOL_SOCKET, SO_NOSIGPIPE, &optval, &optlen);
        bool listener_has_opt = (optval != 0);

        // Connect a client
        int client_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        connect(client_fd, (struct sockaddr*)&sa, sizeof(sa));

        // Wait for listen socket to become readable (incoming connection)
        struct pollfd pfd;
        pfd.fd = listener.fd();
        pfd.events = POLLIN;
        poll(&pfd, 1, 2000);

        // Accept — this calls SetNonBlocking() which sets SO_NOSIGPIPE
        InetAddr client_addr;
        int accepted_fd = listener.Accept(client_addr);
        bool accept_ok = (accepted_fd >= 0);

        // Phase 2: Verify getsockopt on accepted fd
        bool accepted_has_opt = false;
        if (accept_ok) {
            optval = 0;
            getsockopt(accepted_fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, &optlen);
            accepted_has_opt = (optval != 0);
        }

        // Phase 3: Forked child — write to closed peer, verify no SIGPIPE
        bool write_test_pass = false;
        if (accept_ok) {
            pid_t pid = fork();
            if (pid == 0) {
                // Child process
                // Restore SIGPIPE to default — if SO_NOSIGPIPE is broken, we die
                signal(SIGPIPE, SIG_DFL);
                // Close client end (peer) — makes accepted_fd's peer gone
                ::close(client_fd);
                // Small delay to ensure close propagates
                usleep(50000);
                // Write to the now-dead peer
                char buf[] = "test";
                ssize_t n = ::write(accepted_fd, buf, sizeof(buf));
                // If we get here, SO_NOSIGPIPE worked (we got EPIPE, not killed)
                (void)n;
                ::close(accepted_fd);
                _exit(0);
            } else if (pid > 0) {
                // Parent: wait for child
                int status = 0;
                waitpid(pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    write_test_pass = true;
                }
                // Parent cleans up its copies of fds
            } else {
                // fork failed
            }
        }

        // Both parent and child close their copies of client_fd and accepted_fd.
        // After fork(), each process has independent fd table entries — closing
        // in both is correct and required. (Would be a double-close bug with threads.)
        ::close(client_fd);
        if (accept_ok) ::close(accepted_fd);

        bool pass = listener_has_opt && accept_ok && accepted_has_opt && write_test_pass;
        std::string err;
        if (!listener_has_opt) err += "listener missing SO_NOSIGPIPE; ";
        if (!accept_ok) err += "accept failed; ";
        if (!accepted_has_opt) err += "accepted fd missing SO_NOSIGPIPE; ";
        if (!write_test_pass) err += "forked write test failed (SIGPIPE?); ";

        TestFramework::RecordTest("KQ: SO_NOSIGPIPE on accepted sockets",
            pass, err, TestFramework::TestCategory::BASIC);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("KQ: SO_NOSIGPIPE on accepted sockets",
            false, e.what(), TestFramework::TestCategory::BASIC);
    }
}

#endif // __APPLE__

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------
void RunAllTests() {
#if defined(__APPLE__) || defined(__MACH__)
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "KQUEUE PLATFORM TESTS (macOS)" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestTimerDrivesIdleTimeout();
    TestEvEofOnWriteFilter();
    TestPipeWakeupUnderLoad();
    TestFilterConsolidation();
    TestChurnStability();
    TestTimerRearm();
    TestSoNosigpipe();
#else
    std::cout << "\n[SKIP] Kqueue tests only run on macOS" << std::endl;
#endif
}

} // namespace KqueueTests
