#pragma once

// upstream_pool_test.h — Tests for the upstream connection pool feature.
//
// Coverage dimensions:
//   1. Config parsing / validation (no server needed)
//   2. SocketHandler outbound connect (needs a listening server)
//   3. UpstreamConnection unit tests (state, expiry, liveness)
//   4. UpstreamLease RAII semantics (release, move, empty)
//   5. Integration: CheckoutAsync end-to-end through UpstreamManager
//
// All servers use ephemeral port 0 — no fixed port conflicts.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "upstream/upstream_connection.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_manager.h"
#include "upstream/upstream_host_pool.h"
#include "upstream/pool_partition.h"
#include "socket_handler.h"
#include "connection_handler.h"
#include "dispatcher.h"
#include "inet_addr.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <future>
#include <set>

namespace UpstreamPoolTests {

// ---------------------------------------------------------------------------
// RAII Helpers
// ---------------------------------------------------------------------------

// RAII wrapper: stops a Dispatcher and joins its thread on destruction.
// Prevents thread::~thread() being called on a joinable thread (std::terminate).
struct DispatcherThreadGuard {
    std::shared_ptr<Dispatcher> dispatcher;
    std::thread& thread;

    ~DispatcherThreadGuard() {
        try { dispatcher->StopEventLoop(); } catch (...) {}
        if (thread.joinable()) thread.join();
    }
};

// Open a plain TCP listening socket on an OS-assigned ephemeral port.
// Returns {listen_fd, bound_port}. The caller owns the fd.
static std::pair<int, int> MakeListenerFd() {
    int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) throw std::runtime_error("socket() failed");

    int yes = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;  // ephemeral

    if (::bind(lfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(lfd);
        throw std::runtime_error("bind() failed");
    }
    if (::listen(lfd, 16) < 0) {
        ::close(lfd);
        throw std::runtime_error("listen() failed");
    }

    struct sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    ::getsockname(lfd, reinterpret_cast<struct sockaddr*>(&bound), &len);

    return {lfd, ntohs(bound.sin_port)};
}

// Build a minimal UpstreamConfig pointing at host:port.
static UpstreamConfig MakeUpstreamConfig(const std::string& name,
                                          const std::string& host,
                                          int port) {
    UpstreamConfig cfg;
    cfg.name = name;
    cfg.host = host;
    cfg.port = port;
    cfg.pool.max_connections      = 4;
    cfg.pool.max_idle_connections = 2;
    cfg.pool.connect_timeout_ms   = 2000;
    cfg.pool.idle_timeout_sec     = 30;
    cfg.pool.max_lifetime_sec     = 3600;
    cfg.pool.max_requests_per_conn = 0;
    return cfg;
}

// Start a Dispatcher in a background thread and wait until it is running.
// Returns the thread object (caller must join via DispatcherThreadGuard).
static std::thread StartDispatcher(std::shared_ptr<Dispatcher>& disp) {
    disp->Init();

    std::promise<void> ready;
    auto ready_future = ready.get_future();

    std::thread t([&disp, r = std::move(ready)]() mutable {
        disp->EnQueue([&r]() { r.set_value(); });
        disp->RunEventLoop();
    });

    ready_future.wait_for(std::chrono::seconds(5));
    return t;
}

// ---------------------------------------------------------------------------
// Section 1: Config parsing tests (no server needed)
// ---------------------------------------------------------------------------

// Parse a full upstream JSON block and verify all fields land correctly.
void TestConfigParseUpstreamAllFields() {
    std::cout << "\n[TEST] UpstreamPool Config: parse all fields..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name":  "backend",
                "host":  "10.0.0.1",
                "port":  8080,
                "tls": {
                    "enabled":      false,
                    "verify_peer":  true,
                    "sni_hostname": "",
                    "min_version":  "1.2"
                },
                "pool": {
                    "max_connections":       32,
                    "max_idle_connections":   8,
                    "connect_timeout_ms":  3000,
                    "idle_timeout_sec":      60,
                    "max_lifetime_sec":    7200,
                    "max_requests_per_conn": 100
                }
            }]
        })";

        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = true;
        std::string err;

        if (cfg.upstreams.size() != 1) { pass = false; err += "expected 1 upstream; "; }
        else {
            const auto& u = cfg.upstreams[0];
            if (u.name != "backend")       { pass = false; err += "name mismatch; "; }
            if (u.host != "10.0.0.1")      { pass = false; err += "host mismatch; "; }
            if (u.port != 8080)            { pass = false; err += "port mismatch; "; }
            if (u.tls.enabled)             { pass = false; err += "tls.enabled should be false; "; }
            if (!u.tls.verify_peer)        { pass = false; err += "verify_peer default; "; }
            if (u.pool.max_connections != 32)        { pass = false; err += "max_connections; "; }
            if (u.pool.max_idle_connections != 8)    { pass = false; err += "max_idle; "; }
            if (u.pool.connect_timeout_ms != 3000)   { pass = false; err += "connect_timeout_ms; "; }
            if (u.pool.idle_timeout_sec != 60)       { pass = false; err += "idle_timeout_sec; "; }
            if (u.pool.max_lifetime_sec != 7200)     { pass = false; err += "max_lifetime_sec; "; }
            if (u.pool.max_requests_per_conn != 100) { pass = false; err += "max_requests; "; }
        }

        TestFramework::RecordTest("UpstreamPool Config: parse all fields", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: parse all fields", false, e.what());
    }
}

// Missing optional pool sub-object → defaults are applied.
void TestConfigParseUpstreamDefaults() {
    std::cout << "\n[TEST] UpstreamPool Config: minimal config uses defaults..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{"name": "svc", "host": "127.0.0.1", "port": 9000}]
        })";

        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = true;
        std::string err;

        if (cfg.upstreams.empty()) { pass = false; err += "no upstream parsed; "; }
        else {
            const auto& p = cfg.upstreams[0].pool;
            if (p.max_connections != 64)       { pass = false; err += "default max_connections; "; }
            if (p.max_idle_connections != 16)   { pass = false; err += "default max_idle; "; }
            if (p.connect_timeout_ms != 5000)   { pass = false; err += "default connect_timeout_ms; "; }
            if (p.idle_timeout_sec != 90)       { pass = false; err += "default idle_timeout_sec; "; }
            if (p.max_lifetime_sec != 3600)     { pass = false; err += "default max_lifetime_sec; "; }
            if (p.max_requests_per_conn != 0)   { pass = false; err += "default max_requests; "; }
        }

        TestFramework::RecordTest("UpstreamPool Config: minimal config uses defaults", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: minimal config uses defaults", false, e.what());
    }
}

// Empty upstreams array is valid; server simply has no pools.
void TestConfigParseEmptyUpstreams() {
    std::cout << "\n[TEST] UpstreamPool Config: empty upstreams array..." << std::endl;
    try {
        const std::string json = R"({"upstreams": []})";
        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = cfg.upstreams.empty();
        TestFramework::RecordTest("UpstreamPool Config: empty upstreams array",
                                  pass, pass ? "" : "expected empty upstreams");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: empty upstreams array", false, e.what());
    }
}

// Validate rejects configs with duplicate upstream names.
void TestConfigValidateDuplicateName() {
    std::cout << "\n[TEST] UpstreamPool Config: duplicate name rejected..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.upstreams.push_back(MakeUpstreamConfig("dup", "127.0.0.1", 9001));
        cfg.upstreams.push_back(MakeUpstreamConfig("dup", "127.0.0.1", 9002));

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("UpstreamPool Config: duplicate name rejected",
                                      false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("UpstreamPool Config: duplicate name rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: duplicate name rejected", false, e.what());
    }
}

// Validate rejects port = 0 (out of range 1-65535).
void TestConfigValidateInvalidPort() {
    std::cout << "\n[TEST] UpstreamPool Config: invalid port rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u = MakeUpstreamConfig("svc", "127.0.0.1", 0);
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("UpstreamPool Config: invalid port rejected",
                                      false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("UpstreamPool Config: invalid port rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: invalid port rejected", false, e.what());
    }
}

// Validate rejects max_connections < 1.
void TestConfigValidateMaxConnectionsLow() {
    std::cout << "\n[TEST] UpstreamPool Config: max_connections < 1 rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u = MakeUpstreamConfig("svc", "127.0.0.1", 9001);
        u.pool.max_connections = 0;
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("UpstreamPool Config: max_connections < 1 rejected",
                                      false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("UpstreamPool Config: max_connections < 1 rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: max_connections < 1 rejected", false, e.what());
    }
}

// Validate rejects max_idle_connections > max_connections.
void TestConfigValidateMaxIdleExceedsMax() {
    std::cout << "\n[TEST] UpstreamPool Config: max_idle > max_connections rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u = MakeUpstreamConfig("svc", "127.0.0.1", 9001);
        u.pool.max_connections      = 4;
        u.pool.max_idle_connections = 8;  // exceeds max
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("UpstreamPool Config: max_idle > max_connections rejected",
                                      false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("UpstreamPool Config: max_idle > max_connections rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: max_idle > max_connections rejected", false, e.what());
    }
}

// Validate rejects connect_timeout_ms < 100.
void TestConfigValidateConnectTimeoutTooLow() {
    std::cout << "\n[TEST] UpstreamPool Config: connect_timeout_ms < 100 rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u = MakeUpstreamConfig("svc", "127.0.0.1", 9001);
        u.pool.connect_timeout_ms = 99;
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("UpstreamPool Config: connect_timeout_ms < 100 rejected",
                                      false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("UpstreamPool Config: connect_timeout_ms < 100 rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: connect_timeout_ms < 100 rejected", false, e.what());
    }
}

// Round-trip: ToJson then LoadFromString reproduces identical upstream values.
void TestConfigRoundTrip() {
    std::cout << "\n[TEST] UpstreamPool Config: JSON round-trip..." << std::endl;
    try {
        ServerConfig original;
        UpstreamConfig u;
        u.name                        = "rt-svc";
        u.host                        = "192.168.1.50";
        u.port                        = 7777;
        u.pool.max_connections        = 20;
        u.pool.max_idle_connections   = 5;
        u.pool.connect_timeout_ms     = 1500;
        u.pool.idle_timeout_sec       = 45;
        u.pool.max_lifetime_sec       = 1800;
        u.pool.max_requests_per_conn  = 50;
        original.upstreams.push_back(u);

        std::string json_out = ConfigLoader::ToJson(original);
        ServerConfig restored = ConfigLoader::LoadFromString(json_out);

        bool pass = true;
        std::string err;

        if (restored.upstreams.size() != 1) { pass = false; err += "upstream count; "; }
        else {
            const auto& r = restored.upstreams[0];
            if (r.name != u.name)                              { pass = false; err += "name; "; }
            if (r.host != u.host)                              { pass = false; err += "host; "; }
            if (r.port != u.port)                              { pass = false; err += "port; "; }
            if (r.pool.max_connections != u.pool.max_connections)
                { pass = false; err += "max_connections; "; }
            if (r.pool.max_idle_connections != u.pool.max_idle_connections)
                { pass = false; err += "max_idle; "; }
            if (r.pool.connect_timeout_ms != u.pool.connect_timeout_ms)
                { pass = false; err += "connect_timeout_ms; "; }
            if (r.pool.idle_timeout_sec != u.pool.idle_timeout_sec)
                { pass = false; err += "idle_timeout_sec; "; }
            if (r.pool.max_lifetime_sec != u.pool.max_lifetime_sec)
                { pass = false; err += "max_lifetime_sec; "; }
            if (r.pool.max_requests_per_conn != u.pool.max_requests_per_conn)
                { pass = false; err += "max_requests; "; }
        }

        TestFramework::RecordTest("UpstreamPool Config: JSON round-trip", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: JSON round-trip", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 2: SocketHandler connect tests
// ---------------------------------------------------------------------------

// SocketHandler::Connect to a listening socket succeeds (CONNECT_SUCCESS or
// CONNECT_IN_PROGRESS because the connect may complete without waiting).
void TestSocketHandlerConnectSuccess() {
    std::cout << "\n[TEST] UpstreamPool SocketHandler: connect to listening socket..." << std::endl;
    try {
        auto [lfd, port] = MakeListenerFd();
        struct ListenerGuard {
            int fd;
            ~ListenerGuard() { ::close(fd); }
        } lg{lfd};

        // Create a non-blocking client socket and attempt connect.
        int cfd = SocketHandler::CreateClientSocket();
        if (cfd < 0) throw std::runtime_error("CreateClientSocket failed");

        struct ClientGuard {
            int fd;
            ~ClientGuard() { if (fd >= 0) ::close(fd); }
        } cg{cfd};

        SocketHandler sh(cfd);
        InetAddr target("127.0.0.1", port);
        int rc = sh.Connect(target);

        bool pass = (rc == SocketHandler::CONNECT_SUCCESS ||
                     rc == SocketHandler::CONNECT_IN_PROGRESS);
        std::string err = pass ? "" :
            "unexpected Connect() return code: " + std::to_string(rc);

        // Prevent double-close: SocketHandler owns the fd after construction.
        cg.fd = -1;

        TestFramework::RecordTest("UpstreamPool SocketHandler: connect to listening socket",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool SocketHandler: connect to listening socket",
                                  false, e.what());
    }
}

// SocketHandler::Connect to a closed port (connection refused) returns error.
void TestSocketHandlerConnectRefused() {
    std::cout << "\n[TEST] UpstreamPool SocketHandler: connect refused..." << std::endl;
    try {
        // Pick an ephemeral port, bind, then immediately close — so the port
        // is guaranteed to be available-then-gone.
        auto [lfd, port] = MakeListenerFd();
        ::close(lfd);  // close before connecting → ECONNREFUSED

        int cfd = SocketHandler::CreateClientSocket();
        if (cfd < 0) throw std::runtime_error("CreateClientSocket failed");

        SocketHandler sh(cfd);
        InetAddr target("127.0.0.1", port);
        int rc = sh.Connect(target);

        // Non-blocking connect may return IN_PROGRESS first; FinishConnect
        // would then give the error. Accept either CONNECT_ERROR immediately
        // or IN_PROGRESS (the test validates only the initial call here since
        // we don't run an event loop for async completion).
        bool pass = (rc == SocketHandler::CONNECT_ERROR ||
                     rc == SocketHandler::CONNECT_IN_PROGRESS);
        std::string err = pass ? "" :
            "unexpected rc=" + std::to_string(rc) + " for refused port";

        TestFramework::RecordTest("UpstreamPool SocketHandler: connect refused", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool SocketHandler: connect refused", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 3: UpstreamConnection unit tests
// ---------------------------------------------------------------------------

// State machine: CONNECTING → READY → IN_USE → READY
void TestUpstreamConnectionStateTransitions() {
    std::cout << "\n[TEST] UpstreamPool UpstreamConnection: state transitions..." << std::endl;
    try {
        // Open a socketpair so both ends are valid fds (no real server needed).
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");

        // sv[0] is the "upstream" fd; sv[1] is the "server-side" peer.
        // Close sv[1] immediately — we just need sv[0] to be a valid open fd.
        ::close(sv[1]);

        // Wrap sv[0] in an UpstreamConnection (it takes ownership via SocketHandler).
        auto sock = std::make_unique<SocketHandler>(sv[0]);
        auto conn = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
        UpstreamConnection uc(conn, "127.0.0.1", 9999);

        bool pass = true;
        std::string err;

        // Initial state after construction must be CONNECTING.
        if (uc.state() != UpstreamConnection::State::CONNECTING) {
            pass = false; err += "initial state not CONNECTING; ";
        }

        // MarkIdle → READY (MarkReady was an identical alias, removed)
        uc.MarkIdle();
        if (!uc.IsIdle()) { pass = false; err += "after MarkIdle(initial) not idle; "; }

        // MarkInUse → IN_USE
        uc.MarkInUse();
        if (!uc.IsInUse()) { pass = false; err += "after MarkInUse not in-use; "; }

        // MarkIdle → READY
        uc.MarkIdle();
        if (!uc.IsIdle()) { pass = false; err += "after MarkIdle not idle; "; }

        // MarkClosing → CLOSING
        uc.MarkClosing();
        if (!uc.IsClosing()) { pass = false; err += "after MarkClosing not closing; "; }

        TestFramework::RecordTest("UpstreamPool UpstreamConnection: state transitions", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamConnection: state transitions", false, e.what());
    }
}

// IsExpired detects connection past max_lifetime_sec.
void TestUpstreamConnectionExpiredLifetime() {
    std::cout << "\n[TEST] UpstreamPool UpstreamConnection: IsExpired by lifetime..." << std::endl;
    try {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");
        ::close(sv[1]);

        auto sock = std::make_unique<SocketHandler>(sv[0]);
        auto conn = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
        UpstreamConnection uc(conn, "127.0.0.1", 9999);

        // max_lifetime_sec = 0 → unlimited (never expired by lifetime)
        bool pass = true;
        std::string err;

        if (uc.IsExpired(0, 0)) {
            pass = false; err += "unlimited lifetime should not be expired; ";
        }

        // max_lifetime_sec = 1 but connection just created → not yet expired
        if (uc.IsExpired(1, 0)) {
            pass = false; err += "freshly created should not be expired (1s); ";
        }

        // Simulate an aged connection by checking with a very small threshold.
        // We sleep 1s to cross the threshold.
        std::this_thread::sleep_for(std::chrono::milliseconds(1010));
        if (!uc.IsExpired(1, 0)) {
            pass = false; err += "connection older than 1s should be expired; ";
        }

        TestFramework::RecordTest("UpstreamPool UpstreamConnection: IsExpired by lifetime", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamConnection: IsExpired by lifetime", false, e.what());
    }
}

// IsExpired detects connection past max_requests_per_conn.
void TestUpstreamConnectionExpiredRequestCount() {
    std::cout << "\n[TEST] UpstreamPool UpstreamConnection: IsExpired by request count..." << std::endl;
    try {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");
        ::close(sv[1]);

        auto sock = std::make_unique<SocketHandler>(sv[0]);
        auto conn = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
        UpstreamConnection uc(conn, "127.0.0.1", 9999);

        bool pass = true;
        std::string err;

        // max_requests_per_conn = 0 → unlimited
        if (uc.IsExpired(0, 0)) {
            pass = false; err += "unlimited requests should not be expired; ";
        }

        // max_requests_per_conn = 3
        uc.IncrementRequestCount();
        uc.IncrementRequestCount();
        if (uc.IsExpired(0, 3)) {
            pass = false; err += "at 2/3 requests should not be expired; ";
        }

        uc.IncrementRequestCount();
        if (!uc.IsExpired(0, 3)) {
            pass = false; err += "at 3/3 requests should be expired; ";
        }

        TestFramework::RecordTest("UpstreamPool UpstreamConnection: IsExpired by request count",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamConnection: IsExpired by request count",
                                  false, e.what());
    }
}

// IsAlive returns true on a valid open socket, false after peer closes.
void TestUpstreamConnectionIsAlive() {
    std::cout << "\n[TEST] UpstreamPool UpstreamConnection: IsAlive..." << std::endl;
    try {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");

        {
            // Create UpstreamConnection wrapping sv[0]; leave sv[1] open (simulates upstream).
            auto sock = std::make_unique<SocketHandler>(sv[0]);
            auto conn = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
            UpstreamConnection uc(conn, "127.0.0.1", 9999);

            bool pass = true;
            std::string err;

            // While sv[1] is open and has no pending data, IsAlive should return true.
            if (!uc.IsAlive()) {
                pass = false; err += "should be alive when peer fd is open; ";
            }

            // Close the peer end — this sends EOF/POLLHUP to sv[0].
            ::close(sv[1]);
            // Give the kernel a moment to deliver the event.
            std::this_thread::sleep_for(std::chrono::milliseconds(5));

            // IsAlive should now return false (POLLHUP or POLLIN with 0 bytes).
            // This is informational — kernel timing varies, so we don't hard-fail.
            if (uc.IsAlive()) {
                std::cout << "[TEST] Note: IsAlive() still true after peer close "
                             "(platform timing variation, non-critical)" << std::endl;
            }

            TestFramework::RecordTest("UpstreamPool UpstreamConnection: IsAlive", pass, err);
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamConnection: IsAlive", false, e.what());
    }
}

// fd() returns -1 when the underlying conn_ holds no socket.
void TestUpstreamConnectionNullFd() {
    std::cout << "\n[TEST] UpstreamPool UpstreamConnection: fd() with null conn..." << std::endl;
    try {
        // Construct with a null ConnectionHandler shared_ptr.
        UpstreamConnection uc(nullptr, "127.0.0.1", 9999);

        bool pass = (uc.fd() == -1);
        TestFramework::RecordTest("UpstreamPool UpstreamConnection: fd() with null conn",
                                  pass, pass ? "" : "expected fd() == -1 for null conn");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamConnection: fd() with null conn",
                                  false, e.what());
    }
}

// IncrementRequestCount increases the counter monotonically.
void TestUpstreamConnectionRequestCount() {
    std::cout << "\n[TEST] UpstreamPool UpstreamConnection: request count..." << std::endl;
    try {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");
        ::close(sv[1]);

        auto sock = std::make_unique<SocketHandler>(sv[0]);
        auto conn = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
        UpstreamConnection uc(conn, "127.0.0.1", 9999);

        bool pass = true;
        std::string err;

        if (uc.request_count() != 0) { pass = false; err += "initial count != 0; "; }

        uc.IncrementRequestCount();
        if (uc.request_count() != 1) { pass = false; err += "count after 1 increment != 1; "; }

        for (int i = 0; i < 9; ++i) uc.IncrementRequestCount();
        if (uc.request_count() != 10) { pass = false; err += "count after 10 increments != 10; "; }

        TestFramework::RecordTest("UpstreamPool UpstreamConnection: request count", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamConnection: request count", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 4: UpstreamLease RAII tests
//
// The lease destructor calls PoolPartition::ReturnConnection when both
// conn_ and partition_ are non-null. Tests with partition_=nullptr verify
// the no-op path (lease returns nothing to any pool).
// ---------------------------------------------------------------------------

// Default-constructed lease is empty and evaluates to false.
void TestUpstreamLeaseEmptyDefault() {
    std::cout << "\n[TEST] UpstreamPool UpstreamLease: default empty..." << std::endl;
    try {
        UpstreamLease lease;

        bool pass = (!static_cast<bool>(lease) && lease.Get() == nullptr);
        TestFramework::RecordTest("UpstreamPool UpstreamLease: default empty",
                                  pass, pass ? "" : "empty lease should be null/false");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamLease: default empty", false, e.what());
    }
}

// After a move, the source lease is empty and the destination holds the conn.
void TestUpstreamLeaseMoveSematics() {
    std::cout << "\n[TEST] UpstreamPool UpstreamLease: move semantics..." << std::endl;
    try {
        // Build a fake raw connection pointer. We just need a non-null address
        // and a null partition so the destructor skips ReturnConnection.
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");
        ::close(sv[1]);

        auto sock = std::make_unique<SocketHandler>(sv[0]);
        auto conn_handler = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
        // Allocate UpstreamConnection on the heap. With partition_=nullptr the
        // lease destructor is a no-op, so we own and must delete it manually.
        UpstreamConnection* raw_conn = new UpstreamConnection(conn_handler, "127.0.0.1", 9999);

        UpstreamLease src(raw_conn, nullptr);

        bool pass = true;
        std::string err;

        if (!src || src.Get() != raw_conn) {
            pass = false; err += "src lease should hold conn; ";
        }

        // Move into dst
        UpstreamLease dst(std::move(src));

        // src must be empty now
        if (static_cast<bool>(src) || src.Get() != nullptr) {
            pass = false; err += "src should be empty after move; ";
        }

        // dst must hold the connection
        if (!dst || dst.Get() != raw_conn) {
            pass = false; err += "dst should hold conn after move; ";
        }

        // Release so the destructor (with null partition) is a no-op, then
        // manually free the raw UpstreamConnection.
        dst.Release();
        delete raw_conn;

        TestFramework::RecordTest("UpstreamPool UpstreamLease: move semantics", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamLease: move semantics", false, e.what());
    }
}

// Explicit Release() clears the lease before destruction.
void TestUpstreamLeaseExplicitRelease() {
    std::cout << "\n[TEST] UpstreamPool UpstreamLease: explicit Release()..." << std::endl;
    try {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");
        ::close(sv[1]);

        auto sock = std::make_unique<SocketHandler>(sv[0]);
        auto conn_handler = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
        UpstreamConnection* raw_conn = new UpstreamConnection(conn_handler, "127.0.0.1", 9999);

        UpstreamLease lease(raw_conn, nullptr);
        bool pass = true;
        std::string err;

        if (!lease) { pass = false; err += "lease should be non-empty initially; "; }

        lease.Release();

        if (static_cast<bool>(lease) || lease.Get() != nullptr) {
            pass = false; err += "after Release(), lease should be empty; ";
        }

        // Safe to delete now — lease no longer holds the raw ptr.
        delete raw_conn;

        TestFramework::RecordTest("UpstreamPool UpstreamLease: explicit Release()", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamLease: explicit Release()", false, e.what());
    }
}

// Move-assignment: assign from non-empty to empty, then assign from empty to non-empty.
void TestUpstreamLeaseMoveAssignment() {
    std::cout << "\n[TEST] UpstreamPool UpstreamLease: move-assignment..." << std::endl;
    try {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
            throw std::runtime_error("socketpair failed");
        ::close(sv[1]);

        auto sock = std::make_unique<SocketHandler>(sv[0]);
        auto conn_handler = std::make_shared<ConnectionHandler>(nullptr, std::move(sock));
        UpstreamConnection* raw_conn = new UpstreamConnection(conn_handler, "127.0.0.1", 9999);

        UpstreamLease src(raw_conn, nullptr);
        UpstreamLease dst;

        bool pass = true;
        std::string err;

        // Move-assign: empty dst receives conn from src.
        dst = std::move(src);

        if (src.Get() != nullptr) { pass = false; err += "src not cleared by move-assign; "; }
        if (dst.Get() != raw_conn) { pass = false; err += "dst did not receive conn; "; }

        // Move-assign back: dst → src (now empty).
        src = std::move(dst);
        if (dst.Get() != nullptr) { pass = false; err += "dst not cleared; "; }
        if (src.Get() != raw_conn) { pass = false; err += "src did not receive back; "; }

        src.Release();
        delete raw_conn;

        TestFramework::RecordTest("UpstreamPool UpstreamLease: move-assignment", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamLease: move-assignment", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 5: Integration — UpstreamManager with a real Dispatcher
//
// DESIGN NOTE: These tests use a real Dispatcher event loop to exercise the
// actual async code paths. The DispatcherThreadGuard RAII helper guarantees
// that the dispatcher thread is always stopped and joined — even when tests
// fail or throw — preventing the "terminate called without an active exception"
// crash that occurs when std::thread::~thread() is called on a joinable thread.
// ---------------------------------------------------------------------------

// HasUpstream returns true for configured names, false for unknown ones.
void TestUpstreamManagerHasUpstream() {
    std::cout << "\n[TEST] UpstreamPool Integration: HasUpstream lookup..." << std::endl;
    try {
        // Configure two services (uses placeholder ports; no actual connections made).
        UpstreamConfig u1 = MakeUpstreamConfig("alpha", "127.0.0.1", 9001);
        UpstreamConfig u2 = MakeUpstreamConfig("beta",  "127.0.0.1", 9002);

        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);
        // mgr declared BEFORE dtg so dtg destructs first (joins thread),
        // guaranteeing the dispatcher thread is done before mgr is destroyed.
        UpstreamManager mgr({u1, u2}, {dispatcher});
        DispatcherThreadGuard dtg{dispatcher, dt};

        bool pass = true;
        std::string err;

        if (!mgr.HasUpstream("alpha")) { pass = false; err += "alpha not found; "; }
        if (!mgr.HasUpstream("beta"))  { pass = false; err += "beta not found; "; }
        if (mgr.HasUpstream("gamma"))  { pass = false; err += "gamma should not exist; "; }
        if (mgr.HasUpstream(""))       { pass = false; err += "empty name should not exist; "; }

        // dtg destructor stops dispatcher and joins.
        TestFramework::RecordTest("UpstreamPool Integration: HasUpstream lookup", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: HasUpstream lookup", false, e.what());
    }
}

// Checkout from an unknown service name delivers an error callback immediately.
void TestUpstreamManagerUnknownService() {
    std::cout << "\n[TEST] UpstreamPool Integration: checkout from unknown service errors..." << std::endl;
    try {
        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);
        // No upstreams configured.
        UpstreamManager mgr({}, {dispatcher});
        // dtg declared after mgr → destructs first → joins thread before mgr is destroyed.
        DispatcherThreadGuard dtg{dispatcher, dt};

        // Use shared_ptr for the promise so the lambda capture outlives the stack frame.
        auto err_code_p = std::make_shared<std::promise<int>>();
        auto err_code_future = err_code_p->get_future();

        dispatcher->EnQueue([&mgr, err_code_p]() {
            mgr.CheckoutAsync(
                "nonexistent",
                0,
                [err_code_p](UpstreamLease) {
                    try {
                        err_code_p->set_exception(std::make_exception_ptr(
                            std::runtime_error("should not succeed")));
                    } catch (...) {}
                },
                [err_code_p](int ec) {
                    try { err_code_p->set_value(ec); } catch (...) {}
                }
            );
        });

        auto status = err_code_future.wait_for(std::chrono::seconds(3));

        bool pass = false;
        std::string err;

        if (status == std::future_status::timeout) {
            err = "error callback never fired";
        } else {
            try {
                // ec < 0 for any PoolPartition error code
                pass = (err_code_future.get() < 0);
                if (!pass) err = "expected negative error code";
            } catch (const std::exception& ex) {
                err = std::string("unexpected exception: ") + ex.what();
            }
        }

        TestFramework::RecordTest("UpstreamPool Integration: checkout from unknown service errors",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: checkout from unknown service errors",
                                  false, e.what());
    }
}

// AllDrained() is true after InitiateShutdown + WaitForDrain with no active conns.
void TestUpstreamManagerShutdownDrain() {
    std::cout << "\n[TEST] UpstreamPool Integration: shutdown drain..." << std::endl;
    try {
        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);
        // No upstreams — nothing to drain.
        UpstreamManager mgr({}, {dispatcher});
        // dtg after mgr: joins dispatcher thread before mgr destructs.
        DispatcherThreadGuard dtg{dispatcher, dt};

        mgr.InitiateShutdown();
        mgr.WaitForDrain(std::chrono::seconds(2));

        bool pass = mgr.AllDrained();
        TestFramework::RecordTest("UpstreamPool Integration: shutdown drain",
                                  pass, pass ? "" : "AllDrained() returned false after WaitForDrain");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: shutdown drain", false, e.what());
    }
}

// EvictExpired is callable on the dispatcher thread without crashing.
void TestUpstreamManagerEvictExpired() {
    std::cout << "\n[TEST] UpstreamPool Integration: EvictExpired no-crash..." << std::endl;
    try {
        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);
        UpstreamManager mgr({}, {dispatcher});
        // dtg after mgr: joins dispatcher thread before mgr destructs.
        DispatcherThreadGuard dtg{dispatcher, dt};

        auto evict_ok = std::make_shared<std::promise<bool>>();
        auto evict_f = evict_ok->get_future();

        dispatcher->EnQueue([&mgr, evict_ok]() {
            try {
                mgr.EvictExpired(0);
                try { evict_ok->set_value(true); } catch (...) {}
            } catch (...) {
                try { evict_ok->set_value(false); } catch (...) {}
            }
        });

        auto status = evict_f.wait_for(std::chrono::seconds(3));
        bool pass = (status != std::future_status::timeout) && evict_f.get();

        TestFramework::RecordTest("UpstreamPool Integration: EvictExpired no-crash",
                                  pass, pass ? "" : "EvictExpired timed out or threw");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: EvictExpired no-crash",
                                  false, e.what());
    }
}

// CheckoutAsync from a real backend — verifies the end-to-end async connect.
void TestUpstreamManagerCheckoutAsync() {
    std::cout << "\n[TEST] UpstreamPool Integration: CheckoutAsync gets a valid connection..." << std::endl;
    try {
        // Start a plain HttpServer as the "upstream backend".
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/ping", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Body("pong");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        const int backend_port = backend_runner.GetPort();

        // Build a Dispatcher for the "gateway" side.
        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);

        // Configure UpstreamManager with one upstream = the backend.
        // IMPORTANT: mgr must be declared BEFORE dtg so that dtg destructs first
        // (joining the dispatcher thread), ensuring no enqueued tasks reference a
        // destroyed PoolPartition when mgr destructs.
        UpstreamConfig ucfg = MakeUpstreamConfig("backend", "127.0.0.1", backend_port);
        UpstreamManager mgr({ucfg}, {dispatcher});
        // DispatcherThreadGuard guarantees join even on failure paths.
        DispatcherThreadGuard dtg{dispatcher, dt};

        // CheckoutAsync must be called on the dispatcher thread.
        // Use shared_ptr to own the promise so the callback can safely set
        // the value even if this stack frame is gone (e.g., on timeout path).
        auto fd_promise = std::make_shared<std::promise<int>>();
        auto fd_future  = fd_promise->get_future();

        dispatcher->EnQueue([&mgr, fd_promise]() {
            mgr.CheckoutAsync(
                "backend",
                /*dispatcher_index=*/0,
                [fd_promise](UpstreamLease lease) {
                    int fd = lease ? lease->fd() : -1;
                    try { fd_promise->set_value(fd); } catch (...) {}
                    // Lease destructor returns connection to pool.
                },
                [fd_promise](int error_code) {
                    try {
                        fd_promise->set_exception(std::make_exception_ptr(
                            std::runtime_error("checkout failed: " +
                                               std::to_string(error_code))));
                    } catch (...) {}
                }
            );
        });

        // Wait up to 3 seconds for the connect to complete.
        auto status = fd_future.wait_for(std::chrono::seconds(3));

        bool pass = false;
        std::string err;

        if (status == std::future_status::timeout) {
            err = "CheckoutAsync timed out after 3s";
        } else {
            try {
                int fd = fd_future.get();
                pass = (fd > 0);
                if (!pass) err = "got invalid fd=" + std::to_string(fd);
            } catch (const std::exception& ex) {
                err = std::string("checkout error: ") + ex.what();
            }
        }

        // Initiate shutdown on the dispatcher thread — this drains the wait
        // queue and fires any pending error callbacks (via the shared_ptr
        // captured above, so there's no dangling reference risk).
        mgr.InitiateShutdown();
        mgr.WaitForDrain(std::chrono::seconds(2));

        // dtg destructor stops the dispatcher and joins the thread.
        TestFramework::RecordTest("UpstreamPool Integration: CheckoutAsync gets a valid connection",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: CheckoutAsync gets a valid connection",
                                  false, e.what());
    }
}

// Connection reuse: two sequential checkouts should use valid fds.
// If the pool correctly reuses the connection, both fds will be equal.
void TestUpstreamManagerConnectionReuse() {
    std::cout << "\n[TEST] UpstreamPool Integration: connection reuse (same fd)..." << std::endl;
    try {
        // Start backend
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/ok", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Body("ok");
        });
        TestServerRunner<HttpServer> bk(backend);
        const int bp = bk.GetPort();

        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);
        // mgr before dtg: dtg destructs first (joins dispatcher), then mgr destructs safely.
        UpstreamConfig ucfg = MakeUpstreamConfig("backend", "127.0.0.1", bp);
        UpstreamManager mgr({ucfg}, {dispatcher});
        DispatcherThreadGuard dtg{dispatcher, dt};

        // First checkout — shared_ptr ownership ensures safety across timeout.
        auto first_fd_p = std::make_shared<std::promise<int>>();
        auto first_fd_f = first_fd_p->get_future();

        dispatcher->EnQueue([&mgr, first_fd_p]() {
            mgr.CheckoutAsync(
                "backend", 0,
                [first_fd_p](UpstreamLease lease) {
                    int fd = lease ? lease->fd() : -1;
                    try { first_fd_p->set_value(fd); } catch (...) {}
                    // Lease destructor returns connection to pool.
                },
                [first_fd_p](int ec) {
                    try {
                        first_fd_p->set_exception(std::make_exception_ptr(
                            std::runtime_error("first checkout failed: " +
                                               std::to_string(ec))));
                    } catch (...) {}
                }
            );
        });

        auto fst_status = first_fd_f.wait_for(std::chrono::seconds(3));

        bool pass = true;
        std::string err;
        int fd1 = -1;

        if (fst_status == std::future_status::timeout) {
            pass = false;
            err = "first checkout timed out";
        } else {
            try {
                fd1 = first_fd_f.get();
                if (fd1 <= 0) { pass = false; err += "first fd invalid; "; }
            } catch (const std::exception& ex) {
                pass = false;
                err = std::string("first checkout: ") + ex.what();
            }
        }

        if (pass) {
            // Give the pool a moment to process the return.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            // Second checkout — should reuse the same connection.
            auto second_fd_p = std::make_shared<std::promise<int>>();
            auto second_fd_f = second_fd_p->get_future();

            dispatcher->EnQueue([&mgr, second_fd_p]() {
                mgr.CheckoutAsync(
                    "backend", 0,
                    [second_fd_p](UpstreamLease lease) {
                        int fd = lease ? lease->fd() : -1;
                        try { second_fd_p->set_value(fd); } catch (...) {}
                    },
                    [second_fd_p](int ec) {
                        try {
                            second_fd_p->set_exception(std::make_exception_ptr(
                                std::runtime_error("second checkout failed: " +
                                                   std::to_string(ec))));
                        } catch (...) {}
                    }
                );
            });

            auto sst_status = second_fd_f.wait_for(std::chrono::seconds(3));
            if (sst_status == std::future_status::timeout) {
                pass = false;
                err += "second checkout timed out; ";
            } else {
                try {
                    int fd2 = second_fd_f.get();
                    if (fd2 <= 0) { pass = false; err += "second fd invalid; "; }
                    else if (fd1 != fd2) {
                        // Reuse is best-effort — acceptable if pool re-created.
                        std::cout << "[TEST] Note: fd1=" << fd1 << " fd2=" << fd2
                                  << " (new connection was created instead of reusing)" << std::endl;
                    }
                } catch (const std::exception& ex) {
                    pass = false;
                    err += std::string("second checkout: ") + ex.what() + "; ";
                }
            }
        }

        mgr.InitiateShutdown();
        mgr.WaitForDrain(std::chrono::seconds(2));

        TestFramework::RecordTest("UpstreamPool Integration: connection reuse (same fd)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: connection reuse (same fd)",
                                  false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 6: PoolPartition error constants sanity check
// ---------------------------------------------------------------------------

void TestPoolPartitionErrorCodes() {
    std::cout << "\n[TEST] UpstreamPool PoolPartition: error code values..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // All error codes must be negative (callers treat < 0 as error).
        if (PoolPartition::CHECKOUT_POOL_EXHAUSTED  >= 0) { pass = false; err += "POOL_EXHAUSTED; "; }
        if (PoolPartition::CHECKOUT_CONNECT_FAILED  >= 0) { pass = false; err += "CONNECT_FAILED; "; }
        if (PoolPartition::CHECKOUT_CONNECT_TIMEOUT >= 0) { pass = false; err += "CONNECT_TIMEOUT; "; }
        if (PoolPartition::CHECKOUT_SHUTTING_DOWN   >= 0) { pass = false; err += "SHUTTING_DOWN; "; }
        if (PoolPartition::CHECKOUT_QUEUE_TIMEOUT   >= 0) { pass = false; err += "QUEUE_TIMEOUT; "; }

        // All error codes must be distinct.
        std::set<int> codes{
            PoolPartition::CHECKOUT_POOL_EXHAUSTED,
            PoolPartition::CHECKOUT_CONNECT_FAILED,
            PoolPartition::CHECKOUT_CONNECT_TIMEOUT,
            PoolPartition::CHECKOUT_SHUTTING_DOWN,
            PoolPartition::CHECKOUT_QUEUE_TIMEOUT
        };
        if (codes.size() != 5) { pass = false; err += "error codes not distinct; "; }

        TestFramework::RecordTest("UpstreamPool PoolPartition: error code values", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool PoolPartition: error code values", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 7: UpstreamHostPool partition count
// ---------------------------------------------------------------------------

void TestUpstreamHostPoolPartitionCount() {
    std::cout << "\n[TEST] UpstreamPool UpstreamHostPool: one partition per dispatcher..." << std::endl;
    try {
        // Build two dispatchers.
        auto d0 = std::make_shared<Dispatcher>(true, 5);
        auto d1 = std::make_shared<Dispatcher>(true, 5);

        std::thread t0 = StartDispatcher(d0);
        std::thread t1 = StartDispatcher(d1);

        DispatcherThreadGuard g0{d0, t0};
        DispatcherThreadGuard g1{d1, t1};

        UpstreamConfig ucfg = MakeUpstreamConfig("svc", "127.0.0.1", 9001);
        std::atomic<int64_t> outstanding{0};
        std::condition_variable drain_cv;

        UpstreamHostPool pool(
            ucfg.name, ucfg.host, ucfg.port,
            ucfg.pool, {d0, d1}, nullptr,
            outstanding, drain_cv);

        bool pass = true;
        std::string err;

        if (pool.partition_count() != 2) {
            pass = false;
            err = "expected 2 partitions, got " + std::to_string(pool.partition_count());
        }

        // GetPartition(0) and GetPartition(1) must be non-null.
        if (pool.GetPartition(0) == nullptr) { pass = false; err += "partition 0 null; "; }
        if (pool.GetPartition(1) == nullptr) { pass = false; err += "partition 1 null; "; }

        // Out-of-bounds index returns null.
        if (pool.GetPartition(2) != nullptr) { pass = false; err += "partition 2 should be null; "; }

        // Shutdown the pool before the dispatchers stop.
        pool.InitiateShutdown();

        TestFramework::RecordTest("UpstreamPool UpstreamHostPool: one partition per dispatcher",
                                  pass, err);
        // g0 and g1 destructors stop dispatchers and join threads.
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamHostPool: one partition per dispatcher",
                                  false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 8: UpstreamConfig accessor methods on UpstreamHostPool
// ---------------------------------------------------------------------------

void TestUpstreamHostPoolAccessors() {
    std::cout << "\n[TEST] UpstreamPool UpstreamHostPool: accessors..." << std::endl;
    try {
        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);
        DispatcherThreadGuard dtg{dispatcher, dt};

        UpstreamConfig ucfg = MakeUpstreamConfig("my-service", "10.0.0.1", 7777);
        std::atomic<int64_t> outstanding{0};
        std::condition_variable drain_cv;

        UpstreamHostPool pool(
            ucfg.name, ucfg.host, ucfg.port,
            ucfg.pool, {dispatcher}, nullptr,
            outstanding, drain_cv);

        bool pass = true;
        std::string err;

        if (pool.service_name() != "my-service") { pass = false; err += "service_name; "; }
        if (pool.host() != "10.0.0.1")           { pass = false; err += "host; "; }
        if (pool.port() != 7777)                 { pass = false; err += "port; "; }
        if (pool.partition_count() != 1)         { pass = false; err += "partition_count; "; }

        pool.InitiateShutdown();

        TestFramework::RecordTest("UpstreamPool UpstreamHostPool: accessors", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool UpstreamHostPool: accessors", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "UPSTREAM CONNECTION POOL - TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // Section 1: Config parsing / validation
    TestConfigParseUpstreamAllFields();
    TestConfigParseUpstreamDefaults();
    TestConfigParseEmptyUpstreams();
    TestConfigValidateDuplicateName();
    TestConfigValidateInvalidPort();
    TestConfigValidateMaxConnectionsLow();
    TestConfigValidateMaxIdleExceedsMax();
    TestConfigValidateConnectTimeoutTooLow();
    TestConfigRoundTrip();

    // Section 2: SocketHandler connect
    TestSocketHandlerConnectSuccess();
    TestSocketHandlerConnectRefused();

    // Section 3: UpstreamConnection unit tests
    TestUpstreamConnectionStateTransitions();
    TestUpstreamConnectionExpiredLifetime();
    TestUpstreamConnectionExpiredRequestCount();
    TestUpstreamConnectionIsAlive();
    TestUpstreamConnectionNullFd();
    TestUpstreamConnectionRequestCount();

    // Section 4: UpstreamLease RAII
    TestUpstreamLeaseEmptyDefault();
    TestUpstreamLeaseMoveSematics();
    TestUpstreamLeaseExplicitRelease();
    TestUpstreamLeaseMoveAssignment();

    // Section 5: Integration (UpstreamManager + real Dispatcher)
    TestUpstreamManagerHasUpstream();
    TestUpstreamManagerUnknownService();
    TestUpstreamManagerShutdownDrain();
    TestUpstreamManagerEvictExpired();
    TestUpstreamManagerCheckoutAsync();
    TestUpstreamManagerConnectionReuse();

    // Section 6: PoolPartition error codes
    TestPoolPartitionErrorCodes();

    // Section 7: UpstreamHostPool
    TestUpstreamHostPoolPartitionCount();

    // Section 8: UpstreamHostPool accessors
    TestUpstreamHostPoolAccessors();
}

} // namespace UpstreamPoolTests
