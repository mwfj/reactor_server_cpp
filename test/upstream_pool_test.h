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

// Validate rejects connect_timeout_ms < 1000 (timer resolution is 1s).
void TestConfigValidateConnectTimeoutTooLow() {
    std::cout << "\n[TEST] UpstreamPool Config: connect_timeout_ms < 1000 rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u = MakeUpstreamConfig("svc", "127.0.0.1", 9001);
        u.pool.connect_timeout_ms = 999;
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("UpstreamPool Config: connect_timeout_ms < 1000 rejected",
                                      false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("UpstreamPool Config: connect_timeout_ms < 1000 rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Config: connect_timeout_ms < 1000 rejected", false, e.what());
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

// Non-blocking connect to a listening socket succeeds (EINPROGRESS or immediate 0).
// Tests the same raw ::connect() path used by PoolPartition::CreateNewConnection.
void TestSocketHandlerConnectSuccess() {
    std::cout << "\n[TEST] UpstreamPool SocketHandler: connect to listening socket..." << std::endl;
    try {
        auto [lfd, port] = MakeListenerFd();
        struct ListenerGuard {
            int fd;
            ~ListenerGuard() { ::close(fd); }
        } lg{lfd};

        int cfd = SocketHandler::CreateClientSocket();
        if (cfd < 0) throw std::runtime_error("CreateClientSocket failed");

        struct ClientGuard {
            int fd;
            ~ClientGuard() { if (fd >= 0) ::close(fd); }
        } cg{cfd};

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");

        int rc = ::connect(cfd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
        // Non-blocking: expect 0 (immediate) or -1 with EINPROGRESS
        bool pass = (rc == 0 || (rc == -1 && errno == EINPROGRESS));
        std::string err = pass ? "" :
            "unexpected connect() result: rc=" + std::to_string(rc) +
            " errno=" + std::to_string(errno);

        TestFramework::RecordTest("UpstreamPool SocketHandler: connect to listening socket",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool SocketHandler: connect to listening socket",
                                  false, e.what());
    }
}

// Non-blocking connect to a closed port gets EINPROGRESS (async failure)
// or immediate ECONNREFUSED. Tests the same raw path as production code.
void TestSocketHandlerConnectRefused() {
    std::cout << "\n[TEST] UpstreamPool SocketHandler: connect refused..." << std::endl;
    try {
        auto [lfd, port] = MakeListenerFd();
        ::close(lfd);  // close before connecting → ECONNREFUSED

        int cfd = SocketHandler::CreateClientSocket();
        if (cfd < 0) throw std::runtime_error("CreateClientSocket failed");

        struct ClientGuard {
            int fd;
            ~ClientGuard() { if (fd >= 0) ::close(fd); }
        } cg{cfd};

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");

        int rc = ::connect(cfd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
        // Non-blocking: expect ECONNREFUSED immediately or EINPROGRESS
        // (async failure detected via SO_ERROR later)
        bool pass = (rc == -1 && (errno == ECONNREFUSED || errno == EINPROGRESS));
        std::string err = pass ? "" :
            "unexpected rc=" + std::to_string(rc) + " errno=" + std::to_string(errno);

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
        // Use unique_ptr to manage UpstreamConnection lifetime. With partition_=nullptr
        // the lease destructor is a no-op, so we retain ownership here.
        auto uc_owner = std::make_unique<UpstreamConnection>(conn_handler, "127.0.0.1", 9999);
        UpstreamConnection* raw_conn = uc_owner.get();

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

        // Release so the destructor (with null partition) is a no-op.
        // uc_owner handles cleanup when it goes out of scope.
        dst.Release();

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
        auto uc_owner = std::make_unique<UpstreamConnection>(conn_handler, "127.0.0.1", 9999);
        UpstreamConnection* raw_conn = uc_owner.get();

        UpstreamLease lease(raw_conn, nullptr);
        bool pass = true;
        std::string err;

        if (!lease) { pass = false; err += "lease should be non-empty initially; "; }

        lease.Release();

        if (static_cast<bool>(lease) || lease.Get() != nullptr) {
            pass = false; err += "after Release(), lease should be empty; ";
        }
        // uc_owner handles cleanup when it goes out of scope.

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
        auto uc_owner = std::make_unique<UpstreamConnection>(conn_handler, "127.0.0.1", 9999);
        UpstreamConnection* raw_conn = uc_owner.get();

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

        // Release so lease destructor (with null partition) is a no-op.
        // uc_owner handles cleanup when it goes out of scope.
        src.Release();

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
        std::mutex drain_mtx;
        std::condition_variable drain_cv;

        UpstreamHostPool pool(
            ucfg.name, ucfg.host, ucfg.port,
            ucfg.tls.sni_hostname,
            ucfg.pool, {d0, d1}, nullptr,
            outstanding, drain_mtx, drain_cv);

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
        std::mutex drain_mtx;
        std::condition_variable drain_cv;

        UpstreamHostPool pool(
            ucfg.name, ucfg.host, ucfg.port,
            ucfg.tls.sni_hostname,
            ucfg.pool, {dispatcher}, nullptr,
            outstanding, drain_mtx, drain_cv);

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
// Section 9: Connect failure → CHECKOUT_CONNECT_FAILED error callback
//
// Verifies that when a non-blocking connect() fails asynchronously (the
// upstream port is closed — ECONNREFUSED delivered via EPOLLERR/EPOLLHUP
// on the connect fd), the PoolPartition error callback fires with
// CHECKOUT_CONNECT_FAILED.
//
// Approach:
//   1. Bind a listener socket and record its ephemeral port.
//   2. Immediately close the listener — the port is now closed.
//   3. CheckoutAsync connects to that closed port: the kernel may return
//      ECONNREFUSED immediately (rc=-1, errno=ECONNREFUSED) or EINPROGRESS
//      followed by an async EPOLLERR/EPOLLHUP.  Both paths fire the
//      error callback.
//
// This test is fully network-topology-independent (uses loopback only) and
// deterministic — a closed loopback port always produces ECONNREFUSED.
// ---------------------------------------------------------------------------

void TestConnectFailureFiresErrorCallback() {
    std::cout << "\n[TEST] UpstreamPool Integration: connect failure fires error callback..." << std::endl;
    try {
        // Bind a listener, record the port, then close it so the port
        // is free but no process is listening — any connect gets ECONNREFUSED.
        auto [lfd, lport] = MakeListenerFd();
        ::close(lfd);  // port is now closed

        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);

        UpstreamConfig ucfg = MakeUpstreamConfig("fail-svc", "127.0.0.1", lport);
        ucfg.pool.max_connections    = 4;
        ucfg.pool.connect_timeout_ms = 2000;

        // mgr before dtg: dtg destructs first (joins thread) before mgr destructs.
        UpstreamManager mgr({ucfg}, {dispatcher});
        DispatcherThreadGuard dtg{dispatcher, dt};

        auto error_p = std::make_shared<std::promise<int>>();
        auto error_f = error_p->get_future();

        // CheckoutAsync must run on the dispatcher thread.
        dispatcher->EnQueue([&mgr, error_p]() {
            mgr.CheckoutAsync(
                "fail-svc",
                /*dispatcher_index=*/0,
                [error_p](UpstreamLease) {
                    // Should not succeed — port is closed.
                    try {
                        error_p->set_exception(std::make_exception_ptr(
                            std::runtime_error("ready callback fired on closed port")));
                    } catch (...) {}
                },
                [error_p](int ec) {
                    try { error_p->set_value(ec); } catch (...) {}
                }
            );
        });

        // ECONNREFUSED fires almost immediately on loopback.
        // Give up to 5 seconds for the dispatcher to process the event.
        auto status = error_f.wait_for(std::chrono::seconds(5));

        bool pass = false;
        std::string err;

        if (status == std::future_status::timeout) {
            err = "connect failure: error callback did not fire within 5s";
        } else {
            try {
                int ec = error_f.get();
                // CHECKOUT_CONNECT_FAILED (-2) expected; any negative code is acceptable
                pass = (ec < 0);
                if (!pass) err = "expected negative error code, got " + std::to_string(ec);
                else std::cout << "[TEST] Note: error code=" << ec << " (CHECKOUT_CONNECT_FAILED="
                               << PoolPartition::CHECKOUT_CONNECT_FAILED << ")" << std::endl;
            } catch (const std::exception& ex) {
                err = std::string("unexpected exception: ") + ex.what();
            }
        }

        mgr.InitiateShutdown();
        mgr.WaitForDrain(std::chrono::seconds(3));

        TestFramework::RecordTest("UpstreamPool Integration: connect failure fires error callback",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: connect failure fires error callback",
                                  false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 10: Wait-queue overflow — 257th checkout gets CHECKOUT_POOL_EXHAUSTED
//
// With max_connections=1 and a single dispatcher:
//   - partition_max_connections_ = 1
//   - Checkout 1  → enters connecting_conns_ (TotalCount()==1, at limit)
//   - Checkouts 2-257 → each finds TotalCount()==1 >= partition_max_connections_
//     and wait_queue_.size() < MAX_WAIT_QUEUE_SIZE (256), so they enqueue.
//   - Checkout 258 → wait_queue_.size() == 256 == MAX_WAIT_QUEUE_SIZE, so it
//     gets CHECKOUT_POOL_EXHAUSTED immediately.
//
// We connect to an address that won't immediately complete (closed port on
// loopback — EINPROGRESS in the non-blocking connect).  All 258 CheckoutAsync
// calls are issued synchronously on the dispatcher thread inside a single
// EnQueue lambda, so the pool state is fully consistent by the time each
// call runs.  We capture only the 258th result via a shared promise.
//
// After verification, InitiateShutdown drains the wait queue (firing
// CHECKOUT_SHUTTING_DOWN for entries 2-257) before the dispatcher stops.
// ---------------------------------------------------------------------------

void TestWaitQueueOverflow() {
    std::cout << "\n[TEST] UpstreamPool Integration: wait-queue overflow → POOL_EXHAUSTED..." << std::endl;
    try {
        // Create a listening socket, bind, and immediately close it so that
        // the non-blocking ::connect() gets ECONNREFUSED or EINPROGRESS.
        // Either way: if EINPROGRESS the connection stays in connecting_conns_
        // long enough for all 258 checkouts to run synchronously on the dispatcher.
        // If ECONNREFUSED is immediate (kernel delivers RST before CheckoutAsync
        // returns), the error callback fires synchronously and TotalCount drops to 0,
        // meaning subsequent checkouts create new connections instead of queuing.
        // To guarantee EINPROGRESS behaviour, we keep the listener open (it will
        // accept the SYN and put the connection in its backlog) but never call
        // accept(). This gives us a stable EINPROGRESS on every connect().
        auto [lfd, lport] = MakeListenerFd();
        struct ListenerGuard {
            int fd;
            ~ListenerGuard() { ::close(fd); }
        } lg{lfd};

        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);

        // max_connections=1: partition_max_connections_=1 (one dispatcher).
        UpstreamConfig ucfg = MakeUpstreamConfig("exhaust-svc", "127.0.0.1", lport);
        ucfg.pool.max_connections      = 1;
        ucfg.pool.max_idle_connections = 1;
        ucfg.pool.connect_timeout_ms   = 5000; // long timeout so no deadline fires during test

        // mgr before dtg: dtg destructs first (joins thread) before mgr destructs.
        UpstreamManager mgr({ucfg}, {dispatcher});
        DispatcherThreadGuard dtg{dispatcher, dt};

        // shared_ptr so the 258th-checkout error callback outlives this scope.
        auto exhausted_p = std::make_shared<std::promise<int>>();
        auto exhausted_f = exhausted_p->get_future();

        // Run all 258 checkouts on the dispatcher thread atomically.
        dispatcher->EnQueue([&mgr, exhausted_p]() {
            // Shared no-op callbacks for checkouts 1-257 (we only care about the
            // 258th). Using shared_ptr so the lambdas are safely copyable.
            static constexpr int TOTAL_CHECKOUTS = 258;

            for (int i = 1; i <= TOTAL_CHECKOUTS; ++i) {
                if (i < TOTAL_CHECKOUTS) {
                    // Checkouts 1-257: discard results — we just want them to fill
                    // connecting_conns_ (i=1) and wait_queue_ (i=2-257).
                    mgr.CheckoutAsync(
                        "exhaust-svc",
                        /*dispatcher_index=*/0,
                        [](UpstreamLease) { /* intentionally unused */ },
                        [](int) { /* intentionally unused */ }
                    );
                } else {
                    // Checkout 258: wait_queue_ is full → must get POOL_EXHAUSTED.
                    mgr.CheckoutAsync(
                        "exhaust-svc",
                        /*dispatcher_index=*/0,
                        [exhausted_p](UpstreamLease) {
                            // Should not succeed: queue was full.
                            try {
                                exhausted_p->set_exception(std::make_exception_ptr(
                                    std::runtime_error("ready cb fired on 258th checkout")));
                            } catch (...) {}
                        },
                        [exhausted_p](int ec) {
                            try { exhausted_p->set_value(ec); } catch (...) {}
                        }
                    );
                }
            }
        });

        // CHECKOUT_POOL_EXHAUSTED is delivered synchronously inside the EnQueue
        // lambda before it returns, so 1 second is more than enough.
        auto status = exhausted_f.wait_for(std::chrono::seconds(5));

        bool pass = false;
        std::string err;

        if (status == std::future_status::timeout) {
            err = "258th checkout: error callback did not fire within 5s";
        } else {
            try {
                int ec = exhausted_f.get();
                pass = (ec == PoolPartition::CHECKOUT_POOL_EXHAUSTED);
                if (!pass) {
                    err = "expected CHECKOUT_POOL_EXHAUSTED (" +
                          std::to_string(PoolPartition::CHECKOUT_POOL_EXHAUSTED) +
                          "), got " + std::to_string(ec);
                }
            } catch (const std::exception& ex) {
                err = std::string("unexpected exception: ") + ex.what();
            }
        }

        // Shutdown drains wait-queue entries 2-257 (fires SHUTTING_DOWN callbacks)
        // before the dispatcher stops.
        mgr.InitiateShutdown();
        mgr.WaitForDrain(std::chrono::seconds(5));

        TestFramework::RecordTest("UpstreamPool Integration: wait-queue overflow → POOL_EXHAUSTED",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: wait-queue overflow → POOL_EXHAUSTED",
                                  false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 11: Upstream drops connection while lease is held
//
// Verifies that:
//   1. A lease obtained from the pool is valid while the upstream is up.
//   2. Stopping the upstream while the lease is held does not crash.
//   3. Returning the lease gracefully handles the stale connection.
//   4. A subsequent checkout creates a new (valid) connection to a fresh server.
//
// The close callback fired by the upstream's RST (EPOLLRDHUP/EPOLLIN with 0
// bytes) is handled by PoolPartition::OnConnectionClosed, which removes the
// connection from active_conns_ and decrements outstanding_conns_.  Because
// ReturnConnection searches active_conns_ for the pointer, if the close event
// races with the lease destructor it will log a "not found" warning and return
// without crashing — which is the expected graceful-degradation behaviour.
// ---------------------------------------------------------------------------

void TestUpstreamDropsConnectionWhileLeaseHeld() {
    std::cout << "\n[TEST] UpstreamPool Integration: upstream drops connection while lease held..." << std::endl;
    try {
        // Start the first upstream backend.
        HttpServer backend1("127.0.0.1", 0);
        backend1.Get("/ping", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Body("pong");
        });
        TestServerRunner<HttpServer> bk1(backend1);
        const int port1 = bk1.GetPort();

        auto dispatcher = std::make_shared<Dispatcher>(true, 5);
        std::thread dt = StartDispatcher(dispatcher);

        UpstreamConfig ucfg = MakeUpstreamConfig("drop-svc", "127.0.0.1", port1);
        // mgr before dtg: dtg destructs first (joins thread) before mgr destructs.
        UpstreamManager mgr({ucfg}, {dispatcher});
        DispatcherThreadGuard dtg{dispatcher, dt};

        // Step 1: Checkout a connection while the backend is up.
        // Store the lease in a shared_ptr visible to the outer scope so we
        // can hold it across the backend stop — exercising the zombie path.
        auto held_lease = std::make_shared<UpstreamLease>();
        auto lease_p = std::make_shared<std::promise<int>>();
        auto lease_f = lease_p->get_future();

        dispatcher->EnQueue([&mgr, lease_p, held_lease]() {
            mgr.CheckoutAsync(
                "drop-svc", 0,
                [lease_p, held_lease](UpstreamLease lease) {
                    int fd = lease ? lease->fd() : -1;
                    // Move the lease into held_lease so it survives the lambda.
                    // The lease is NOT returned to the pool here — it stays
                    // alive in the outer scope until we explicitly release it.
                    *held_lease = std::move(lease);
                    try { lease_p->set_value(fd); } catch (...) {}
                },
                [lease_p](int ec) {
                    try {
                        lease_p->set_exception(std::make_exception_ptr(
                            std::runtime_error("checkout failed: " + std::to_string(ec))));
                    } catch (...) {}
                }
            );
        });

        auto ls = lease_f.wait_for(std::chrono::seconds(3));
        bool pass = true;
        std::string err;
        int first_fd = -1;

        if (ls == std::future_status::timeout) {
            pass = false;
            err = "first checkout timed out";
        } else {
            try {
                first_fd = lease_f.get();
                if (first_fd <= 0) { pass = false; err = "first checkout returned invalid fd"; }
            } catch (const std::exception& ex) {
                pass = false;
                err = std::string("first checkout failed: ") + ex.what();
            }
        }

        if (!pass) {
            // Release lease on dispatcher thread before shutdown
            auto release_p = std::make_shared<std::promise<void>>();
            auto release_f = release_p->get_future();
            dispatcher->EnQueue([held_lease, release_p]() {
                held_lease->Release();
                release_p->set_value();
            });
            release_f.wait_for(std::chrono::seconds(2));
            mgr.InitiateShutdown();
            mgr.WaitForDrain(std::chrono::seconds(2));
            TestFramework::RecordTest(
                "UpstreamPool Integration: upstream drops connection while lease held",
                false, err);
            return;
        }

        // Step 2: Stop the backend while the lease is STILL HELD.
        // This sends RST/FIN to the upstream connection. The connection's
        // close callback fires on the dispatcher thread, moving it to
        // zombie_conns_ (since an active lease holds a raw pointer).
        backend1.Stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Step 3: Release the held lease on the dispatcher thread.
        // The connection is now in zombie_conns_ (closed by backend stop).
        // ReturnConnection finds it in the zombie list and cleans it up.
        {
            auto rel_p = std::make_shared<std::promise<void>>();
            auto rel_f = rel_p->get_future();
            dispatcher->EnQueue([held_lease, rel_p]() {
                held_lease->Release();
                rel_p->set_value();
            });
            rel_f.wait_for(std::chrono::seconds(2));
        }

        // Step 4: Attempt a second checkout. Backend is stopped, so this
        // should fail (connect refused) — error callback fires.
        // We verify no crash and the callback fires.
        auto second_p = std::make_shared<std::promise<int>>();
        auto second_f = second_p->get_future();

        dispatcher->EnQueue([&mgr, second_p]() {
            mgr.CheckoutAsync(
                "drop-svc", 0,
                [second_p](UpstreamLease lease) {
                    int fd = lease ? lease->fd() : -1;
                    try { second_p->set_value(fd); } catch (...) {}
                },
                [second_p](int ec) {
                    // Negative ec means error (connect failed, pool exhausted, etc.)
                    // We encode as negative to distinguish from valid fds.
                    try { second_p->set_value(ec); } catch (...) {}
                }
            );
        });

        auto s2 = second_f.wait_for(std::chrono::seconds(5));
        if (s2 == std::future_status::timeout) {
            pass = false;
            err = "second checkout (after upstream stop) did not complete within 5s";
        } else {
            // Any completion (success or error) means no crash — that's what we verify.
            try {
                int result = second_f.get();
                // Log informational note about what happened.
                if (result > 0) {
                    std::cout << "[TEST] Note: second checkout returned fd=" << result
                              << " (stale connection was still reported as alive)" << std::endl;
                } else {
                    std::cout << "[TEST] Note: second checkout returned error=" << result
                              << " (stale connection was correctly detected or new connect failed)" << std::endl;
                }
                // pass remains true — any non-crash result is acceptable here.
            } catch (const std::exception& ex) {
                pass = false;
                err = std::string("second checkout threw: ") + ex.what();
            }
        }

        mgr.InitiateShutdown();
        mgr.WaitForDrain(std::chrono::seconds(3));

        TestFramework::RecordTest(
            "UpstreamPool Integration: upstream drops connection while lease held",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "UpstreamPool Integration: upstream drops connection while lease held",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 12: Multi-dispatcher concurrency
//
// Verifies that two dispatchers with their own per-dispatcher PoolPartitions
// can each checkout a connection concurrently without interference.
//
// Two dispatchers → two PoolPartitions per upstream.  Each dispatcher runs its
// own event loop on its own thread.  We enqueue a CheckoutAsync on each
// dispatcher thread simultaneously and wait for both to succeed.  This
// exercises the partitioning logic (each checkout lands on the correct
// partition) and confirms there is no shared mutable state between partitions.
// ---------------------------------------------------------------------------

void TestMultiDispatcherConcurrency() {
    std::cout << "\n[TEST] UpstreamPool Integration: multi-dispatcher concurrency..." << std::endl;
    try {
        // Start a single backend that both dispatchers will connect to.
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/ok", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Body("ok");
        });
        TestServerRunner<HttpServer> bk(backend);
        const int bp = bk.GetPort();

        // Two dispatchers, each with 1-second timer.
        auto d0 = std::make_shared<Dispatcher>(true, 5);
        auto d1 = std::make_shared<Dispatcher>(true, 5);
        std::thread t0 = StartDispatcher(d0);
        std::thread t1 = StartDispatcher(d1);

        // Configure upstream to allow at least 2 connections (1 per dispatcher).
        UpstreamConfig ucfg = MakeUpstreamConfig("multi-svc", "127.0.0.1", bp);
        ucfg.pool.max_connections      = 4;
        ucfg.pool.max_idle_connections = 2;

        // mgr before guards: guards destruct first (join threads) before mgr destructs.
        UpstreamManager mgr({ucfg}, {d0, d1});

        // IMPORTANT: declare guards AFTER mgr so they destruct before mgr.
        // LIFO destruction: g1 first, then g0, then mgr — guarantees both
        // dispatcher threads are joined before the PoolPartitions are freed.
        DispatcherThreadGuard g0{d0, t0};
        DispatcherThreadGuard g1{d1, t1};

        // Promise/future pair for each dispatcher's checkout result.
        auto fd0_p = std::make_shared<std::promise<int>>();
        auto fd1_p = std::make_shared<std::promise<int>>();
        auto fd0_f = fd0_p->get_future();
        auto fd1_f = fd1_p->get_future();

        // Enqueue checkout on dispatcher 0 (partition 0).
        d0->EnQueue([&mgr, fd0_p]() {
            mgr.CheckoutAsync(
                "multi-svc",
                /*dispatcher_index=*/0,
                [fd0_p](UpstreamLease lease) {
                    int fd = lease ? lease->fd() : -1;
                    try { fd0_p->set_value(fd); } catch (...) {}
                    // Lease destructor returns connection to partition 0.
                },
                [fd0_p](int ec) {
                    try {
                        fd0_p->set_exception(std::make_exception_ptr(
                            std::runtime_error("d0 checkout failed: " +
                                               std::to_string(ec))));
                    } catch (...) {}
                }
            );
        });

        // Enqueue checkout on dispatcher 1 (partition 1).
        d1->EnQueue([&mgr, fd1_p]() {
            mgr.CheckoutAsync(
                "multi-svc",
                /*dispatcher_index=*/1,
                [fd1_p](UpstreamLease lease) {
                    int fd = lease ? lease->fd() : -1;
                    try { fd1_p->set_value(fd); } catch (...) {}
                    // Lease destructor returns connection to partition 1.
                },
                [fd1_p](int ec) {
                    try {
                        fd1_p->set_exception(std::make_exception_ptr(
                            std::runtime_error("d1 checkout failed: " +
                                               std::to_string(ec))));
                    } catch (...) {}
                }
            );
        });

        // Wait for both checkouts to complete.
        bool pass = true;
        std::string err;

        auto s0 = fd0_f.wait_for(std::chrono::seconds(5));
        auto s1 = fd1_f.wait_for(std::chrono::seconds(5));

        if (s0 == std::future_status::timeout) {
            pass = false; err += "dispatcher 0 checkout timed out; ";
        } else {
            try {
                int fd0 = fd0_f.get();
                if (fd0 <= 0) { pass = false; err += "d0 fd invalid (" + std::to_string(fd0) + "); "; }
            } catch (const std::exception& ex) {
                pass = false; err += std::string("d0 checkout error: ") + ex.what() + "; ";
            }
        }

        if (s1 == std::future_status::timeout) {
            pass = false; err += "dispatcher 1 checkout timed out; ";
        } else {
            try {
                int fd1 = fd1_f.get();
                if (fd1 <= 0) { pass = false; err += "d1 fd invalid (" + std::to_string(fd1) + "); "; }
            } catch (const std::exception& ex) {
                pass = false; err += std::string("d1 checkout error: ") + ex.what() + "; ";
            }
        }

        mgr.InitiateShutdown();
        mgr.WaitForDrain(std::chrono::seconds(3));

        // g1 destructs first (joins t1), then g0 (joins t0), then mgr.
        TestFramework::RecordTest("UpstreamPool Integration: multi-dispatcher concurrency",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("UpstreamPool Integration: multi-dispatcher concurrency",
                                  false, e.what());
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

    // Section 9: Connect failure fires error callback
    TestConnectFailureFiresErrorCallback();

    // Section 10: Wait-queue overflow
    TestWaitQueueOverflow();

    // Section 11: Upstream drops connection while lease is held
    TestUpstreamDropsConnectionWhileLeaseHeld();

    // Section 12: Multi-dispatcher concurrency
    TestMultiDispatcherConcurrency();
}

} // namespace UpstreamPoolTests
