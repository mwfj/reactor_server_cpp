#pragma once

#include "test_framework.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "net/dns_resolver.h"

#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <string>

namespace ConfigTests {

    // Test 1: Verify all default values
    void TestDefaultConfig() {
        std::cout << "\n[TEST] Default Config Values..." << std::endl;

        try {
            ServerConfig config = ConfigLoader::Default();

            bool pass = true;
            std::string err;

            if (config.bind_host != "127.0.0.1") {
                pass = false; err += "bind_host != 127.0.0.1; ";
            }
            if (config.bind_port != 8080) {
                pass = false; err += "bind_port != 8080; ";
            }
            if (config.tls.enabled != false) {
                pass = false; err += "tls.enabled != false; ";
            }
            if (config.tls.min_version != "1.2") {
                pass = false; err += "tls.min_version != 1.2; ";
            }
            if (config.log.level != "info") {
                pass = false; err += "log.level != info; ";
            }
            if (config.log.max_file_size != 10485760) {
                pass = false; err += "log.max_file_size != 10485760; ";
            }
            if (config.log.max_files != 3) {
                pass = false; err += "log.max_files != 3; ";
            }
            if (config.max_connections != 10000) {
                pass = false; err += "max_connections != 10000; ";
            }
            if (config.idle_timeout_sec != 300) {
                pass = false; err += "idle_timeout_sec != 300; ";
            }
            if (config.worker_threads != 3) {
                pass = false; err += "worker_threads != 3; ";
            }
            if (config.max_header_size != 8192) {
                pass = false; err += "max_header_size != 8192; ";
            }
            if (config.max_body_size != 1048576) {
                pass = false; err += "max_body_size != 1048576; ";
            }
            if (config.max_ws_message_size != 16777216) {
                pass = false; err += "max_ws_message_size != 16777216; ";
            }
            if (config.request_timeout_sec != 30) {
                pass = false; err += "request_timeout_sec != 30; ";
            }

            TestFramework::RecordTest("Default Config Values", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Default Config Values", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 2: Load from JSON string with all fields
    void TestLoadFromString() {
        std::cout << "\n[TEST] Load Config From String..." << std::endl;

        try {
            std::string json_str = R"({
                "bind_host": "0.0.0.0",
                "bind_port": 9090,
                "max_connections": 5000,
                "idle_timeout_sec": 120,
                "worker_threads": 8,
                "max_header_size": 4096,
                "max_body_size": 2097152,
                "max_ws_message_size": 8388608,
                "request_timeout_sec": 60,
                "tls": {
                    "enabled": true,
                    "cert_file": "/path/to/cert.pem",
                    "key_file": "/path/to/key.pem",
                    "min_version": "1.3"
                },
                "log": {
                    "level": "debug",
                    "file": "/var/log/reactor.log",
                    "max_file_size": 5242880,
                    "max_files": 5
                }
            })";

            ServerConfig config = ConfigLoader::LoadFromString(json_str);

            bool pass = true;
            std::string err;

            if (config.bind_host != "0.0.0.0") {
                pass = false; err += "bind_host mismatch; ";
            }
            if (config.bind_port != 9090) {
                pass = false; err += "bind_port mismatch; ";
            }
            if (config.max_connections != 5000) {
                pass = false; err += "max_connections mismatch; ";
            }
            if (config.idle_timeout_sec != 120) {
                pass = false; err += "idle_timeout_sec mismatch; ";
            }
            if (config.worker_threads != 8) {
                pass = false; err += "worker_threads mismatch; ";
            }
            if (config.max_header_size != 4096) {
                pass = false; err += "max_header_size mismatch; ";
            }
            if (config.max_body_size != 2097152) {
                pass = false; err += "max_body_size mismatch; ";
            }
            if (config.max_ws_message_size != 8388608) {
                pass = false; err += "max_ws_message_size mismatch; ";
            }
            if (config.request_timeout_sec != 60) {
                pass = false; err += "request_timeout_sec mismatch; ";
            }
            if (!config.tls.enabled) {
                pass = false; err += "tls.enabled mismatch; ";
            }
            if (config.tls.cert_file != "/path/to/cert.pem") {
                pass = false; err += "tls.cert_file mismatch; ";
            }
            if (config.tls.key_file != "/path/to/key.pem") {
                pass = false; err += "tls.key_file mismatch; ";
            }
            if (config.tls.min_version != "1.3") {
                pass = false; err += "tls.min_version mismatch; ";
            }
            if (config.log.level != "debug") {
                pass = false; err += "log.level mismatch; ";
            }
            if (config.log.file != "/var/log/reactor.log") {
                pass = false; err += "log.file mismatch; ";
            }
            if (config.log.max_file_size != 5242880) {
                pass = false; err += "log.max_file_size mismatch; ";
            }
            if (config.log.max_files != 5) {
                pass = false; err += "log.max_files mismatch; ";
            }

            TestFramework::RecordTest("Load Config From String", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Load Config From String", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 3: Load from file
    void TestLoadFromFile() {
        std::cout << "\n[TEST] Load Config From File..." << std::endl;

        const char* tmp_path = "/tmp/reactor_test_config.json";

        try {
            // Write temp config file
            {
                std::ofstream out(tmp_path);
                out << R"({
                    "bind_host": "192.168.1.1",
                    "bind_port": 3000,
                    "worker_threads": 4
                })";
            }

            ServerConfig config = ConfigLoader::LoadFromFile(tmp_path);

            bool pass = true;
            std::string err;

            if (config.bind_host != "192.168.1.1") {
                pass = false; err += "bind_host mismatch; ";
            }
            if (config.bind_port != 3000) {
                pass = false; err += "bind_port mismatch; ";
            }
            if (config.worker_threads != 4) {
                pass = false; err += "worker_threads mismatch; ";
            }
            // Missing fields should use defaults
            if (config.max_connections != 10000) {
                pass = false; err += "max_connections should be default 10000; ";
            }

            // Clean up
            std::remove(tmp_path);

            TestFramework::RecordTest("Load Config From File", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            std::remove(tmp_path);
            TestFramework::RecordTest("Load Config From File", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 4: Invalid JSON should throw
    void TestInvalidJson() {
        std::cout << "\n[TEST] Invalid JSON Detection..." << std::endl;

        try {
            ConfigLoader::LoadFromString("{invalid json content");
            // Should not reach here
            TestFramework::RecordTest("Invalid JSON Detection", false,
                "Expected exception for invalid JSON", TestFramework::TestCategory::OTHER);
        } catch (const std::runtime_error&) {
            TestFramework::RecordTest("Invalid JSON Detection", true, "", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Invalid JSON Detection", false,
                std::string("Wrong exception type: ") + e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 5: Validation - invalid port
    void TestValidationInvalidPort() {
        std::cout << "\n[TEST] Validation Invalid Port..." << std::endl;

        try {
            ServerConfig config;
            config.bind_port = -1;
            ConfigLoader::Validate(config);
            // Should not reach here
            TestFramework::RecordTest("Validation Invalid Port", false,
                "Expected exception for port -1", TestFramework::TestCategory::OTHER);
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("Validation Invalid Port", true, "", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Validation Invalid Port", false,
                std::string("Wrong exception type: ") + e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 6: Validation - TLS enabled with no cert
    void TestValidationTlsNoCert() {
        std::cout << "\n[TEST] Validation TLS No Cert..." << std::endl;

        try {
            ServerConfig config;
            config.tls.enabled = true;
            config.tls.cert_file = "";
            config.tls.key_file = "/path/to/key.pem";
            ConfigLoader::Validate(config);
            // Should not reach here
            TestFramework::RecordTest("Validation TLS No Cert", false,
                "Expected exception for empty cert_file", TestFramework::TestCategory::OTHER);
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("Validation TLS No Cert", true, "", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Validation TLS No Cert", false,
                std::string("Wrong exception type: ") + e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 7: Environment variable overrides
    void TestEnvOverrides() {
        std::cout << "\n[TEST] Environment Variable Overrides..." << std::endl;

        try {
            // Set environment variables
            setenv("REACTOR_BIND_PORT", "4444", 1);
            setenv("REACTOR_BIND_HOST", "10.0.0.1", 1);
            setenv("REACTOR_WORKER_THREADS", "16", 1);
            setenv("REACTOR_TLS_ENABLED", "true", 1);
            setenv("REACTOR_TLS_CERT", "/env/cert.pem", 1);
            setenv("REACTOR_TLS_KEY", "/env/key.pem", 1);
            setenv("REACTOR_LOG_LEVEL", "warn", 1);

            ServerConfig config = ConfigLoader::Default();
            ConfigLoader::ApplyEnvOverrides(config);

            bool pass = true;
            std::string err;

            if (config.bind_port != 4444) {
                pass = false; err += "bind_port not overridden; ";
            }
            if (config.bind_host != "10.0.0.1") {
                pass = false; err += "bind_host not overridden; ";
            }
            if (config.worker_threads != 16) {
                pass = false; err += "worker_threads not overridden; ";
            }
            if (!config.tls.enabled) {
                pass = false; err += "tls.enabled not overridden; ";
            }
            if (config.tls.cert_file != "/env/cert.pem") {
                pass = false; err += "tls.cert_file not overridden; ";
            }
            if (config.tls.key_file != "/env/key.pem") {
                pass = false; err += "tls.key_file not overridden; ";
            }
            if (config.log.level != "warn") {
                pass = false; err += "log.level not overridden; ";
            }

            // Clean up environment variables
            unsetenv("REACTOR_BIND_PORT");
            unsetenv("REACTOR_BIND_HOST");
            unsetenv("REACTOR_WORKER_THREADS");
            unsetenv("REACTOR_TLS_ENABLED");
            unsetenv("REACTOR_TLS_CERT");
            unsetenv("REACTOR_TLS_KEY");
            unsetenv("REACTOR_LOG_LEVEL");

            TestFramework::RecordTest("Environment Variable Overrides", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            // Clean up even on error
            unsetenv("REACTOR_BIND_PORT");
            unsetenv("REACTOR_BIND_HOST");
            unsetenv("REACTOR_WORKER_THREADS");
            unsetenv("REACTOR_TLS_ENABLED");
            unsetenv("REACTOR_TLS_CERT");
            unsetenv("REACTOR_TLS_KEY");
            unsetenv("REACTOR_LOG_LEVEL");
            TestFramework::RecordTest("Environment Variable Overrides", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 8: Missing file should throw
    void TestMissingFile() {
        std::cout << "\n[TEST] Missing Config File..." << std::endl;

        try {
            ConfigLoader::LoadFromFile("/nonexistent/path/config.json");
            // Should not reach here
            TestFramework::RecordTest("Missing Config File", false,
                "Expected exception for missing file", TestFramework::TestCategory::OTHER);
        } catch (const std::runtime_error&) {
            TestFramework::RecordTest("Missing Config File", true, "", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Missing Config File", false,
                std::string("Wrong exception type: ") + e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 9: Circuit breaker defaults
    void TestCircuitBreakerDefaults() {
        std::cout << "\n[TEST] Circuit Breaker Defaults..." << std::endl;
        try {
            CircuitBreakerConfig cb;   // value-initialized defaults
            bool pass = cb.enabled == false &&
                        cb.dry_run == false &&
                        cb.consecutive_failure_threshold == 5 &&
                        cb.failure_rate_threshold == 50 &&
                        cb.minimum_volume == 20 &&
                        cb.window_seconds == 10 &&
                        cb.permitted_half_open_calls == 5 &&
                        cb.base_open_duration_ms == 5000 &&
                        cb.max_open_duration_ms == 60000 &&
                        cb.max_ejection_percent_per_host_set == 50 &&
                        cb.retry_budget_percent == 20 &&
                        cb.retry_budget_min_concurrency == 3;
            TestFramework::RecordTest("Circuit Breaker Defaults", pass,
                pass ? "" : "default value mismatch",
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Circuit Breaker Defaults", false, e.what(),
                TestFramework::TestCategory::OTHER);
        }
    }

    // Test 10: Circuit breaker JSON parsing (populated block)
    void TestCircuitBreakerJsonParse() {
        std::cout << "\n[TEST] Circuit Breaker JSON Parse..." << std::endl;
        try {
            std::string json = R"({
                "upstreams": [{
                    "name": "svc",
                    "host": "10.0.0.1",
                    "port": 8080,
                    "circuit_breaker": {
                        "enabled": true,
                        "dry_run": true,
                        "consecutive_failure_threshold": 7,
                        "failure_rate_threshold": 75,
                        "minimum_volume": 50,
                        "window_seconds": 30,
                        "permitted_half_open_calls": 3,
                        "base_open_duration_ms": 2000,
                        "max_open_duration_ms": 120000,
                        "max_ejection_percent_per_host_set": 33,
                        "retry_budget_percent": 10,
                        "retry_budget_min_concurrency": 5
                    }
                }]
            })";
            ServerConfig config = ConfigLoader::LoadFromString(json);
            const auto& cb = config.upstreams.at(0).circuit_breaker;
            bool pass = cb.enabled == true && cb.dry_run == true &&
                        cb.consecutive_failure_threshold == 7 &&
                        cb.failure_rate_threshold == 75 &&
                        cb.minimum_volume == 50 &&
                        cb.window_seconds == 30 &&
                        cb.permitted_half_open_calls == 3 &&
                        cb.base_open_duration_ms == 2000 &&
                        cb.max_open_duration_ms == 120000 &&
                        cb.max_ejection_percent_per_host_set == 33 &&
                        cb.retry_budget_percent == 10 &&
                        cb.retry_budget_min_concurrency == 5;
            TestFramework::RecordTest("Circuit Breaker JSON Parse", pass,
                pass ? "" : "parsed values mismatch",
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Circuit Breaker JSON Parse", false, e.what(),
                TestFramework::TestCategory::OTHER);
        }
    }

    // Test 11: Circuit breaker JSON partial block uses defaults for missing fields
    void TestCircuitBreakerJsonPartial() {
        std::cout << "\n[TEST] Circuit Breaker JSON Partial..." << std::endl;
        try {
            std::string json = R"({
                "upstreams": [{
                    "name": "svc", "host": "10.0.0.1", "port": 8080,
                    "circuit_breaker": {"enabled": true}
                }]
            })";
            ServerConfig config = ConfigLoader::LoadFromString(json);
            const auto& cb = config.upstreams.at(0).circuit_breaker;
            bool pass = cb.enabled == true &&
                        cb.consecutive_failure_threshold == 5 &&
                        cb.window_seconds == 10;
            TestFramework::RecordTest("Circuit Breaker JSON Partial", pass,
                pass ? "" : "expected defaults for unset fields",
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Circuit Breaker JSON Partial", false, e.what(),
                TestFramework::TestCategory::OTHER);
        }
    }

    // Test 12: Round-trip via ToJson() preserves circuit_breaker
    void TestCircuitBreakerJsonRoundTrip() {
        std::cout << "\n[TEST] Circuit Breaker JSON Round-Trip..." << std::endl;
        try {
            ServerConfig in;
            UpstreamConfig u;
            u.name = "svc"; u.host = "10.0.0.1"; u.port = 8080;
            u.circuit_breaker.enabled = true;
            u.circuit_breaker.window_seconds = 25;
            u.circuit_breaker.failure_rate_threshold = 42;
            in.upstreams.push_back(u);

            std::string serialized = ConfigLoader::ToJson(in);
            ServerConfig out = ConfigLoader::LoadFromString(serialized);

            const auto& cb = out.upstreams.at(0).circuit_breaker;
            bool pass = cb.enabled == true && cb.window_seconds == 25 &&
                        cb.failure_rate_threshold == 42;
            TestFramework::RecordTest("Circuit Breaker JSON Round-Trip", pass,
                pass ? "" : "round-trip lost fields",
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Circuit Breaker JSON Round-Trip", false,
                e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Helper: assert a circuit_breaker JSON override is rejected by Validate().
    static void ExpectValidationFailure(const std::string& name,
                                        const std::string& cb_json_override,
                                        const std::string& expected_substr) {
        std::string json = std::string(R"({
            "upstreams": [{
                "name": "svc", "host": "10.0.0.1", "port": 8080,
                "circuit_breaker": )") + cb_json_override + R"(
            }]
        })";
        try {
            ServerConfig config = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(config);
            TestFramework::RecordTest(name, false,
                "expected validation failure containing: " + expected_substr,
                TestFramework::TestCategory::OTHER);
        } catch (const std::invalid_argument& e) {
            std::string msg(e.what());
            bool pass = msg.find(expected_substr) != std::string::npos;
            TestFramework::RecordTest(name, pass,
                pass ? "" : std::string("wrong error: ") + msg,
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(name, false,
                std::string("wrong exception type: ") + e.what(),
                TestFramework::TestCategory::OTHER);
        }
    }

    // Test 13: Validation rejects bad circuit_breaker fields
    void TestCircuitBreakerValidation() {
        std::cout << "\n[TEST] Circuit Breaker Validation..." << std::endl;
        ExpectValidationFailure("CB Validation: consecutive_failure_threshold<1",
            R"({"consecutive_failure_threshold": 0})",
            "consecutive_failure_threshold must be in [1, 10000]");
        ExpectValidationFailure("CB Validation: failure_rate_threshold>100",
            R"({"failure_rate_threshold": 101})",
            "failure_rate_threshold must be in [0, 100]");
        ExpectValidationFailure("CB Validation: minimum_volume<1",
            R"({"minimum_volume": 0})",
            "minimum_volume must be in [1, 10000000]");
        ExpectValidationFailure("CB Validation: window_seconds<1",
            R"({"window_seconds": 0})",
            "window_seconds must be in [1, 3600]");
        ExpectValidationFailure("CB Validation: window_seconds>3600",
            R"({"window_seconds": 3601})",
            "window_seconds must be in [1, 3600]");
        ExpectValidationFailure("CB Validation: base_open_duration_ms<100",
            R"({"base_open_duration_ms": 50})",
            "base_open_duration_ms must be >= 100");
        ExpectValidationFailure("CB Validation: max<base",
            R"({"base_open_duration_ms": 5000, "max_open_duration_ms": 1000})",
            "max_open_duration_ms must be >= base_open_duration_ms");
        ExpectValidationFailure("CB Validation: retry_budget_percent>100",
            R"({"retry_budget_percent": 200})",
            "retry_budget_percent must be in [0, 100]");
        ExpectValidationFailure("CB Validation: retry_budget_min_concurrency<0",
            R"({"retry_budget_min_concurrency": -1})",
            "retry_budget_min_concurrency must be >= 0");
        ExpectValidationFailure("CB Validation: max_ejection_percent>100",
            R"({"max_ejection_percent_per_host_set": 150})",
            "max_ejection_percent_per_host_set must be in [0, 100]");
        ExpectValidationFailure("CB Validation: permitted_half_open_calls<1",
            R"({"permitted_half_open_calls": 0})",
            "permitted_half_open_calls must be in [1, 1000]");
        // Upper-bound regressions — pathological configs must be rejected.
        ExpectValidationFailure("CB Validation: consecutive_failure_threshold>10000",
            R"({"consecutive_failure_threshold": 10001})",
            "consecutive_failure_threshold must be in [1, 10000]");
        ExpectValidationFailure("CB Validation: minimum_volume>10000000",
            R"({"minimum_volume": 10000001})",
            "minimum_volume must be in [1, 10000000]");
        ExpectValidationFailure("CB Validation: permitted_half_open_calls>1000",
            R"({"permitted_half_open_calls": 1001})",
            "permitted_half_open_calls must be in [1, 1000]");
        // Type-strictness guards: nlohmann's value<int>() silently coerces
        // float/bool to int (1.9 → 1, true → 1). Rejecting at parse time is
        // safer than letting malformed configs pass Validate() and change
        // production breaker behavior.
        ExpectValidationFailure("CB Validation: float rejected for int field",
            R"({"window_seconds": 1.9})",
            "circuit_breaker.window_seconds must be an integer");
        ExpectValidationFailure("CB Validation: bool rejected for int field",
            R"({"consecutive_failure_threshold": true})",
            "circuit_breaker.consecutive_failure_threshold must be an integer");
        ExpectValidationFailure("CB Validation: int rejected for bool field",
            R"({"enabled": 1})",
            "circuit_breaker.enabled must be a boolean");
    }

    // UpstreamConfig::operator== EXCLUDES circuit_breaker.
    // CircuitBreakerManager::Reload is wired in HttpServer::Reload, so a
    // CB-only SIGHUP is a clean hot reload. Excluding circuit_breaker from
    // the equality check ensures the outer reload doesn't fire a spurious
    // "restart required" warning on a pure CB-fields edit.
    // Topology fields (name, host, port, tls, pool, proxy) remain
    // restart-only and must still trigger inequality.
    void TestCircuitBreakerEquality() {
        std::cout << "\n[TEST] Circuit Breaker Equality (CB excluded from UpstreamConfig::operator==)..." << std::endl;
        try {
            UpstreamConfig a;
            a.name = "svc"; a.host = "h"; a.port = 80;
            UpstreamConfig b = a;

            // Default equal.
            bool equal_default = (a == b);

            // Circuit-breaker-only edit must NOT break equality — breaker
            // fields are live-reloadable via CircuitBreakerManager::Reload.
            b.circuit_breaker.enabled = true;
            b.circuit_breaker.window_seconds = 30;
            bool cb_edit_invisible = (a == b);

            // CircuitBreakerConfig::operator== still detects the field diff
            // (CircuitBreakerManager::Reload relies on this inner comparison).
            bool cb_fields_differ = (a.circuit_breaker != b.circuit_breaker);

            // Topology changes still make configs unequal.
            UpstreamConfig c = a;
            c.host = "different";
            bool topology_changed = (a != c);

            UpstreamConfig d = a;
            d.port = 9999;
            bool port_change_detected = (a != d);

            bool pass = equal_default && cb_edit_invisible &&
                        cb_fields_differ && topology_changed &&
                        port_change_detected;
            TestFramework::RecordTest("Circuit Breaker Equality (CB excluded from UpstreamConfig::operator==)",
                pass,
                pass ? "" :
                "equal_default=" + std::to_string(equal_default) +
                " cb_edit_invisible=" + std::to_string(cb_edit_invisible) +
                " cb_fields_differ=" + std::to_string(cb_fields_differ) +
                " topology_changed=" + std::to_string(topology_changed) +
                " port_change_detected=" + std::to_string(port_change_detected),
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Circuit Breaker Equality (CB excluded from UpstreamConfig::operator==)",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 6 (ConfigLoader Normalize + DNS) tests — §15.1 row 6
    // ───────────────────────────────────────────────────────────────────

    // Pins the Phase 1 non-goal §1.2.7: scope-id-qualified IPv6 literals
    // (fe80::1%eth0 / fe80::1%5) MUST be rejected by the validation
    // chain. If this ever starts passing, the XFF / rate-limit / ACL
    // assumptions documented in DEVELOPMENT_RULES.md break silently —
    // the test fails loudly so a reintroduction has to be deliberate.
    void TestIsValidRejectsScopeId() {
        std::cout << "\n[TEST] Config: IsValid* / Validate reject scope-id IPv6..."
                  << std::endl;
        try {
            bool pass = true;
            std::string err;

            auto check = [&](const std::string& in) {
                using NET_DNS_NAMESPACE::DnsResolver;
                if (DnsResolver::IsValidHostOrIpLiteral(in)) {
                    pass = false;
                    err += "IsValidHostOrIpLiteral accepted '" + in + "'; ";
                }
                std::string bare;
                if (DnsResolver::NormalizeHostToBare(in, &bare)) {
                    pass = false;
                    err += "NormalizeHostToBare accepted '" + in +
                           "' (→ '" + bare + "'); ";
                }
                // Bracketed form also rejects — strict RFC 3986 §3.2.2.
                const std::string bracketed = "[" + in + "]";
                if (DnsResolver::NormalizeHostToBare(bracketed, &bare)) {
                    pass = false;
                    err += "NormalizeHostToBare accepted '" + bracketed +
                           "' (→ '" + bare + "'); ";
                }

                // End-to-end: full Validate pipeline must reject bind_host
                // carrying the scope-id. This pins the full validation
                // chain, not just the leaf helper.
                ServerConfig cfg = ConfigLoader::Default();
                cfg.bind_host = in;
                bool validated = true;
                try {
                    ConfigLoader::Validate(cfg);
                } catch (const std::invalid_argument&) {
                    validated = false;
                }
                if (validated) {
                    pass = false;
                    err += "Validate accepted bind_host='" + in + "'; ";
                }

                // Same for upstream host.
                cfg = ConfigLoader::Default();
                cfg.upstreams.clear();
                UpstreamConfig u;
                u.name = "api";
                u.host = in;
                u.port = 8080;
                cfg.upstreams.push_back(u);
                validated = true;
                try {
                    ConfigLoader::Validate(cfg);
                } catch (const std::invalid_argument&) {
                    validated = false;
                }
                if (validated) {
                    pass = false;
                    err += "Validate accepted upstream.host='" + in + "'; ";
                }
            };

            check("fe80::1%eth0");
            check("fe80::1%5");
            check("fe80::ab%lo0");
            check("::1%0");

            TestFramework::RecordTest(
                "Config: IsValid* / Validate reject scope-id IPv6",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "Config: IsValid* / Validate reject scope-id IPv6",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Normalize strips surrounding IPv6 brackets from bind_host and
    // upstreams[].host; preserves a single trailing dot on hostnames
    // (absolute-FQDN marker for getaddrinfo search-domain suppression).
    void TestNormalizeBracketStripAndTrailingDot() {
        std::cout << "\n[TEST] Config: Normalize strips brackets + preserves FQDN dot..."
                  << std::endl;
        try {
            bool pass = true;
            std::string err;

            ServerConfig cfg = ConfigLoader::Default();
            cfg.bind_host = "[::1]";
            UpstreamConfig u;
            u.name = "api";
            u.host = "[fe80::1]";
            u.port = 443;
            cfg.upstreams.push_back(u);
            UpstreamConfig u2;
            u2.name = "svc";
            u2.host = "backend.ns.svc.cluster.local.";
            u2.port = 8080;
            cfg.upstreams.push_back(u2);

            ConfigLoader::Normalize(cfg);

            if (cfg.bind_host != "::1") {
                pass = false; err += "bind_host='" + cfg.bind_host + "'; ";
            }
            if (cfg.upstreams[0].host != "fe80::1") {
                pass = false; err += "up0.host='" + cfg.upstreams[0].host + "'; ";
            }
            if (cfg.upstreams[1].host != "backend.ns.svc.cluster.local.") {
                pass = false;
                err += "trailing-dot stripped: up1.host='" + cfg.upstreams[1].host + "'; ";
            }

            // Idempotent — second call must be a no-op.
            ServerConfig cfg2 = cfg;
            ConfigLoader::Normalize(cfg2);
            if (cfg2.bind_host != cfg.bind_host ||
                cfg2.upstreams[0].host != cfg.upstreams[0].host ||
                cfg2.upstreams[1].host != cfg.upstreams[1].host) {
                pass = false; err += "not idempotent; ";
            }

            TestFramework::RecordTest(
                "Config: Normalize strips brackets + preserves FQDN dot",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "Config: Normalize strips brackets + preserves FQDN dot",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Normalize strips ONE trailing dot from tls.sni_hostname. Rejects
    // malformed inputs (".", "api.com..", "....") because the post-strip
    // result must be a usable SNI value.
    void TestNormalizeTlsSniTrailingDot() {
        std::cout << "\n[TEST] Config: Normalize strips sni trailing dot, rejects malformed..."
                  << std::endl;
        try {
            bool pass = true;
            std::string err;

            // Happy path: one trailing dot stripped.
            {
                ServerConfig cfg = ConfigLoader::Default();
                UpstreamConfig u;
                u.name = "api";
                u.host = "10.0.0.1";
                u.port = 443;
                u.tls.enabled = true;
                u.tls.sni_hostname = "api.example.com.";
                cfg.upstreams.push_back(u);
                ConfigLoader::Normalize(cfg);
                if (cfg.upstreams[0].tls.sni_hostname != "api.example.com") {
                    pass = false;
                    err += "sni='" + cfg.upstreams[0].tls.sni_hostname + "'; ";
                }
            }

            // Reject ".": strips to empty.
            {
                ServerConfig cfg = ConfigLoader::Default();
                UpstreamConfig u;
                u.name = "api"; u.host = "10.0.0.1"; u.port = 443;
                u.tls.enabled = true;
                u.tls.sni_hostname = ".";
                cfg.upstreams.push_back(u);
                bool threw = false;
                try { ConfigLoader::Normalize(cfg); }
                catch (const std::invalid_argument&) { threw = true; }
                if (!threw) { pass = false; err += "'.' accepted; "; }
            }

            // Reject "api.com..": post-strip still has trailing dot.
            {
                ServerConfig cfg = ConfigLoader::Default();
                UpstreamConfig u;
                u.name = "api"; u.host = "10.0.0.1"; u.port = 443;
                u.tls.enabled = true;
                u.tls.sni_hostname = "api.com..";
                cfg.upstreams.push_back(u);
                bool threw = false;
                try { ConfigLoader::Normalize(cfg); }
                catch (const std::invalid_argument&) { threw = true; }
                if (!threw) { pass = false; err += "'api.com..' accepted; "; }
            }

            // Empty sni_hostname is untouched (absence is legal — fallback
            // to host-derived SNI happens elsewhere).
            {
                ServerConfig cfg = ConfigLoader::Default();
                UpstreamConfig u;
                u.name = "api"; u.host = "10.0.0.1"; u.port = 443;
                u.tls.enabled = true;
                // sni_hostname left empty by default
                cfg.upstreams.push_back(u);
                ConfigLoader::Normalize(cfg);
                if (!cfg.upstreams[0].tls.sni_hostname.empty()) {
                    pass = false; err += "empty sni mutated; ";
                }
            }

            TestFramework::RecordTest(
                "Config: Normalize strips sni trailing dot, rejects malformed",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "Config: Normalize strips sni trailing dot, rejects malformed",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Validate accepts hostnames and bare IPv6 literals for
    // upstreams[].host, replacing the previous strict IPv4-only check.
    // Bracketed forms must fail Validate (they should have been stripped
    // by Normalize first).
    void TestValidateAcceptsHostnameAndIpv6Upstream() {
        std::cout << "\n[TEST] Config: Validate accepts hostname + IPv6 upstream host..."
                  << std::endl;
        try {
            bool pass = true;
            std::string err;

            auto validates = [&](const std::string& h) {
                ServerConfig cfg = ConfigLoader::Default();
                cfg.upstreams.clear();
                UpstreamConfig u;
                u.name = "api"; u.host = h; u.port = 8080;
                cfg.upstreams.push_back(u);
                try { ConfigLoader::Validate(cfg); return true; }
                catch (const std::invalid_argument&) { return false; }
            };

            // Accept: IPv4, bare IPv6, RFC 1123 hostname, absolute FQDN.
            for (const std::string& h : {
                std::string("10.0.0.1"),
                std::string("::1"),
                std::string("fe80::abcd"),
                std::string("api.example.com"),
                std::string("backend.ns.svc.cluster.local."),
            }) {
                if (!validates(h)) {
                    pass = false; err += "rejected valid '" + h + "'; ";
                }
            }

            // Reject: legacy numeric-dotted, underscore, bracketed form
            // (Normalize should have stripped brackets before Validate
            // ran; if Validate is called directly on bracketed input it
            // must reject).
            for (const std::string& h : {
                std::string("0127.0.0.1"),   // glibc inet_aton hazard
                std::string("bad_host"),     // underscore
                std::string("[::1]"),         // brackets not stripped
                std::string(""),              // empty
            }) {
                if (validates(h)) {
                    pass = false; err += "accepted invalid '" + h + "'; ";
                }
            }

            TestFramework::RecordTest(
                "Config: Validate accepts hostname + IPv6 upstream host",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "Config: Validate accepts hostname + IPv6 upstream host",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // DNS validation: resolver_max_inflight is restart-only and must
    // reject <= 0 at Validate time (defense-in-depth for
    // DnsResolver::EnsurePoolStarted's workers_.reserve call).
    // resolve_timeout_ms / overall_timeout_ms are reloadable; both
    // must reject <= 0 at both Validate and ValidateHotReloadable.
    void TestValidateDnsRules() {
        std::cout << "\n[TEST] Config: Validate DNS rules..." << std::endl;
        try {
            bool pass = true;
            std::string err;

            auto validate_throws = [](ServerConfig cfg) {
                try { ConfigLoader::Validate(cfg); return false; }
                catch (const std::invalid_argument&) { return true; }
            };
            auto hot_throws = [](ServerConfig cfg) {
                try {
                    ConfigLoader::ValidateHotReloadable(cfg, {});
                    return false;
                } catch (const std::invalid_argument&) { return true; }
            };

            // resolver_max_inflight <= 0 rejected.
            {
                ServerConfig cfg = ConfigLoader::Default();
                cfg.dns.resolver_max_inflight = 0;
                if (!validate_throws(cfg)) { pass = false; err += "rmi=0 accepted; "; }
                cfg.dns.resolver_max_inflight = -1;
                if (!validate_throws(cfg)) { pass = false; err += "rmi=-1 accepted; "; }
            }

            // resolve_timeout_ms <= 0 rejected — Validate AND hot-reload.
            {
                ServerConfig cfg = ConfigLoader::Default();
                cfg.dns.resolve_timeout_ms = 0;
                if (!validate_throws(cfg)) { pass = false; err += "rt=0 validate; "; }
                if (!hot_throws(cfg)) { pass = false; err += "rt=0 hot; "; }
            }

            // overall_timeout_ms <= 0 rejected.
            {
                ServerConfig cfg = ConfigLoader::Default();
                cfg.dns.overall_timeout_ms = -1;
                if (!validate_throws(cfg)) { pass = false; err += "ot=-1 validate; "; }
                if (!hot_throws(cfg)) { pass = false; err += "ot=-1 hot; "; }
            }

            // overall < resolve rejected.
            {
                ServerConfig cfg = ConfigLoader::Default();
                cfg.dns.resolve_timeout_ms = 5000;
                cfg.dns.overall_timeout_ms = 1000;
                if (!validate_throws(cfg)) { pass = false; err += "ot<rt validate; "; }
                if (!hot_throws(cfg)) { pass = false; err += "ot<rt hot; "; }
            }

            // Defaults pass.
            {
                ServerConfig cfg = ConfigLoader::Default();
                try {
                    ConfigLoader::Validate(cfg);
                    ConfigLoader::ValidateHotReloadable(cfg, {});
                } catch (const std::invalid_argument& e) {
                    pass = false; err += "defaults rejected: ";
                    err += e.what(); err += "; ";
                }
            }

            TestFramework::RecordTest(
                "Config: Validate DNS rules",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "Config: Validate DNS rules",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // JSON round-trip preserves the dns block. Covers the new
    // LoadFromString parse + ToJson emit paths.
    void TestDnsJsonRoundTrip() {
        std::cout << "\n[TEST] Config: dns JSON round-trip..." << std::endl;
        try {
            bool pass = true;
            std::string err;

            const std::string json = R"({
                "dns": {
                    "lookup_family": "v6_preferred",
                    "resolve_timeout_ms": 2500,
                    "overall_timeout_ms": 12000,
                    "stale_on_error": false,
                    "resolver_max_inflight": 16
                }
            })";
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            if (cfg.dns.lookup_family !=
                NET_DNS_NAMESPACE::LookupFamily::kV6Preferred) {
                pass = false; err += "lookup_family not v6_preferred; ";
            }
            if (cfg.dns.resolve_timeout_ms != 2500) {
                pass = false; err += "resolve_timeout_ms != 2500; ";
            }
            if (cfg.dns.overall_timeout_ms != 12000) {
                pass = false; err += "overall_timeout_ms != 12000; ";
            }
            if (cfg.dns.stale_on_error != false) {
                pass = false; err += "stale_on_error != false; ";
            }
            if (cfg.dns.resolver_max_inflight != 16) {
                pass = false; err += "resolver_max_inflight != 16; ";
            }

            // Round-trip via ToJson → LoadFromString preserves values.
            const std::string round = ConfigLoader::ToJson(cfg);
            ServerConfig cfg2 = ConfigLoader::LoadFromString(round);
            if (cfg2.dns.lookup_family != cfg.dns.lookup_family ||
                cfg2.dns.resolve_timeout_ms != cfg.dns.resolve_timeout_ms ||
                cfg2.dns.overall_timeout_ms != cfg.dns.overall_timeout_ms ||
                cfg2.dns.stale_on_error != cfg.dns.stale_on_error ||
                cfg2.dns.resolver_max_inflight != cfg.dns.resolver_max_inflight) {
                pass = false; err += "round-trip drift; ";
            }

            TestFramework::RecordTest(
                "Config: dns JSON round-trip",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "Config: dns JSON round-trip",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Run all config tests
    void RunAllTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "CONFIGURATION - UNIT TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestDefaultConfig();
        TestLoadFromString();
        TestLoadFromFile();
        TestInvalidJson();
        TestValidationInvalidPort();
        TestValidationTlsNoCert();
        TestEnvOverrides();
        TestMissingFile();

        // Circuit breaker config tests
        TestCircuitBreakerDefaults();
        TestCircuitBreakerJsonParse();
        TestCircuitBreakerJsonPartial();
        TestCircuitBreakerJsonRoundTrip();
        TestCircuitBreakerValidation();
        TestCircuitBreakerEquality();

        // Step 6 — ConfigLoader Normalize + DNS + hostname acceptance
        TestIsValidRejectsScopeId();
        TestNormalizeBracketStripAndTrailingDot();
        TestNormalizeTlsSniTrailingDot();
        TestValidateAcceptsHostnameAndIpv6Upstream();
        TestValidateDnsRules();
        TestDnsJsonRoundTrip();
    }

} // namespace ConfigTests
