#pragma once

#include "test_framework.h"
#include "config/server_config.h"
#include "config/config_loader.h"

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
            "consecutive_failure_threshold must be >= 1");
        ExpectValidationFailure("CB Validation: failure_rate_threshold>100",
            R"({"failure_rate_threshold": 101})",
            "failure_rate_threshold must be in [0, 100]");
        ExpectValidationFailure("CB Validation: minimum_volume<1",
            R"({"minimum_volume": 0})",
            "minimum_volume must be >= 1");
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
            "permitted_half_open_calls must be >= 1");
    }

    // Test 14: Equality operator covers circuit_breaker field
    void TestCircuitBreakerEquality() {
        std::cout << "\n[TEST] Circuit Breaker Equality..." << std::endl;
        try {
            UpstreamConfig a;
            a.name = "svc"; a.host = "h"; a.port = 80;
            UpstreamConfig b = a;
            bool equal_default = (a == b);

            b.circuit_breaker.enabled = true;
            bool not_equal_after_diff = (a != b);

            bool pass = equal_default && not_equal_after_diff;
            TestFramework::RecordTest("Circuit Breaker Equality", pass,
                pass ? "" : "operator== failed for circuit_breaker",
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Circuit Breaker Equality", false, e.what(),
                TestFramework::TestCategory::OTHER);
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

        // Phase 1: Circuit breaker config
        TestCircuitBreakerDefaults();
        TestCircuitBreakerJsonParse();
        TestCircuitBreakerJsonPartial();
        TestCircuitBreakerJsonRoundTrip();
        TestCircuitBreakerValidation();
        TestCircuitBreakerEquality();
    }

} // namespace ConfigTests
