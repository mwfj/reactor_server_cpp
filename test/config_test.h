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
    }

} // namespace ConfigTests
