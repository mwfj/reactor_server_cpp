# Reactor Server C++ - Makefile
# High-performance network server using the Reactor pattern with epoll
#
# Quick start:
#   make        - Build the project
#   make test   - Build and run all tests
#   make clean  - Remove build artifacts
#   make help   - Show detailed help

# Compiler and flags
CXX = g++
CC = gcc

# Platform-specific OpenSSL configuration
# - Linux: OpenSSL headers/libs are in system paths, no extra flags needed
# - macOS (ARM/Intel): Homebrew installs OpenSSL outside system paths
UNAME_S := $(shell uname -s)
OPENSSL_CFLAGS =
OPENSSL_LDFLAGS =
ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
    ifneq ($(OPENSSL_PREFIX),)
        OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
        OPENSSL_LDFLAGS := -L$(OPENSSL_PREFIX)/lib
    endif
endif

CXXFLAGS = -std=c++17 -g -Wall -Iinclude -Ithread_pool/include -Iutil -Itest -Ithird_party -Ithird_party/nghttp2 -Ithird_party/jwt-cpp/include -DJWT_DISABLE_PICOJSON $(OPENSSL_CFLAGS)
CFLAGS = -g -Wall -Ithird_party/llhttp
NGHTTP2_CFLAGS = -std=c99 -g -Wall -DHAVE_CONFIG_H -Ithird_party/nghttp2
LDFLAGS = $(OPENSSL_LDFLAGS) -lpthread -lssl -lcrypto

# Directories
SERVER_DIR = server
LIB_DIR = include
TEST_DIR = test
THREAD_POOL_DIR = thread_pool
UTIL_DIR = util
THIRD_PARTY_DIR = third_party

# Target executables
TARGET = test_runner
SERVER_TARGET = server_runner

# Source files (organized by component)
# Core reactor components
REACTOR_SRCS = $(SERVER_DIR)/dispatcher.cc $(SERVER_DIR)/event_handler.cc $(SERVER_DIR)/epoll_handler.cc $(SERVER_DIR)/kqueue_handler.cc $(SERVER_DIR)/channel.cc

# Network components
NETWORK_SRCS = $(SERVER_DIR)/inet_addr.cc $(SERVER_DIR)/dns_resolver.cc $(SERVER_DIR)/socket_handler.cc $(SERVER_DIR)/acceptor.cc $(SERVER_DIR)/connection_handler.cc

# Server and buffer
SERVER_SRCS = $(SERVER_DIR)/net_server.cc $(SERVER_DIR)/buffer.cc

# Thread pool sources
THREAD_POOL_SRCS = $(THREAD_POOL_DIR)/src/threadpool.cc $(THREAD_POOL_DIR)/src/threadtask.cc

# Foundation sources (logging, config)
FOUNDATION_SRCS = $(SERVER_DIR)/logger.cc $(SERVER_DIR)/config_loader.cc

# HTTP layer sources
HTTP_SRCS = $(SERVER_DIR)/http_response.cc $(SERVER_DIR)/http_parser.cc $(SERVER_DIR)/route_trie.cc $(SERVER_DIR)/http_router.cc $(SERVER_DIR)/http_connection_handler.cc $(SERVER_DIR)/http_server.cc

# WebSocket layer sources
WS_SRCS = $(SERVER_DIR)/websocket_frame.cc $(SERVER_DIR)/websocket_handshake.cc $(SERVER_DIR)/websocket_parser.cc $(SERVER_DIR)/websocket_connection.cc

# HTTP/2 layer sources
HTTP2_SRCS = $(SERVER_DIR)/http2_session.cc $(SERVER_DIR)/http2_stream.cc $(SERVER_DIR)/http2_connection_handler.cc $(SERVER_DIR)/protocol_detector.cc

# TLS layer sources
TLS_SRCS = $(SERVER_DIR)/tls_context.cc $(SERVER_DIR)/tls_connection.cc $(SERVER_DIR)/tls_client_context.cc

# Upstream connection pool sources
UPSTREAM_SRCS = $(SERVER_DIR)/upstream_connection.cc $(SERVER_DIR)/pool_partition.cc $(SERVER_DIR)/upstream_host_pool.cc $(SERVER_DIR)/upstream_manager.cc $(SERVER_DIR)/header_rewriter.cc $(SERVER_DIR)/retry_policy.cc $(SERVER_DIR)/upstream_http_codec.cc $(SERVER_DIR)/http_request_serializer.cc $(SERVER_DIR)/proxy_transaction.cc $(SERVER_DIR)/proxy_handler.cc

# Rate limit layer sources
RATE_LIMIT_SRCS = $(SERVER_DIR)/token_bucket.cc $(SERVER_DIR)/rate_limit_zone.cc $(SERVER_DIR)/rate_limiter.cc

# Circuit breaker layer sources
CIRCUIT_BREAKER_SRCS = $(SERVER_DIR)/circuit_breaker_window.cc $(SERVER_DIR)/circuit_breaker_slice.cc $(SERVER_DIR)/retry_budget.cc $(SERVER_DIR)/circuit_breaker_host.cc $(SERVER_DIR)/circuit_breaker_manager.cc

# Auth layer sources (OAuth 2.0 token validation — Layer 7 middleware)
# Note: JWT decode + signature verification is delegated to vendored jwt-cpp
# (third_party/jwt-cpp/, header-only). See design spec §12.1 and r4/r5 revision
# history for the library-adoption rationale.
AUTH_SRCS = $(SERVER_DIR)/token_hasher.cc $(SERVER_DIR)/auth_policy_matcher.cc $(SERVER_DIR)/auth_claims.cc

# CLI layer sources
CLI_SRCS = $(SERVER_DIR)/cli_parser.cc $(SERVER_DIR)/signal_handler.cc $(SERVER_DIR)/pid_file.cc $(SERVER_DIR)/daemonizer.cc

# Application code (test entry point)
APP_SRCS = $(TEST_DIR)/test_framework.cc $(TEST_DIR)/run_test.cc

# Production entry point
MAIN_SRC = $(SERVER_DIR)/main.cc

# TimeStamp Code
UTIL_SRCS = $(UTIL_DIR)/timestamp.cc

# llhttp C sources
LLHTTP_SRC = $(THIRD_PARTY_DIR)/llhttp/llhttp.c $(THIRD_PARTY_DIR)/llhttp/api.c $(THIRD_PARTY_DIR)/llhttp/http.c
LLHTTP_OBJ = $(LLHTTP_SRC:.c=.o)

# nghttp2 C sources (vendored HTTP/2 library)
NGHTTP2_SRC = $(THIRD_PARTY_DIR)/nghttp2/nghttp2_alpn.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_buf.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_callbacks.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_debug.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_extpri.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_frame.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_hd.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_hd_huffman.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_hd_huffman_data.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_helper.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_http.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_map.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_mem.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_option.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_outbound_item.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_pq.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_priority_spec.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_queue.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_ratelim.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_rcbuf.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_session.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_stream.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_submit.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_time.c \
              $(THIRD_PARTY_DIR)/nghttp2/nghttp2_version.c \
              $(THIRD_PARTY_DIR)/nghttp2/sfparse.c
NGHTTP2_OBJ = $(NGHTTP2_SRC:.c=.o)

# Server library sources (shared between test and production binaries)
LIB_SRCS = $(REACTOR_SRCS) $(NETWORK_SRCS) $(SERVER_SRCS) $(THREAD_POOL_SRCS) $(FOUNDATION_SRCS) $(HTTP_SRCS) $(HTTP2_SRCS) $(WS_SRCS) $(TLS_SRCS) $(UPSTREAM_SRCS) $(RATE_LIMIT_SRCS) $(CIRCUIT_BREAKER_SRCS) $(AUTH_SRCS) $(CLI_SRCS) $(UTIL_SRCS)

# Test binary sources
TEST_SRCS = $(LIB_SRCS) $(TEST_DIR)/test_framework.cc $(TEST_DIR)/run_test.cc

# Header files (organized by category)
CORE_HEADERS = $(LIB_DIR)/common.h $(LIB_DIR)/inet_addr.h
CALLBACK_HEADERS = $(LIB_DIR)/callbacks.h
REACTOR_HEADERS = $(LIB_DIR)/dispatcher.h $(LIB_DIR)/epoll_handler.h $(LIB_DIR)/channel.h
NETWORK_HEADERS = $(LIB_DIR)/socket_handler.h $(LIB_DIR)/acceptor.h $(LIB_DIR)/connection_handler.h
SERVER_HEADERS = $(LIB_DIR)/net_server.h $(LIB_DIR)/buffer.h
THREAD_POOL_HEADERS = $(THREAD_POOL_DIR)/include/threadpool.h $(THREAD_POOL_DIR)/include/threadtask.h
UTIL_HEADERS = $(UTIL_DIR)/timestamp.h
FOUNDATION_HEADERS = $(LIB_DIR)/log/logger.h $(LIB_DIR)/log/log_utils.h $(LIB_DIR)/config/server_config.h $(LIB_DIR)/config/config_loader.h
HTTP_HEADERS = $(LIB_DIR)/http/http_callbacks.h $(LIB_DIR)/http/http_connection_handler.h $(LIB_DIR)/http/http_parser.h $(LIB_DIR)/http/http_request.h $(LIB_DIR)/http/http_response.h $(LIB_DIR)/http/http_router.h $(LIB_DIR)/http/http_server.h $(LIB_DIR)/http/route_trie.h $(LIB_DIR)/http/route_trie_impl.h
HTTP2_HEADERS = $(LIB_DIR)/http2/http2_callbacks.h $(LIB_DIR)/http2/http2_connection_handler.h $(LIB_DIR)/http2/http2_constants.h $(LIB_DIR)/http2/http2_session.h $(LIB_DIR)/http2/http2_stream.h $(LIB_DIR)/http2/protocol_detector.h
WS_HEADERS = $(LIB_DIR)/ws/websocket_connection.h $(LIB_DIR)/ws/websocket_frame.h $(LIB_DIR)/ws/websocket_handshake.h $(LIB_DIR)/ws/websocket_parser.h $(LIB_DIR)/ws/utf8_validate.h
TLS_HEADERS = $(LIB_DIR)/tls/tls_context.h $(LIB_DIR)/tls/tls_connection.h $(LIB_DIR)/tls/tls_client_context.h
UPSTREAM_HEADERS = $(LIB_DIR)/upstream/upstream_manager.h $(LIB_DIR)/upstream/upstream_host_pool.h $(LIB_DIR)/upstream/pool_partition.h $(LIB_DIR)/upstream/upstream_connection.h $(LIB_DIR)/upstream/upstream_lease.h $(LIB_DIR)/upstream/upstream_http_codec.h $(LIB_DIR)/upstream/http_request_serializer.h $(LIB_DIR)/upstream/header_rewriter.h $(LIB_DIR)/upstream/retry_policy.h $(LIB_DIR)/upstream/proxy_transaction.h $(LIB_DIR)/upstream/proxy_handler.h $(LIB_DIR)/upstream/upstream_response.h $(LIB_DIR)/upstream/upstream_callbacks.h
RATE_LIMIT_HEADERS = $(LIB_DIR)/rate_limit/token_bucket.h $(LIB_DIR)/rate_limit/rate_limit_zone.h $(LIB_DIR)/rate_limit/rate_limiter.h
CIRCUIT_BREAKER_HEADERS = $(LIB_DIR)/circuit_breaker/circuit_breaker_state.h $(LIB_DIR)/circuit_breaker/circuit_breaker_window.h $(LIB_DIR)/circuit_breaker/circuit_breaker_slice.h $(LIB_DIR)/circuit_breaker/retry_budget.h $(LIB_DIR)/circuit_breaker/circuit_breaker_host.h $(LIB_DIR)/circuit_breaker/circuit_breaker_manager.h
# Auth headers. The vendored jwt-cpp headers are pulled into the dependency
# graph so a bump-jwt-cpp PR correctly invalidates the whole build.
JWT_CPP_DIR = $(THIRD_PARTY_DIR)/jwt-cpp/include/jwt-cpp
AUTH_HEADERS = $(LIB_DIR)/auth/auth_context.h $(LIB_DIR)/auth/auth_config.h $(LIB_DIR)/auth/token_hasher.h $(LIB_DIR)/auth/auth_policy_matcher.h $(LIB_DIR)/auth/auth_claims.h $(JWT_CPP_DIR)/jwt.h $(JWT_CPP_DIR)/base.h $(JWT_CPP_DIR)/traits/nlohmann-json/defaults.h $(JWT_CPP_DIR)/traits/nlohmann-json/traits.h
CLI_HEADERS = $(LIB_DIR)/cli/cli_parser.h $(LIB_DIR)/cli/signal_handler.h $(LIB_DIR)/cli/pid_file.h $(LIB_DIR)/cli/version.h $(LIB_DIR)/cli/daemonizer.h
TEST_HEADERS = $(TEST_DIR)/test_framework.h $(TEST_DIR)/http_test_client.h $(TEST_DIR)/basic_test.h $(TEST_DIR)/stress_test.h $(TEST_DIR)/race_condition_test.h $(TEST_DIR)/timeout_test.h $(TEST_DIR)/config_test.h $(TEST_DIR)/http_test.h $(TEST_DIR)/websocket_test.h $(TEST_DIR)/tls_test.h $(TEST_DIR)/cli_test.h $(TEST_DIR)/http2_test.h $(TEST_DIR)/route_test.h $(TEST_DIR)/upstream_pool_test.h $(TEST_DIR)/proxy_test.h $(TEST_DIR)/rate_limit_test.h $(TEST_DIR)/kqueue_test.h $(TEST_DIR)/circuit_breaker_test.h $(TEST_DIR)/circuit_breaker_components_test.h $(TEST_DIR)/circuit_breaker_integration_test.h $(TEST_DIR)/circuit_breaker_retry_budget_test.h $(TEST_DIR)/circuit_breaker_wait_queue_drain_test.h $(TEST_DIR)/circuit_breaker_observability_test.h $(TEST_DIR)/circuit_breaker_reload_test.h $(TEST_DIR)/auth_foundation_test.h

# All headers combined
HEADERS = $(CORE_HEADERS) $(CALLBACK_HEADERS) $(REACTOR_HEADERS) $(NETWORK_HEADERS) $(SERVER_HEADERS) $(THREAD_POOL_HEADERS) $(UTIL_HEADERS) $(FOUNDATION_HEADERS) $(HTTP_HEADERS) $(HTTP2_HEADERS) $(WS_HEADERS) $(TLS_HEADERS) $(UPSTREAM_HEADERS) $(RATE_LIMIT_HEADERS) $(CIRCUIT_BREAKER_HEADERS) $(AUTH_HEADERS) $(CLI_HEADERS) $(TEST_HEADERS)

# Default target
.DEFAULT_GOAL := all

all: $(TARGET) $(SERVER_TARGET)

# Compile llhttp C sources to object files
$(THIRD_PARTY_DIR)/llhttp/%.o: $(THIRD_PARTY_DIR)/llhttp/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile nghttp2 C sources to object files
$(THIRD_PARTY_DIR)/nghttp2/%.o: $(THIRD_PARTY_DIR)/nghttp2/%.c
	$(CC) $(NGHTTP2_CFLAGS) -c $< -o $@

# Build the test executable
$(TARGET): $(TEST_SRCS) $(HEADERS) $(LLHTTP_OBJ) $(NGHTTP2_OBJ)
	$(CXX) $(CXXFLAGS) $(TEST_SRCS) $(LLHTTP_OBJ) $(NGHTTP2_OBJ) $(LDFLAGS) -o $(TARGET)

# Build the production server binary
$(SERVER_TARGET): $(LIB_SRCS) $(MAIN_SRC) $(HEADERS) $(LLHTTP_OBJ) $(NGHTTP2_OBJ)
	$(CXX) $(CXXFLAGS) $(LIB_SRCS) $(MAIN_SRC) $(LLHTTP_OBJ) $(NGHTTP2_OBJ) $(LDFLAGS) -o $(SERVER_TARGET)

# Clean build artifacts
clean:
	rm -rf $(TARGET)* $(SERVER_TARGET) $(LLHTTP_OBJ) $(NGHTTP2_OBJ) *.dSYM *.plist

# Run all tests
test: $(TARGET) $(SERVER_TARGET)
	@echo "Running test suite..."
	./$(TARGET)

# Run only race condition tests
test_race: $(TARGET)
	@echo "Running race condition tests only..."
	./$(TARGET) race

# Run only stress tests
test_stress: $(TARGET)
	@echo "Running stress tests only..."
	./$(TARGET) stress

# Run only basic tests
test_basic: $(TARGET)
	@echo "Running basic tests only..."
	./$(TARGET) basic

# Run only config tests
test_config: $(TARGET)
	@echo "Running config tests only..."
	./$(TARGET) config

# Run only HTTP tests (placeholder for Phase 2)
test_http: $(TARGET)
	@echo "Running HTTP tests only..."
	./$(TARGET) http

# Run only WebSocket tests (placeholder for Phase 3)
test_ws: $(TARGET)
	@echo "Running WebSocket tests only..."
	./$(TARGET) ws

# Run only TLS tests (placeholder for Phase 4)
test_tls: $(TARGET)
	@echo "Running TLS tests only..."
	./$(TARGET) tls

# Run only CLI entry point tests
test_cli: $(TARGET) $(SERVER_TARGET)
	@echo "Running CLI tests only..."
	./$(TARGET) cli

# Run only HTTP/2 tests
test_http2: $(TARGET)
	@echo "Running HTTP/2 tests only..."
	./$(TARGET) http2

# Run only upstream connection pool tests
test_upstream: $(TARGET)
	@echo "Running upstream connection pool tests only..."
	./$(TARGET) upstream

# Run only proxy engine tests
test_proxy: $(TARGET)
	@echo "Running proxy engine tests only..."
	./$(TARGET) proxy

# Run only rate limit tests
test_rate_limit: $(TARGET)
	@echo "Running rate limit tests only..."
	./$(TARGET) rate_limit

# Run only circuit breaker tests
test_circuit_breaker: $(TARGET)
	@echo "Running circuit breaker tests only..."
	./$(TARGET) circuit_breaker

# Run only auth foundation tests
test_auth: $(TARGET)
	@echo "Running auth foundation tests only..."
	./$(TARGET) auth

# Display help information
help:
	@echo "Reactor Server C++ - Makefile Help"
	@echo "===================================="
	@echo ""
	@echo "Available targets:"
	@echo "  make [all]       - Build the project (default target)"
	@echo "                     Compiles all source files and creates './test_runner' executable"
	@echo ""
	@echo "  make test        - Build and run all tests"
	@echo "                     Runs BasicTests (port 9888), StressTests (port 9889),"
	@echo "                     RaceConditionTests (port 10000), and ConfigTests"
	@echo ""
	@echo "  make test_basic  - Build and run only basic tests"
	@echo "                     Equivalent to './test_runner basic'"
	@echo ""
	@echo "  make test_stress - Build and run only stress tests"
	@echo "                     Runs 100 concurrent clients (equivalent to './test_runner stress' or './test_runner -s')"
	@echo "                     Validates fixes from STRESS_TEST_BUG_FIXES.md"
	@echo ""
	@echo "  make test_race   - Build and run only race condition tests"
	@echo "                     Runs 7 race condition tests (equivalent to './test_runner race')"
	@echo "                     Validates fixes from EVENTFD_RACE_CONDITION_FIXES.md"
	@echo ""
	@echo "  make test_config - Build and run only config tests"
	@echo "                     Runs configuration loading/validation tests"
	@echo ""
	@echo "  make test_http   - Build and run only HTTP tests (Phase 2)"
	@echo ""
	@echo "  make test_ws     - Build and run only WebSocket tests (Phase 3)"
	@echo ""
	@echo "  make test_tls    - Build and run only TLS tests (Phase 4)"
	@echo ""
	@echo "  make clean       - Remove build artifacts"
	@echo "                     Deletes './test_runner' executable and llhttp object files"
	@echo ""
	@echo "  make help        - Show this help message"
	@echo ""
	@echo "Build configuration:"
	@echo "  Compiler:      $(CXX)"
	@echo "  C++ Standard:  C++17"
	@echo "  Flags:         $(CXXFLAGS)"
	@echo "  Linker:        $(LDFLAGS)"
	@echo ""
	@echo "Project structure:"
	@echo "  Headers:       include/*.h"
	@echo "  Source:        server/*.cc"
	@echo "  Thread Pool:   thread_pool/include/*.h thread_pool/src/*.cc"
	@echo "  Third Party:   third_party/ (nlohmann/json, spdlog, llhttp)"
	@echo "  Tests:         test/*.cc test/*.h"
	@echo "  Test runner:   ./test_runner"
	@echo "  Server:        ./server_runner"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build the project"
	@echo "  make clean        # Clean build artifacts"
	@echo "  make test         # Build and run all tests"
	@echo "  make test_basic   # Run only basic tests"
	@echo "  make test_stress  # Run only stress tests (100 concurrent clients)"
	@echo "  make test_race    # Run only race condition tests"
	@echo "  make test_config  # Run only config tests"
	@echo ""
	@echo "Direct executable usage (after building):"
	@echo "  ./test_runner             # Run all tests"
	@echo "  ./test_runner basic       # Run basic tests only (or: ./test_runner -b)"
	@echo "  ./test_runner stress      # Run stress tests only (or: ./test_runner -s)"
	@echo "  ./test_runner race        # Run race condition tests only (or: ./test_runner -r)"
	@echo "  ./test_runner timeout     # Run timeout tests only (or: ./test_runner -t)"
	@echo "  ./test_runner config      # Run config tests only (or: ./test_runner -c)"
	@echo "  ./test_runner help        # Show help message (or: ./test_runner -h)"
	@echo ""
	@echo "For more information, see:"
	@echo "  - STRESS_TEST_BUG_FIXES.md - Stress test bug analysis"
	@echo "  - EVENTFD_RACE_CONDITION_FIXES.md - Race condition fixes"
	@echo "  - test/RACE_CONDITION_TESTS_README.md - Race condition tests"

# Phony targets
# Build only the production server binary
server: $(SERVER_TARGET)

.PHONY: all clean test server test_basic test_stress test_race test_config test_http test_ws test_tls test_cli test_http2 test_upstream test_proxy test_rate_limit test_circuit_breaker test_auth help
