# Reactor Server C++ - Makefile
# High-performance network server using the Reactor pattern with epoll
#
# Quick start:
#   make        - Build the project
#   make test   - Build and run all tests
#   make clean  - Remove build artifacts
#   make help   - Show detailed help

# Compiler and flags. CXX/CC use ?= so CI can override via env (e.g. CXX=clang++).
CXX ?= g++
CC ?= gcc

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

# *_EXTRA hooks let CI layer in sanitizers (-fsanitize=...) and other one-off
# flags without clobbering the project's required compile/link flags. Empty
# by default; populated via `make CXXFLAGS_EXTRA=...` or env.
CXXFLAGS = -std=c++17 -g -Wall -Iinclude -Ithread_pool/include -Iutil -Itest -Ithird_party -Ithird_party/nghttp2 -Ithird_party/jwt-cpp/include -DJWT_DISABLE_PICOJSON $(OPENSSL_CFLAGS) $(CXXFLAGS_EXTRA)
CFLAGS = -g -Wall -Ithird_party/llhttp $(CFLAGS_EXTRA)
NGHTTP2_CFLAGS = -std=c99 -g -Wall -DHAVE_CONFIG_H -Ithird_party/nghttp2 $(NGHTTP2_CFLAGS_EXTRA)
LDFLAGS = $(OPENSSL_LDFLAGS) -lpthread -lssl -lcrypto $(LDFLAGS_EXTRA)

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
UPSTREAM_SRCS = $(SERVER_DIR)/upstream_connection.cc $(SERVER_DIR)/pool_partition.cc $(SERVER_DIR)/upstream_host_pool.cc $(SERVER_DIR)/upstream_manager.cc $(SERVER_DIR)/header_rewriter.cc $(SERVER_DIR)/retry_policy.cc $(SERVER_DIR)/upstream_http_codec.cc $(SERVER_DIR)/upstream_h2_codec.cc $(SERVER_DIR)/upstream_h2_connection.cc $(SERVER_DIR)/h2_connection_table.cc $(SERVER_DIR)/http_request_serializer.cc $(SERVER_DIR)/proxy_transaction.cc $(SERVER_DIR)/proxy_handler.cc

# Rate limit layer sources
RATE_LIMIT_SRCS = $(SERVER_DIR)/token_bucket.cc $(SERVER_DIR)/rate_limit_zone.cc $(SERVER_DIR)/rate_limiter.cc

# Circuit breaker layer sources
CIRCUIT_BREAKER_SRCS = $(SERVER_DIR)/circuit_breaker_window.cc $(SERVER_DIR)/circuit_breaker_slice.cc $(SERVER_DIR)/retry_budget.cc $(SERVER_DIR)/circuit_breaker_host.cc $(SERVER_DIR)/circuit_breaker_manager.cc

# Auth layer sources (OAuth 2.0 token validation — Layer 7 middleware)
# Note: JWT decode + signature verification is delegated to vendored jwt-cpp
# (third_party/jwt-cpp/, header-only).
AUTH_SRCS = $(SERVER_DIR)/token_hasher.cc $(SERVER_DIR)/auth_policy_matcher.cc $(SERVER_DIR)/auth_claims.cc \
            $(SERVER_DIR)/jwks_cache.cc $(SERVER_DIR)/auth_upstream_http_client.cc $(SERVER_DIR)/issuer.cc \
            $(SERVER_DIR)/jwks_fetcher.cc $(SERVER_DIR)/oidc_discovery.cc $(SERVER_DIR)/jwt_verifier.cc \
            $(SERVER_DIR)/auth_error_responses.cc $(SERVER_DIR)/auth_manager.cc $(SERVER_DIR)/auth_middleware.cc \
            $(SERVER_DIR)/auth_url_util.cc $(SERVER_DIR)/introspection_cache.cc \
            $(SERVER_DIR)/introspection_client.cc

# Observability layer sources (OpenTelemetry — Layer 7 middleware)
# Foundational value types only at this stage; Span / Tracer / Meter
# / OtlpHttpExporter / PrometheusExporter / ObservabilityManager land
# in subsequent slices.
OBSERVABILITY_SRCS = $(SERVER_DIR)/trace_id.cc $(SERVER_DIR)/trace_state.cc \
                     $(SERVER_DIR)/attr_value.cc $(SERVER_DIR)/sampler.cc \
                     $(SERVER_DIR)/span.cc $(SERVER_DIR)/tracer.cc \
                     $(SERVER_DIR)/tracer_provider.cc \
                     $(SERVER_DIR)/metric_label_registry.cc \
                     $(SERVER_DIR)/metric_writer_context.cc \
                     $(SERVER_DIR)/counter.cc $(SERVER_DIR)/histogram.cc \
                     $(SERVER_DIR)/meter.cc $(SERVER_DIR)/meter_provider.cc \
                     $(SERVER_DIR)/metrics_catalog.cc \
                     $(SERVER_DIR)/observability_manager.cc \
                     $(SERVER_DIR)/observability_middleware.cc \
                     $(SERVER_DIR)/propagator.cc \
                     $(SERVER_DIR)/jaeger_propagator.cc \
                     $(SERVER_DIR)/composite_propagator.cc \
                     $(SERVER_DIR)/batch_span_processor.cc \
                     $(SERVER_DIR)/periodic_metric_reader.cc \
                     $(SERVER_DIR)/otlp_http_exporter.cc \
                     $(SERVER_DIR)/otlp_transport.cc \
                     $(SERVER_DIR)/prometheus_exporter.cc \
                     $(SERVER_DIR)/metrics_handler.cc

# CLI layer sources
CLI_SRCS = $(SERVER_DIR)/cli_parser.cc $(SERVER_DIR)/signal_handler.cc $(SERVER_DIR)/pid_file.cc $(SERVER_DIR)/daemonizer.cc

# Application code (test entry point)
APP_SRCS = $(TEST_DIR)/test_framework.cc $(TEST_DIR)/run_test.cc

# Production entry point
MAIN_SRC = $(SERVER_DIR)/main.cc

# TimeStamp Code
UTIL_SRCS = $(UTIL_DIR)/timestamp.cc $(UTIL_DIR)/base64.cc

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
LIB_SRCS = $(REACTOR_SRCS) $(NETWORK_SRCS) $(SERVER_SRCS) $(THREAD_POOL_SRCS) $(FOUNDATION_SRCS) $(HTTP_SRCS) $(HTTP2_SRCS) $(WS_SRCS) $(TLS_SRCS) $(UPSTREAM_SRCS) $(RATE_LIMIT_SRCS) $(CIRCUIT_BREAKER_SRCS) $(AUTH_SRCS) $(OBSERVABILITY_SRCS) $(CLI_SRCS) $(UTIL_SRCS)

# Test binary sources
TEST_SRCS = $(LIB_SRCS) $(TEST_DIR)/test_framework.cc $(TEST_DIR)/run_test.cc

# Header files (organized by category)
CORE_HEADERS = $(LIB_DIR)/common.h $(LIB_DIR)/inet_addr.h
CALLBACK_HEADERS = $(LIB_DIR)/callbacks.h
REACTOR_HEADERS = $(LIB_DIR)/dispatcher.h $(LIB_DIR)/epoll_handler.h $(LIB_DIR)/channel.h
NETWORK_HEADERS = $(LIB_DIR)/socket_handler.h $(LIB_DIR)/acceptor.h $(LIB_DIR)/connection_handler.h
DNS_HEADERS = $(LIB_DIR)/net/dns_resolver.h
SERVER_HEADERS = $(LIB_DIR)/net_server.h $(LIB_DIR)/buffer.h
THREAD_POOL_HEADERS = $(THREAD_POOL_DIR)/include/threadpool.h $(THREAD_POOL_DIR)/include/threadtask.h
UTIL_HEADERS = $(UTIL_DIR)/timestamp.h $(UTIL_DIR)/base64.h
FOUNDATION_HEADERS = $(LIB_DIR)/log/logger.h $(LIB_DIR)/log/log_utils.h $(LIB_DIR)/config/server_config.h $(LIB_DIR)/config/config_loader.h
HTTP_HEADERS = $(LIB_DIR)/http/http_callbacks.h $(LIB_DIR)/http/http_connection_handler.h $(LIB_DIR)/http/http_parser.h $(LIB_DIR)/http/http_request.h $(LIB_DIR)/http/http_response.h $(LIB_DIR)/http/http_router.h $(LIB_DIR)/http/http_server.h $(LIB_DIR)/http/http_status.h $(LIB_DIR)/http/route_match.h $(LIB_DIR)/http/route_trie.h $(LIB_DIR)/http/route_trie_impl.h $(LIB_DIR)/http/streaming_response_sender.h $(LIB_DIR)/http/streaming_response_sender_utils.h $(LIB_DIR)/http/trailer_policy.h
OBSERVABILITY_HEADERS = $(LIB_DIR)/observability/common.h $(LIB_DIR)/observability/attr_value.h $(LIB_DIR)/observability/batch_span_processor.h $(LIB_DIR)/observability/counter.h $(LIB_DIR)/observability/histogram.h $(LIB_DIR)/observability/instrumentation_scope.h $(LIB_DIR)/observability/meter.h $(LIB_DIR)/observability/meter_provider.h $(LIB_DIR)/observability/metric_exporter.h $(LIB_DIR)/observability/metric_label_registry.h $(LIB_DIR)/observability/metric_writer_context.h $(LIB_DIR)/observability/metrics_catalog.h $(LIB_DIR)/observability/metrics_handler.h $(LIB_DIR)/observability/metrics_snapshot.h $(LIB_DIR)/observability/observability_config.h $(LIB_DIR)/observability/observability_manager.h $(LIB_DIR)/observability/observability_middleware.h $(LIB_DIR)/observability/observability_snapshot.h $(LIB_DIR)/observability/otlp_http_exporter.h $(LIB_DIR)/observability/otlp_transport.h $(LIB_DIR)/observability/periodic_metric_reader.h $(LIB_DIR)/observability/prometheus_exporter.h $(LIB_DIR)/observability/propagator.h $(LIB_DIR)/observability/resource.h $(LIB_DIR)/observability/sampler.h $(LIB_DIR)/observability/semantic_conventions.h $(LIB_DIR)/observability/span.h $(LIB_DIR)/observability/span_context.h $(LIB_DIR)/observability/span_data.h $(LIB_DIR)/observability/span_exporter.h $(LIB_DIR)/observability/span_kind.h $(LIB_DIR)/observability/span_processor.h $(LIB_DIR)/observability/span_status.h $(LIB_DIR)/observability/trace_context.h $(LIB_DIR)/observability/trace_id.h $(LIB_DIR)/observability/trace_state.h $(LIB_DIR)/observability/tracer.h $(LIB_DIR)/observability/tracer_provider.h
HTTP2_HEADERS = $(LIB_DIR)/http2/http2_callbacks.h $(LIB_DIR)/http2/http2_connection_handler.h $(LIB_DIR)/http2/http2_constants.h $(LIB_DIR)/http2/http2_session.h $(LIB_DIR)/http2/http2_stream.h $(LIB_DIR)/http2/protocol_detector.h
WS_HEADERS = $(LIB_DIR)/ws/websocket_connection.h $(LIB_DIR)/ws/websocket_frame.h $(LIB_DIR)/ws/websocket_handshake.h $(LIB_DIR)/ws/websocket_parser.h $(LIB_DIR)/ws/utf8_validate.h
TLS_HEADERS = $(LIB_DIR)/tls/tls_context.h $(LIB_DIR)/tls/tls_connection.h $(LIB_DIR)/tls/tls_client_context.h
UPSTREAM_HEADERS = $(LIB_DIR)/upstream/upstream_manager.h $(LIB_DIR)/upstream/upstream_host_pool.h $(LIB_DIR)/upstream/pool_partition.h $(LIB_DIR)/upstream/upstream_connection.h $(LIB_DIR)/upstream/upstream_lease.h $(LIB_DIR)/upstream/upstream_codec.h $(LIB_DIR)/upstream/upstream_http_codec.h $(LIB_DIR)/upstream/upstream_h2_codec.h $(LIB_DIR)/upstream/upstream_h2_stream.h $(LIB_DIR)/upstream/upstream_h2_connection.h $(LIB_DIR)/upstream/h2_connection_table.h $(LIB_DIR)/upstream/h2_settings.h $(LIB_DIR)/upstream/http_request_serializer.h $(LIB_DIR)/upstream/header_rewriter.h $(LIB_DIR)/upstream/retry_policy.h $(LIB_DIR)/upstream/proxy_transaction.h $(LIB_DIR)/upstream/proxy_handler.h $(LIB_DIR)/upstream/upstream_response.h $(LIB_DIR)/upstream/upstream_callbacks.h
RATE_LIMIT_HEADERS = $(LIB_DIR)/rate_limit/token_bucket.h $(LIB_DIR)/rate_limit/rate_limit_zone.h $(LIB_DIR)/rate_limit/rate_limiter.h
CIRCUIT_BREAKER_HEADERS = $(LIB_DIR)/circuit_breaker/circuit_breaker_state.h $(LIB_DIR)/circuit_breaker/circuit_breaker_window.h $(LIB_DIR)/circuit_breaker/circuit_breaker_slice.h $(LIB_DIR)/circuit_breaker/retry_budget.h $(LIB_DIR)/circuit_breaker/circuit_breaker_host.h $(LIB_DIR)/circuit_breaker/circuit_breaker_manager.h
# Auth headers. The vendored jwt-cpp headers are pulled into the dependency
# graph so a bump-jwt-cpp PR correctly invalidates the whole build.
JWT_CPP_DIR = $(THIRD_PARTY_DIR)/jwt-cpp/include/jwt-cpp
AUTH_HEADERS = $(LIB_DIR)/auth/auth_context.h $(LIB_DIR)/auth/auth_config.h $(LIB_DIR)/auth/token_hasher.h $(LIB_DIR)/auth/auth_policy_matcher.h $(LIB_DIR)/auth/auth_claims.h $(LIB_DIR)/auth/auth_result.h $(LIB_DIR)/auth/auth_url_util.h $(LIB_DIR)/auth/jwks_cache.h $(LIB_DIR)/auth/upstream_http_client.h $(LIB_DIR)/auth/issuer.h $(LIB_DIR)/auth/jwks_fetcher.h $(LIB_DIR)/auth/oidc_discovery.h $(LIB_DIR)/auth/jwt_verifier.h $(LIB_DIR)/auth/auth_error_responses.h $(LIB_DIR)/auth/auth_manager.h $(LIB_DIR)/auth/auth_middleware.h $(LIB_DIR)/auth/introspection_cache.h $(LIB_DIR)/auth/introspection_client.h $(JWT_CPP_DIR)/jwt.h $(JWT_CPP_DIR)/base.h $(JWT_CPP_DIR)/traits/nlohmann-json/defaults.h $(JWT_CPP_DIR)/traits/nlohmann-json/traits.h
CLI_HEADERS = $(LIB_DIR)/cli/cli_parser.h $(LIB_DIR)/cli/signal_handler.h $(LIB_DIR)/cli/pid_file.h $(LIB_DIR)/cli/version.h $(LIB_DIR)/cli/daemonizer.h
TEST_HEADERS = $(TEST_DIR)/test_framework.h $(TEST_DIR)/http_test_client.h $(TEST_DIR)/basic_test.h $(TEST_DIR)/stress_test.h $(TEST_DIR)/race_condition_test.h $(TEST_DIR)/timeout_test.h $(TEST_DIR)/config_test.h $(TEST_DIR)/http_test.h $(TEST_DIR)/websocket_test.h $(TEST_DIR)/tls_test.h $(TEST_DIR)/cli_test.h $(TEST_DIR)/http2_test.h $(TEST_DIR)/route_test.h $(TEST_DIR)/upstream_pool_test.h $(TEST_DIR)/proxy_test.h $(TEST_DIR)/rate_limit_test.h $(TEST_DIR)/kqueue_test.h $(TEST_DIR)/circuit_breaker_test.h $(TEST_DIR)/circuit_breaker_components_test.h $(TEST_DIR)/circuit_breaker_integration_test.h $(TEST_DIR)/circuit_breaker_retry_budget_test.h $(TEST_DIR)/circuit_breaker_wait_queue_drain_test.h $(TEST_DIR)/circuit_breaker_observability_test.h $(TEST_DIR)/circuit_breaker_reload_test.h $(TEST_DIR)/auth_foundation_test.h $(TEST_DIR)/jwt_verifier_test.h $(TEST_DIR)/jwks_cache_test.h $(TEST_DIR)/oidc_discovery_test.h $(TEST_DIR)/header_rewriter_auth_test.h $(TEST_DIR)/auth_manager_test.h $(TEST_DIR)/auth_integration_test.h $(TEST_DIR)/auth_failure_mode_test.h $(TEST_DIR)/auth_reload_test.h $(TEST_DIR)/auth_multi_issuer_test.h $(TEST_DIR)/auth_websocket_upgrade_test.h $(TEST_DIR)/auth_race_test.h $(TEST_DIR)/dns_resolver_test.h $(TEST_DIR)/dual_stack_test.h $(TEST_DIR)/router_async_middleware_test.h $(TEST_DIR)/introspection_cache_test.h $(TEST_DIR)/introspection_client_test.h $(TEST_DIR)/mock_introspection_server.h $(TEST_DIR)/auth_introspection_integration_test.h $(TEST_DIR)/auth_observability_test.h $(TEST_DIR)/h2_upstream_test.h $(TEST_DIR)/observability_test_helpers.h $(TEST_DIR)/observability_foundation_test.h $(TEST_DIR)/observability_tracer_test.h $(TEST_DIR)/observability_metrics_test.h $(TEST_DIR)/observability_manager_test.h $(TEST_DIR)/observability_propagator_test.h $(TEST_DIR)/observability_export_pipeline_test.h $(TEST_DIR)/observability_prometheus_test.h $(TEST_DIR)/observability_config_test.h $(TEST_DIR)/observability_shutdown_test.h $(TEST_DIR)/observability_link_kill_test.h $(TEST_DIR)/observability_issue_inject_test.h $(TEST_DIR)/observability_stress_test.h $(TEST_DIR)/observability_e2e_test.h $(TEST_DIR)/observability_self_handler_test.h $(TEST_DIR)/observability_proxy_client_test.h $(TEST_DIR)/observability_auth_trace_test.h $(TEST_DIR)/observability_catalog_test.h $(TEST_DIR)/observability_kill_marshal_test.h

# All headers combined
HEADERS = $(CORE_HEADERS) $(CALLBACK_HEADERS) $(REACTOR_HEADERS) $(NETWORK_HEADERS) $(DNS_HEADERS) $(SERVER_HEADERS) $(THREAD_POOL_HEADERS) $(UTIL_HEADERS) $(FOUNDATION_HEADERS) $(HTTP_HEADERS) $(HTTP2_HEADERS) $(WS_HEADERS) $(TLS_HEADERS) $(UPSTREAM_HEADERS) $(RATE_LIMIT_HEADERS) $(CIRCUIT_BREAKER_HEADERS) $(AUTH_HEADERS) $(CLI_HEADERS) $(OBSERVABILITY_HEADERS) $(TEST_HEADERS)

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
	rm -rf $(TARGET)* $(TSAN_TARGET) $(SERVER_TARGET) $(LLHTTP_OBJ) $(NGHTTP2_OBJ) *.dSYM *.plist

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

# Run only HTTP tests
test_http: $(TARGET)
	@echo "Running HTTP tests only..."
	./$(TARGET) http

# Run only WebSocket tests
test_ws: $(TARGET)
	@echo "Running WebSocket tests only..."
	./$(TARGET) ws

# Run only TLS tests
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

# Run the full proxy feature family (internal regressions + end-to-end engine)
test_proxy: $(TARGET)
	@echo "Running the full proxy feature family..."
	./$(TARGET) proxy

# Run only rate limit tests
test_rate_limit: $(TARGET)
	@echo "Running rate limit tests only..."
	./$(TARGET) rate_limit

# Run the full circuit-breaker feature family (umbrella — every CB sub-suite)
test_circuit_breaker: $(TARGET)
	@echo "Running the full circuit-breaker feature family..."
	./$(TARGET) circuit_breaker

# Run the full auth feature family (umbrella — every auth-related sub-suite)
test_auth: $(TARGET)
	@echo "Running the full auth feature family..."
	./$(TARGET) auth

# Auth foundation sub-suite (token_hasher / claims / policy matcher / config validation)
test_auth_foundation: $(TARGET)
	@echo "Running auth foundation sub-suite only..."
	./$(TARGET) auth_foundation

test_jwt: $(TARGET)
	@echo "Running JWT verifier unit tests only..."
	./$(TARGET) jwt

test_jwks: $(TARGET)
	@echo "Running JWKS cache unit tests only..."
	./$(TARGET) jwks

test_oidc: $(TARGET)
	@echo "Running OIDC discovery unit tests only..."
	./$(TARGET) oidc

test_hrauth: $(TARGET)
	@echo "Running header rewriter auth overlay tests only..."
	./$(TARGET) hrauth

test_auth_mgr: $(TARGET)
	@echo "Running AuthManager unit tests only..."
	./$(TARGET) auth_mgr

test_auth2: $(TARGET)
	@echo "Running auth integration tests only..."
	./$(TARGET) auth2

test_auth_fail: $(TARGET)
	@echo "Running auth failure mode tests only..."
	./$(TARGET) auth_fail

test_auth_reload: $(TARGET)
	@echo "Running auth reload tests only..."
	./$(TARGET) auth_reload

test_auth_multi: $(TARGET)
	@echo "Running auth multi-issuer tests only..."
	./$(TARGET) auth_multi

test_auth_ws: $(TARGET)
	@echo "Running auth WebSocket upgrade tests only..."
	./$(TARGET) auth_ws

test_auth_race: $(TARGET)
	@echo "Running auth race condition tests only..."
	./$(TARGET) auth_race

# Router async-middleware tests
test_router_async: $(TARGET)
	@echo "Running router async-middleware tests only..."
	./$(TARGET) router_async

# Introspection cache unit tests
test_introspection_cache: $(TARGET)
	@echo "Running introspection cache unit tests only..."
	./$(TARGET) introspection_cache

# Introspection client unit tests (static helpers + AsyncPendingState)
test_intro_client: $(TARGET)
	@echo "Running introspection client unit tests only..."
	./$(TARGET) intro_client

# Introspection integration tests (async middleware + mock IdP)
test_auth_intro: $(TARGET)
	@echo "Running introspection integration tests only..."
	./$(TARGET) auth_intro

# Run the full DNS / dual-stack feature family (DnsResolver primitives +
# dual-stack integration).
test_dns: $(TARGET)
	@echo "Running the full DNS / dual-stack feature family..."
	./$(TARGET) dns

# Sub-suite — dual-stack integration only (OS-sensitive). Used by the
# macOS CI subset; primitive timing tests excluded to avoid runner-load
# flake.
test_dual_stack: $(TARGET)
	@echo "Running dual-stack integration tests only..."
	./$(TARGET) dual_stack

# Sub-suite — DnsResolver primitives only (timing-sensitive).
test_dns_resolver: $(TARGET)
	@echo "Running DnsResolver primitives tests only..."
	./$(TARGET) dns_resolver

test_auth_observability: $(TARGET)
	@echo "Running auth observability tests only..."
	./$(TARGET) auth_observability

# H2 upstream client path tests (codec, H2ConnectionTable, pool snapshots,
# wire-level nghttp2 session tests via in-process socketpair).
test_h2_upstream: $(TARGET)
	@echo "Running H2 upstream client path tests only..."
	./$(TARGET) h2_upstream

# Per-suite OTel observability targets — each maps onto a flag the
# test runner already understands. `test_obs` chains every per-suite
# target (the runner doesn't ship an umbrella flag — unknown flags
# exit through the unknown-option path).
test_obs: test_obs_foundation test_obs_tracer test_obs_metrics \
          test_obs_mgr test_obs_propagator test_obs_jaeger_propagator \
          test_obs_export test_obs_prom test_obs_config test_obs_shutdown \
          test_obs_linkkill test_obs_issue test_obs_stress test_obs_e2e \
          test_obs_self_handler test_obs_proxy_client test_obs_auth_trace \
          test_obs_catalog test_obs_kill_marshal test_obs_ws_messages
	@echo "All observability suites passed."

test_obs_foundation: $(TARGET)
	@echo "Running observability foundation tests..."
	./$(TARGET) obs_foundation

test_obs_tracer: $(TARGET)
	@echo "Running observability tracer tests..."
	./$(TARGET) obs_tracer

test_obs_metrics: $(TARGET)
	@echo "Running observability metrics tests..."
	./$(TARGET) obs_metrics

test_obs_mgr: $(TARGET)
	@echo "Running observability manager tests..."
	./$(TARGET) obs_mgr

test_obs_propagator: $(TARGET)
	@echo "Running W3C propagator tests..."
	./$(TARGET) obs_propagator

test_obs_jaeger_propagator: $(TARGET)
	@echo "Running Jaeger propagator tests..."
	./$(TARGET) obs_jaeger_propagator

test_obs_export: $(TARGET)
	@echo "Running observability export pipeline tests..."
	./$(TARGET) obs_export

test_obs_prom: $(TARGET)
	@echo "Running Prometheus exporter tests..."
	./$(TARGET) obs_prom

test_obs_config: $(TARGET)
	@echo "Running observability config tests..."
	./$(TARGET) obs_config

test_obs_shutdown: $(TARGET)
	@echo "Running observability shutdown tests..."
	./$(TARGET) obs_shutdown

test_obs_linkkill: $(TARGET)
	@echo "Running observability link/kill tests..."
	./$(TARGET) obs_linkkill

test_obs_issue: $(TARGET)
	@echo "Running observability issue context tests..."
	./$(TARGET) obs_issue

test_obs_stress: $(TARGET)
	@echo "Running observability stress tests..."
	./$(TARGET) obs_stress

test_obs_e2e: $(TARGET)
	@echo "Running observability end-to-end tests..."
	./$(TARGET) obs_e2e

test_obs_self_handler: $(TARGET)
	@echo "Running observability self-handler shutdown tests..."
	./$(TARGET) obs_self_handler

test_obs_proxy_client: $(TARGET)
	@echo "Running observability proxy CLIENT-span tests..."
	./$(TARGET) obs_proxy_client

test_obs_auth_trace: $(TARGET)
	@echo "Running observability auth-trace tests..."
	./$(TARGET) obs_auth_trace

test_obs_catalog: $(TARGET)
	@echo "Running observability metrics-catalog tests..."
	./$(TARGET) obs_catalog

test_obs_ws_messages: $(TARGET)
	@echo "Running WebSocket per-message observability tests..."
	./$(TARGET) obs_ws_messages

# Thread-Sanitizer build for dual-stack stop/reload/destruction race tests.
# Builds a separate binary (test_runner_tsan) with -fsanitize=thread and
# runs the dual_stack TSAN subset (stop-vs-reload, teardown barrier,
# destructor race, abort-gate ordering).
#
# Usage:  make test_dual_stack_tsan
# Note:   TSAN + OpenSSL may emit benign suppressible reports for internal
#         OpenSSL initialisation on macOS (Apple system libraries are not
#         TSAN-instrumented).  Any report touching reactor or HttpServer code
#         is a real race.
TSAN_CXXFLAGS = $(CXXFLAGS) -fsanitize=thread
TSAN_LDFLAGS  = $(LDFLAGS) -fsanitize=thread
TSAN_TARGET   = test_runner_tsan

$(TSAN_TARGET): $(TEST_SRCS) $(HEADERS) $(LLHTTP_OBJ) $(NGHTTP2_OBJ)
	@echo "Building TSAN test runner ($(TSAN_TARGET))..."
	$(CXX) $(TSAN_CXXFLAGS) $(TEST_SRCS) $(LLHTTP_OBJ) $(NGHTTP2_OBJ) $(TSAN_LDFLAGS) -o $(TSAN_TARGET)

test_dual_stack_tsan: $(TSAN_TARGET)
	@echo "Running dual-stack TSAN tests (stop/reload/destruction) under ThreadSanitizer..."
	./$(TSAN_TARGET) dual_stack_tsan

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
	@echo "  make test_http   - Build and run only HTTP tests"
	@echo ""
	@echo "  make test_ws     - Build and run only WebSocket tests"
	@echo ""
	@echo "  make test_tls    - Build and run only TLS tests"
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

.PHONY: all clean test server test_basic test_stress test_race test_config test_http test_ws test_tls test_cli test_http2 test_upstream test_proxy test_rate_limit test_circuit_breaker test_auth test_auth_foundation test_jwt test_jwks test_oidc test_hrauth test_auth_mgr test_auth2 test_auth_fail test_auth_reload test_auth_multi test_auth_ws test_auth_race test_router_async test_introspection_cache test_intro_client test_auth_intro test_dns test_dual_stack test_dual_stack_tsan test_dns_resolver test_auth_observability test_h2_upstream test_obs test_obs_foundation test_obs_tracer test_obs_metrics test_obs_mgr test_obs_propagator test_obs_jaeger_propagator test_obs_export test_obs_prom test_obs_config test_obs_shutdown test_obs_linkkill test_obs_issue test_obs_stress test_obs_e2e help
