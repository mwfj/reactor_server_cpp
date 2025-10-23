# make                  # Build the executable
# make clean            # Remove build artifacts
# make test             # Build and run all tests
# make test-server      # Build and run server test
# make test-client      # Build and run client test
# make test-integrated  # Build and run integrated test
# make test-edge        # Build and run edge-triggered mode test
# make test-error       # Build and run error test
# make test-performance # Build and run performance test (5000 clients)

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -g -Wall -Iinclude
LDFLAGS = -lpthread

# Directories
SERVER_DIR = server
LIB_DIR = include
TEST_DIR = test

# Target executable
TARGET = run

# Source files (organized by component)
# Core reactor components
REACTOR_SRCS = $(SERVER_DIR)/dispatcher.cc $(SERVER_DIR)/epoll_handler.cc $(SERVER_DIR)/channel.cc

# Network components
NETWORK_SRCS = $(SERVER_DIR)/socket_handler.cc $(SERVER_DIR)/acceptor.cc $(SERVER_DIR)/connection_handler.cc

# Server and buffer
SERVER_SRCS = $(SERVER_DIR)/net_server.cc $(SERVER_DIR)/buffer.cc

# Application code
APP_SRCS = $(SERVER_DIR)/reactor_server.cc $(TEST_DIR)/test_framework.cc $(TEST_DIR)/framework_test.cc

# All sources combined
SRCS = $(REACTOR_SRCS) $(NETWORK_SRCS) $(SERVER_SRCS) $(APP_SRCS)

# Header files (organized by category)
CORE_HEADERS = $(LIB_DIR)/common.h $(LIB_DIR)/inet_addr.h
REACTOR_HEADERS = $(LIB_DIR)/dispatcher.h $(LIB_DIR)/epoll_handler.h $(LIB_DIR)/channel.h
NETWORK_HEADERS = $(LIB_DIR)/socket_handler.h $(LIB_DIR)/acceptor.h $(LIB_DIR)/connection_handler.h
SERVER_HEADERS = $(LIB_DIR)/net_server.h $(LIB_DIR)/buffer.h $(LIB_DIR)/reactor_server.h
TEST_HEADERS = $(LIB_DIR)/client.h

# All headers combined
HEADERS = $(CORE_HEADERS) $(REACTOR_HEADERS) $(NETWORK_HEADERS) $(SERVER_HEADERS) $(TEST_HEADERS)

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SRCS) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LDFLAGS) -o $(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET)

# Run all tests
test: $(TARGET)
	./$(TARGET)

# Run specific test modes
test-server: $(TARGET)
	./$(TARGET) server

test-client: $(TARGET)
	./$(TARGET) client

test-integrated: $(TARGET)
	./$(TARGET) integrated

test-edge: $(TARGET)
	./$(TARGET) edge

test-error: $(TARGET)
	./$(TARGET) error

test-performance: $(TARGET)
	./$(TARGET) performance

# Phony targets
.PHONY: all clean test test-server test-client test-integrated test-edge test-error test-performance