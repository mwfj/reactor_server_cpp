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
APP_SRCS = $(SERVER_DIR)/reactor_server.cc $(TEST_DIR)/test_framework.cc $(TEST_DIR)/run_test.cc

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
.DEFAULT_GOAL := all

all: $(TARGET)

# Build the executable
$(TARGET): $(SRCS) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LDFLAGS) -o $(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET)

# Run all tests
test: $(TARGET)
	@echo "Running test suite..."
	./$(TARGET)

# Display help information
help:
	@echo "Reactor Server C++ - Makefile Help"
	@echo "===================================="
	@echo ""
	@echo "Available targets:"
	@echo "  make [all]     - Build the project (default target)"
	@echo "                   Compiles all source files and creates './run' executable"
	@echo ""
	@echo "  make test      - Build and run all tests"
	@echo "                   Runs BasicTests (port 8888) and StressTests (port 8889)"
	@echo ""
	@echo "  make clean     - Remove build artifacts"
	@echo "                   Deletes the './run' executable"
	@echo ""
	@echo "  make help      - Show this help message"
	@echo ""
	@echo "Build configuration:"
	@echo "  Compiler:      $(CXX)"
	@echo "  C++ Standard:  C++11"
	@echo "  Flags:         $(CXXFLAGS)"
	@echo "  Linker:        $(LDFLAGS)"
	@echo ""
	@echo "Project structure:"
	@echo "  Headers:       include/*.h"
	@echo "  Source:        server/*.cc"
	@echo "  Tests:         test/*.cc test/*.h"
	@echo "  Executable:    ./run"
	@echo ""
	@echo "Usage examples:"
	@echo "  make           # Build the project"
	@echo "  make clean     # Clean build artifacts"
	@echo "  make test      # Build and run tests"
	@echo "  ./run          # Run tests directly (after building)"
	@echo ""
	@echo "For more information, see README.md"

# Phony targets
.PHONY: all clean test help