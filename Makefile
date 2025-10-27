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
CXXFLAGS = -std=c++11 -g -Wall -Iinclude -Ithread_pool/include
LDFLAGS = -lpthread

# Directories
SERVER_DIR = server
LIB_DIR = include
TEST_DIR = test
THREAD_POOL_DIR = thread_pool

# Target executable
TARGET = run

# Source files (organized by component)
# Core reactor components
REACTOR_SRCS = $(SERVER_DIR)/dispatcher.cc $(SERVER_DIR)/epoll_handler.cc $(SERVER_DIR)/channel.cc

# Network components
NETWORK_SRCS = $(SERVER_DIR)/socket_handler.cc $(SERVER_DIR)/acceptor.cc $(SERVER_DIR)/connection_handler.cc

# Server and buffer
SERVER_SRCS = $(SERVER_DIR)/net_server.cc $(SERVER_DIR)/buffer.cc

# Thread pool sources
THREAD_POOL_SRCS = $(THREAD_POOL_DIR)/src/threadpool.cc $(THREAD_POOL_DIR)/src/threadtask.cc

# Application code
APP_SRCS = $(SERVER_DIR)/reactor_server.cc $(TEST_DIR)/test_framework.cc $(TEST_DIR)/run_test.cc

# All sources combined
SRCS = $(REACTOR_SRCS) $(NETWORK_SRCS) $(SERVER_SRCS) $(THREAD_POOL_SRCS) $(APP_SRCS)

# Header files (organized by category)
CORE_HEADERS = $(LIB_DIR)/common.h $(LIB_DIR)/inet_addr.h
REACTOR_HEADERS = $(LIB_DIR)/dispatcher.h $(LIB_DIR)/epoll_handler.h $(LIB_DIR)/channel.h
NETWORK_HEADERS = $(LIB_DIR)/socket_handler.h $(LIB_DIR)/acceptor.h $(LIB_DIR)/connection_handler.h
SERVER_HEADERS = $(LIB_DIR)/net_server.h $(LIB_DIR)/buffer.h $(LIB_DIR)/reactor_server.h
THREAD_POOL_HEADERS = $(THREAD_POOL_DIR)/include/threadpool.h $(THREAD_POOL_DIR)/include/threadtask.h
TEST_HEADERS = $(LIB_DIR)/client.h $(TEST_DIR)/test_framework.h $(TEST_DIR)/basic_test.h $(TEST_DIR)/stress_test.h $(TEST_DIR)/race_condition_test.h

# All headers combined
HEADERS = $(CORE_HEADERS) $(REACTOR_HEADERS) $(NETWORK_HEADERS) $(SERVER_HEADERS) $(THREAD_POOL_HEADERS) $(TEST_HEADERS)

# Default target
.DEFAULT_GOAL := all

all: $(TARGET)

# Build the executable
$(TARGET): $(SRCS) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LDFLAGS) -o $(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) run_race_test

# Run all tests
test: $(TARGET)
	@echo "Running test suite..."
	./$(TARGET)

# Build standalone race condition test executable
race_test: $(REACTOR_SRCS) $(NETWORK_SRCS) $(SERVER_SRCS) $(THREAD_POOL_SRCS) $(SERVER_DIR)/reactor_server.cc $(TEST_DIR)/test_framework.cc $(TEST_DIR)/test_race_condition.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) $(REACTOR_SRCS) $(NETWORK_SRCS) $(SERVER_SRCS) $(THREAD_POOL_SRCS) $(SERVER_DIR)/reactor_server.cc $(TEST_DIR)/test_framework.cc $(TEST_DIR)/test_race_condition.cc $(LDFLAGS) -o run_race_test

# Run only race condition tests
test_race: race_test
	@echo "Running race condition tests..."
	./run_race_test

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
	@echo "                   Runs BasicTests (port 8888), StressTests (port 8889),"
	@echo "                   and RaceConditionTests (port 9000)"
	@echo ""
	@echo "  make test_race - Build and run only race condition tests"
	@echo "                   Creates './run_race_test' and runs 7 race condition tests"
	@echo "                   Validates fixes from EVENTFD_RACE_CONDITION_FIXES.md"
	@echo ""
	@echo "  make clean     - Remove build artifacts"
	@echo "                   Deletes './run' and './run_race_test' executables"
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
	@echo "  Thread Pool:   thread_pool/include/*.h thread_pool/src/*.cc"
	@echo "  Tests:         test/*.cc test/*.h"
	@echo "  Executable:    ./run"
	@echo ""
	@echo "Usage examples:"
	@echo "  make           # Build the project"
	@echo "  make clean     # Clean build artifacts"
	@echo "  make test      # Build and run all tests"
	@echo "  make test_race # Run only race condition tests"
	@echo "  ./run          # Run all tests directly (after building)"
	@echo ""
	@echo "For more information, see README.md and test/RACE_CONDITION_TESTS_README.md"

# Phony targets
.PHONY: all clean test test_race race_test help