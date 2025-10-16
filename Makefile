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
CXXFLAGS = -std=c++11 -g -Wall -Ilib
LDFLAGS = -lpthread

# Directories
SRC_DIR = src
LIB_DIR = lib

# Target executable
TARGET = run

# Source files (with src/ prefix)
SRCS = $(SRC_DIR)/server.cc $(SRC_DIR)/main.cc $(SRC_DIR)/socket_handler.cc \
       $(SRC_DIR)/channel.cc $(SRC_DIR)/epoll_handler.cc $(SRC_DIR)/dispatcher.cc \
       $(SRC_DIR)/acceptor.cc $(SRC_DIR)/connection_handler.cc

# Header files (with lib/ prefix for dependency tracking)
HEADERS = $(LIB_DIR)/server.h $(LIB_DIR)/client.h $(LIB_DIR)/common.h \
          $(LIB_DIR)/socket_handler.h $(LIB_DIR)/channel.h $(LIB_DIR)/epoll_handler.h \
          $(LIB_DIR)/inet_addr.h $(LIB_DIR)/dispatcher.h $(LIB_DIR)/acceptor.h \
          $(LIB_DIR)/connection_handler.h

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