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
CXXFLAGS = -std=c++11 -g -Wall
LDFLAGS = -lpthread

# Target executable
TARGET = run

# Source files
SRCS = server.cc main.cc

# Header files (for dependency tracking)
HEADERS = server.h client.h common.h

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