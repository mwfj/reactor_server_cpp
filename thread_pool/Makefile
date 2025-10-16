CXX := g++
CXXFLAGS := -std=c++11 -g -Wall -Wextra -Wpedantic -pthread -Ilib
LDLIBS := -pthread

# Directories
SRC_DIR := src
LIB_DIR := lib

# Source files (with src/ prefix)
SRCS := $(SRC_DIR)/main.cc $(SRC_DIR)/threadpool.cc $(SRC_DIR)/threadtask.cc

# Object files (placed in src/ directory)
OBJS := $(SRC_DIR)/main.o $(SRC_DIR)/threadpool.o $(SRC_DIR)/threadtask.o

# Header files (with lib/ prefix)
HEADERS := $(LIB_DIR)/threadpool.h $(LIB_DIR)/threadtask.h

# Target executable
TARGET := run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDLIBS)

# Dependency rules with new paths
$(SRC_DIR)/main.o: $(SRC_DIR)/main.cc $(LIB_DIR)/threadpool.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SRC_DIR)/threadpool.o: $(SRC_DIR)/threadpool.cc $(LIB_DIR)/threadpool.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SRC_DIR)/threadtask.o: $(SRC_DIR)/threadtask.cc $(LIB_DIR)/threadtask.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean