CXX := g++
CXXFLAGS := -std=c++11 -g -Wall -Wextra -Wpedantic -pthread
LDLIBS := -pthread

SRCS := main.cc threadpool.cc threadtask.cc
OBJS := $(SRCS:.cc=.o)
TARGET := run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDLIBS)

main.o: main.cc threadpool.h
threadpool.o: threadpool.cc threadpool.h
threadtask.o: threadtask.cc threadtask.h

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean