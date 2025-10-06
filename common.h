#pragma once

// Platform detection
#ifdef _WIN32
    // Windows
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    
    // Windows doesn't have these POSIX headers
    // #include <unistd.h>     // Use _close(), _read(), _write() instead
    // #include <signal.h>     // Use Windows equivalents
    
    // Map POSIX-like functions to Windows equivalents
    #define close closesocket
    typedef int socklen_t;
    
#elif defined(__APPLE__) || defined(__MACH__)
    // macOS
    #include <sys/socket.h>
    #include <unistd.h>
    #include <signal.h>
    #include <sys/wait.h>
    #include <fcntl.h>
    #include <netinet/tcp.h>
    #include <errno.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/types.h>
    #include <string.h>
    
    // macOS uses kqueue instead of epoll
    #include <sys/event.h>
    #include <sys/time.h>
    
#elif defined(__linux__)
    // Linux
    #include <sys/socket.h>
    #include <unistd.h>
    #include <signal.h>
    #include <sys/wait.h>
    #include <sys/epoll.h>
    #include <fcntl.h>
    #include <netinet/tcp.h>
    #include <errno.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/types.h>
    #include <string.h>
    
#else
    #error "Unsupported platform"
#endif

// Common headers (available on all platforms)
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <chrono>
#include <thread>

#define MAX_BUFFER_SIZE 1024
#define MAX_REPLY_SIZE 50
#define NUMBER_OF_CHILD_PROCESSES 25
#define MAX_CONNECTIONS 10000  // Maximum concurrent connections (epoll scales beyond FD_SETSIZE)
#define MAX_EPOLL_EVENTS 1000  // Max events to process per epoll_wait call