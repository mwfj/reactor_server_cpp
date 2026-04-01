#pragma once

// Common C++ headers (available on all platforms)
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <string.h>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <utility>
#include <chrono>
#include <thread>
#include <mutex>
#include <vector>
#include <deque>
#include <memory>
#include <functional>
#include <map>
#include <unordered_map>
#include <atomic>

// Support cross-platform (current support Linux & macOS)
// Common system-level library
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Platform detection
#if defined(__linux__)
    // Linux
    #include <sys/epoll.h>      
    #include <sys/eventfd.h>
    #include <sys/timerfd.h> 

#elif defined(__APPLE__) || defined(__MACH__)
    // macOS uses kqueue instead of epoll
    #include <sys/event.h>
    #include <sys/time.h>
// NOT Support Windows Currently
// #elif _WIN32
//     // Windows
//     #define WIN32_LEAN_AND_MEAN
//     #include <winsock2.h>
//     #include <ws2tcpip.h>
//     #include <windows.h>
//     #pragma comment(lib, "ws2_32.lib")
    
    // Windows doesn't have these POSIX headers
    // #include <unistd.h>     // Use _close(), _read(), _write() instead
    // #include <signal.h>     // Use Windows equivalents
    
// Map POSIX-like functions to Windows equivalents
//     #define close closesocket
//     typedef int socklen_t;    
#else
    #error "Unsupported platform"
#endif

// Platform-safe send flags to suppress SIGPIPE
#if defined(__linux__)
    #define SEND_FLAGS MSG_NOSIGNAL
#else
    // macOS: SO_NOSIGPIPE is set per-socket in SocketHandler::SetNonBlocking()
    #define SEND_FLAGS 0
#endif

#define MAX_BUFFER_SIZE 1024
#define MAX_REPLY_SIZE 50
#define NUMBER_OF_CHILD_PROCESSES 25
#define MAX_CONNECTIONS 10000  // Maximum concurrent connections (epoll scales beyond FD_SETSIZE)
#define MAX_EVENT_NUMS 1000 // Max events to process per epoll_wait/kevent call

// Platform-agnostic event constants
// These map to the underlying platform's event system (epoll on Linux, kqueue on macOS)
#if defined(__linux__)
    // Linux: Use epoll constants directly
    #define EVENT_READ      EPOLLIN
    #define EVENT_WRITE     EPOLLOUT
    #define EVENT_ET        EPOLLET      // Edge-triggered mode
    #define EVENT_RDHUP     EPOLLRDHUP   // Peer closed connection
    #define EVENT_HUP       EPOLLHUP     // Hangup
    #define EVENT_ERR       EPOLLERR     // Error condition
    #define EVENT_PRI       EPOLLPRI     // Priority data
#elif defined(__APPLE__) || defined(__MACH__)
    // macOS: Define kqueue-compatible constants
    // Note: kqueue uses separate filters (EVFILT_READ/EVFILT_WRITE) not bitflags
    // These are bit positions for our internal event_ field in Channel
    #define EVENT_READ      0x001        // Read event
    #define EVENT_WRITE     0x002        // Write event
    #define EVENT_ET        0x004        // Edge-triggered (kqueue is always edge-triggered)
    #define EVENT_RDHUP     0x008        // Read hang-up (EOF condition)
    #define EVENT_HUP       0x010        // Hangup
    #define EVENT_ERR       0x020        // Error condition
    #define EVENT_PRI       0x040        // Priority data
#endif