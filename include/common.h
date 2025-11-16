#pragma once

// TODO: Supoort cross-platform(current support Linux only)

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
    #include <sys/event.h>
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
    #include <sys/eventfd.h>
    #include <sys/timerfd.h> 
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
#include <mutex>
#include <vector>
#include <memory>
#include <functional>
#include <map>
#include <atomic>

#define MAX_BUFFER_SIZE 1024
#define MAX_REPLY_SIZE 50
#define NUMBER_OF_CHILD_PROCESSES 25
#define MAX_CONNECTIONS 10000  // Maximum concurrent connections (epoll scales beyond FD_SETSIZE)
#define MAX_EVETN_NUMS 1000 // Max events to process per epoll_wait call

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