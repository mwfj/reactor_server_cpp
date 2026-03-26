#pragma once

inline constexpr const char* REACTOR_SERVER_VERSION = "1.0.0";
inline constexpr const char* REACTOR_SERVER_NAME    = "reactor_server";

#if defined(__linux__)
    inline constexpr const char* REACTOR_PLATFORM = "Linux";
#elif defined(__APPLE__) || defined(__MACH__)
    inline constexpr const char* REACTOR_PLATFORM = "macOS";
#else
    inline constexpr const char* REACTOR_PLATFORM = "Unsupported";
#endif
