#pragma once

// Lightweight CLI header — only needs <string> and pid_t (not in common.h).
#include <string>
#include <sys/types.h>

class PidFile {
public:
    // Acquire the PID file: write current PID, hold exclusive flock.
    // If the file is locked by another process, prints error and returns false.
    // Returns true on success.
    static bool Acquire(const std::string& path);

    // Release the PID file: remove file, release flock, close fd.
    // Safe to call multiple times.
    static void Release();

    // Read the PID from the file. Returns -1 if unreadable or missing.
    static pid_t ReadPid(const std::string& path);

    // Check if a PID file exists and its process is alive.
    // If stale (process dead), removes the file.
    // Returns the live PID, or -1 if not running.
    static pid_t CheckRunning(const std::string& path);

    PidFile() = delete;
};
