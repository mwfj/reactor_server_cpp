#pragma once

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
    // Returns: >0 = running (known PID), 0 = locked but PID unreadable, -1 = not running.
    static pid_t CheckRunning(const std::string& path);

    // Like CheckRunning, but keeps the flock fd open so the caller can
    // verify the lock is still held when signaling the PID. The caller
    // must close lock_fd when done. On not-running, lock_fd is set to -1.
    static pid_t CheckRunningHoldLock(const std::string& path, int& lock_fd);

    PidFile() = delete;
};
