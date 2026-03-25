#include "cli/pid_file.h"
#include "cli/version.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <unistd.h>

// ── File-scope static state ──────────────────────────────────────

static int g_pid_fd = -1;
static std::string g_pid_path;

// ── Acquire ──────────────────────────────────────────────────────

bool PidFile::Acquire(const std::string& path) {
    int fd = open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        std::cerr << "Error: Cannot open PID file '" << path
                  << "': " << std::strerror(errno) << "\n";
        return false;
    }

    // Try to acquire an exclusive non-blocking lock
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            // Another process holds the lock — read its PID for the error message
            char buf[32];
            ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
            close(fd);
            if (n > 0) {
                buf[n] = '\0';
                std::cerr << "Error: " << REACTOR_SERVER_NAME
                          << " is already running (PID "
                          << std::atol(buf) << ")\n";
            } else {
                std::cerr << "Error: " << REACTOR_SERVER_NAME
                          << " is already running (PID file locked)\n";
            }
        } else {
            std::cerr << "Error: Cannot lock PID file '" << path
                      << "': " << std::strerror(errno) << "\n";
            close(fd);
        }
        return false;
    }

    // Lock acquired — write our PID
    if (ftruncate(fd, 0) != 0) {
        std::cerr << "Error: Cannot truncate PID file: "
                  << std::strerror(errno) << "\n";
        close(fd);
        return false;
    }

    dprintf(fd, "%d\n", static_cast<int>(getpid()));

    // Keep fd open (holds the flock) until Release()
    g_pid_fd = fd;
    g_pid_path = path;
    return true;
}

// ── Release ──────────────────────────────────────────────────────

void PidFile::Release() {
    if (g_pid_fd >= 0) {
        unlink(g_pid_path.c_str());
        close(g_pid_fd);  // implicitly releases flock
        g_pid_fd = -1;
        g_pid_path.clear();
    }
}

// ── ReadPid ──────────────────────────────────────────────────────

pid_t PidFile::ReadPid(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) {
        return -1;
    }

    buf[n] = '\0';
    char* end = nullptr;
    long pid = std::strtol(buf, &end, 10);
    if (end == buf || pid <= 0) {
        return -1;
    }

    return static_cast<pid_t>(pid);
}

// ── CheckRunning ─────────────────────────────────────────────────

pid_t PidFile::CheckRunning(const std::string& path) {
    pid_t pid = ReadPid(path);
    if (pid <= 0) {
        return -1;
    }

    if (kill(pid, 0) == 0) {
        // Process is alive (or we have permission to signal it)
        return pid;
    }

    if (errno == ESRCH) {
        // Process does not exist — stale PID file
        unlink(path.c_str());
        return -1;
    }

    if (errno == EPERM) {
        // Process exists but we lack permission to signal it
        return pid;
    }

    // Unexpected error — treat as not running
    return -1;
}
