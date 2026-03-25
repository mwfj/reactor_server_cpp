#include "cli/pid_file.h"
#include "cli/version.h"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

// ── File-scope static state ──────────────────────────────────────

static int g_pid_fd = -1;
static std::string g_pid_path;

// ── Shared PID parsing helper ────────────────────────────────────
// Parses a PID from a buffer. Rejects overflow, non-positive values,
// and trailing non-whitespace (e.g. "123abc"). Returns -1 on failure.
static pid_t ParsePidBuf(const char* buf, ssize_t len) {
    if (len <= 0) {
        return -1;
    }

    // Need a null-terminated copy for strtol
    char tmp[32];
    if (len >= static_cast<ssize_t>(sizeof(tmp))) {
        return -1;
    }
    std::memcpy(tmp, buf, static_cast<size_t>(len));
    tmp[len] = '\0';

    errno = 0;
    char* end = nullptr;
    long pid = std::strtol(tmp, &end, 10);

    if (end == tmp || errno == ERANGE || pid <= 0 || pid > INT_MAX) {
        return -1;
    }
    while (*end != '\0') {
        if (*end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') {
            return -1;
        }
        ++end;
    }

    return static_cast<pid_t>(pid);
}

// Validate that an open fd refers to a regular file.
static bool IsRegularFile(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
}

// ── Acquire ──────────────────────────────────────────────────────

bool PidFile::Acquire(const std::string& path) {
    int fd = open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, 0644);
    if (fd < 0) {
        std::cerr << "Error: Cannot open PID file '" << path
                  << "': " << std::strerror(errno) << "\n";
        return false;
    }

    // Reject non-regular files (attacker could pre-create a FIFO/device)
    if (!IsRegularFile(fd)) {
        std::cerr << "Error: PID file '" << path
                  << "' is not a regular file\n";
        close(fd);
        return false;
    }

    // Try to acquire an exclusive non-blocking lock
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            char buf[32];
            ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
            close(fd);
            pid_t rival = (n > 0) ? ParsePidBuf(buf, n) : -1;
            if (rival > 0) {
                std::cerr << "Error: " << REACTOR_SERVER_NAME
                          << " is already running (PID " << rival << ")\n";
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

    if (dprintf(fd, "%d\n", static_cast<int>(getpid())) < 0) {
        std::cerr << "Error: Cannot write PID: " << std::strerror(errno) << "\n";
        close(fd);
        return false;
    }

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
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }

    if (!IsRegularFile(fd)) {
        close(fd);
        return -1;
    }

    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    return ParsePidBuf(buf, n);
}

// ── CheckRunning ─────────────────────────────────────────────────

// On Linux, verify that process `pid` actually holds an fd open on the
// same inode as `pid_fd`. This guards against PID file content tampering
// where the file says one PID but the flock is held by a different process.
static bool VerifyLockHolder(pid_t pid, int pid_fd) {
#if defined(__linux__)
    struct stat pid_file_st;
    if (fstat(pid_fd, &pid_file_st) != 0) {
        return false;
    }

    // Scan /proc/<pid>/fd/ for an fd pointing to the same inode
    char proc_dir[64];
    std::snprintf(proc_dir, sizeof(proc_dir), "/proc/%d/fd", static_cast<int>(pid));
    int dfd = open(proc_dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        // Can't read /proc/<pid>/fd — the PID in the file may be
        // tampered, so reject rather than trust unverifiable content
        return false;
    }
    close(dfd);

    // Scan fd numbers 0-255 for a matching inode
    // (the server holds the PID file on a low fd)
    for (int i = 0; i < 256; ++i) {
        char link_path[80];
        struct stat link_st;
        std::snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d",
                      static_cast<int>(pid), i);
        if (stat(link_path, &link_st) == 0 &&
            link_st.st_dev == pid_file_st.st_dev &&
            link_st.st_ino == pid_file_st.st_ino) {
            return true;
        }
    }
    return false;
#else
    // macOS: no /proc, fall back to kill check
    (void)pid_fd;
    return (kill(pid, 0) == 0 || errno == EPERM);
#endif
}

pid_t PidFile::CheckRunning(const std::string& path) {
    // Single open: flock probe + PID read on the same fd to eliminate
    // the TOCTOU window where file content could change between reads.
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }

    if (!IsRegularFile(fd)) {
        close(fd);
        return -1;
    }

    // Probe the flock to determine if a reactor_server instance holds it.
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        // We got the lock — no server holds it (stale PID file)
        flock(fd, LOCK_UN);
        close(fd);
        unlink(path.c_str());
        return -1;
    }
    int flock_errno = errno;

    if (flock_errno != EWOULDBLOCK) {
        close(fd);
        return -1;
    }

    // Lock held by another process. Read PID from THIS fd.
    char buf[32];
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    pid_t pid = ParsePidBuf(buf, n);

    if (pid <= 0) {
        close(fd);
        return -1;
    }

    // Verify the PID in the file is actually the process holding the flock.
    // Defends against content tampering (advisory locks don't prevent writes).
    if (!VerifyLockHolder(pid, fd)) {
        close(fd);
        return -1;
    }

    close(fd);
    return pid;
}
