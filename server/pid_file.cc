#include "cli/pid_file.h"
#include "cli/version.h"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <fcntl.h>
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
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        std::cerr << "Error: PID file '" << path
                  << "' is not a regular file\n";
        close(fd);
        return false;
    }

    // Reject files owned by a different user. In world-writable directories
    // like /tmp, another user could pre-create the file (even empty) to
    // interfere. O_CREAT creates files owned by our euid, so this check
    // passes for files we just created.
    if (st.st_uid != geteuid()) {
        std::cerr << "Error: PID file '" << path
                  << "' is owned by a different user\n";
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
//
// Security model: the flock probe is the authoritative check. If we
// cannot acquire the exclusive lock, a reactor_server instance holds it.
// The PID read from the file was written by the lock holder at startup.
//
// Known limitation (shared with nginx/haproxy): a same-user attacker
// who can write to the PID file can change the recorded PID. Advisory
// locks cannot prevent this. However, such an attacker can already
// kill same-user processes directly, so the PID file is not the
// weakest link. Cross-user tampering is prevented by file ownership.

pid_t PidFile::CheckRunning(const std::string& path) {
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
        // We got the lock — no server holds it. Unlink while we still
        // hold the lock to prevent a race where a new server acquires
        // the file between our close() and unlink().
        unlink(path.c_str());
        close(fd);
        return -1;
    }
    int flock_errno = errno;

    if (flock_errno != EWOULDBLOCK) {
        close(fd);
        return -1;
    }

    // Lock held by another process. Read PID from this fd.
    char buf[32];
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    close(fd);

    pid_t pid = ParsePidBuf(buf, n);
    // Return 0 when the lock proves something is running but the PID
    // content is unreadable/corrupt. Callers can distinguish:
    //   >0 = running with known PID
    //    0 = running but PID unknown
    //   -1 = not running
    return (pid > 0) ? pid : 0;
}
