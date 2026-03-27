#include "cli/daemonizer.h"

#if !defined(_WIN32)

#include "common.h"
// <cstring>, <cerrno>/<errno.h>, <fcntl.h>, <sys/types.h>, <unistd.h>
// provided by common.h
#include <cstdio>      // std::fprintf
#include <cstdlib>     // _exit
#include <sys/stat.h>  // umask

// Readiness pipe: grandchild writes a status byte, parent reads it.
// [0] = read end (parent), [1] = write end (grandchild).
static int g_ready_pipe[2] = {-1, -1};

void Daemonizer::Daemonize() {
    // Create the readiness pipe before forking so both parent and
    // grandchild inherit the fds. Parent reads; grandchild writes.
    if (pipe(g_ready_pipe) < 0) {
        std::fprintf(stderr, "Error: pipe() failed: %s\n", std::strerror(errno));
        _exit(1);
    }

    // ── First fork ──────────────────────────────────────────
    // Parent waits for readiness signal, child continues.
    pid_t pid = fork();
    if (pid < 0) {
        std::fprintf(stderr, "Error: first fork() failed: %s\n", std::strerror(errno));
        _exit(1);
    }
    if (pid > 0) {
        // Parent: close write end, wait for grandchild's status byte.
        close(g_ready_pipe[1]);
        unsigned char status = 1;
        ssize_t n;
        // Retry on EINTR — a stray signal during the blocking read must not
        // cause a false failure report to the launching shell.
        do {
            n = read(g_ready_pipe[0], &status, 1);
        } while (n < 0 && errno == EINTR);
        close(g_ready_pipe[0]);
        // n==0: grandchild died without writing (pipe closed) → failure
        // n==1: got status byte (0 = success, nonzero = failure)
        _exit((n == 1 && status == 0) ? 0 : 1);
    }

    // ── Child: close read end ───────────────────────────────
    close(g_ready_pipe[0]);
    g_ready_pipe[0] = -1;

    // ── Child: new session ──────────────────────────────────
    if (setsid() < 0) {
        std::fprintf(stderr, "Error: setsid() failed: %s\n", std::strerror(errno));
        _exit(1);
    }

    // ── Second fork ─────────────────────────────────────────
    // Grandchild is not a session leader, so it cannot
    // re-acquire a controlling terminal (System V semantics).
    pid = fork();
    if (pid < 0) {
        std::fprintf(stderr, "Error: second fork() failed: %s\n", std::strerror(errno));
        _exit(1);
    }
    if (pid > 0) {
        // Intermediate child: exit. The write end of the pipe is
        // inherited by the grandchild (dup'd across fork).
        _exit(0);
    }

    // ── Grandchild: the actual daemon ───────────────────────

    // Restrict file creation: owner full, group read, other nothing.
    umask(027);

    // Change to root to avoid holding a mount point busy.
    if (chdir("/") < 0) {
        std::fprintf(stderr, "Warning: chdir(\"/\") failed: %s\n", std::strerror(errno));
    }

    // Redirect stdin/stdout/stderr to /dev/null.
    int devnull = open("/dev/null", O_RDWR);
    if (devnull < 0) {
        _exit(1);
    }

    if (dup2(devnull, STDIN_FILENO) < 0 ||
        dup2(devnull, STDOUT_FILENO) < 0 ||
        dup2(devnull, STDERR_FILENO) < 0) {
        _exit(1);
    }

    if (devnull > STDERR_FILENO) {
        close(devnull);
    }

    // Return to caller in the grandchild. Caller proceeds with
    // startup and MUST call NotifyReady() or NotifyFailed().
}

void Daemonizer::NotifyReady() {
    if (g_ready_pipe[1] >= 0) {
        unsigned char status = 0;  // success
        (void)write(g_ready_pipe[1], &status, 1);
        close(g_ready_pipe[1]);
        g_ready_pipe[1] = -1;
    }
}

void Daemonizer::NotifyFailed() {
    if (g_ready_pipe[1] >= 0) {
        unsigned char status = 1;  // failure
        (void)write(g_ready_pipe[1], &status, 1);
        close(g_ready_pipe[1]);
        g_ready_pipe[1] = -1;
    }
}

#endif // !defined(_WIN32)
