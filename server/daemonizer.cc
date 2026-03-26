#include "cli/daemonizer.h"

#if !defined(_WIN32)

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void Daemonizer::Daemonize() {
    // ── First fork ──────────────────────────────────────────
    // Parent exits, child continues. Ensures child is not a
    // process group leader (required for setsid()).
    pid_t pid = fork();
    if (pid < 0) {
        std::fprintf(stderr, "Error: first fork() failed: %s\n", std::strerror(errno));
        _exit(1);
    }
    if (pid > 0) {
        // Parent: exit successfully. The launching shell sees exit code 0.
        _exit(0);
    }

    // ── Child: new session ──────────────────────────────────
    // Detach from controlling terminal, become session leader.
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
        // Intermediate child: exit.
        _exit(0);
    }

    // ── Grandchild: the actual daemon ───────────────────────

    // Restrict file creation: owner full, group read, other nothing.
    // Prevents log files and PID files from being world-writable.
    umask(027);

    // Change to root to avoid holding a mount point busy.
    if (chdir("/") < 0) {
        // Non-fatal: the daemon still works, it just might prevent
        // a filesystem unmount. stderr is still available at this point.
        std::fprintf(stderr, "Warning: chdir(\"/\") failed: %s\n", std::strerror(errno));
    }

    // Redirect stdin/stdout/stderr to /dev/null.
    // After this point, std::cerr and std::cout go nowhere.
    int devnull = open("/dev/null", O_RDWR);
    if (devnull < 0) {
        _exit(1);  // cannot continue without /dev/null
    }

    if (dup2(devnull, STDIN_FILENO) < 0 ||
        dup2(devnull, STDOUT_FILENO) < 0 ||
        dup2(devnull, STDERR_FILENO) < 0) {
        _exit(1);
    }

    if (devnull > STDERR_FILENO) {
        close(devnull);
    }

    // Return to caller in the grandchild. Caller proceeds with:
    // PidFile::Acquire, SignalHandler::Install, logging::Init, HttpServer.
}

#endif // !defined(_WIN32)
