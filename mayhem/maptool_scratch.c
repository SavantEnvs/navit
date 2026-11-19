/*
 * Linked into the AFL maptool only (build/afl, the maptool_* targets).
 *
 * maptool writes its output (out.bin) and its temp directory (tempfile.c: mkdir
 * "maptool_<pid>.tmp", exit(1) on failure) into the current directory. When the fuzzer's working
 * directory is not writable, or a crashed run left a maptool_<pid>.tmp behind for a reused pid,
 * maptool exits before parsing and every input covers the same 66 edges.
 *
 * Before main() this constructor makes the -i input path absolute, then moves into a fresh
 * mkdtemp() directory under $TMPDIR (default /tmp), and cleans that directory up on exit or on a
 * sanitizer report. Under an AFL forkserver this runs once, before the fork, so the executions share
 * the directory: each forked child only empties it when it exits.
 */
#define _GNU_SOURCE
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

extern void __sanitizer_set_death_callback(void (*)(void)) __attribute__((weak));

static char scratch_dir[PATH_MAX];
static pid_t scratch_owner;

static int rm_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftw) {
    (void)sb;
    (void)flag;
    /* A forked child (AFL forkserver) empties the shared directory; only its creator removes it. */
    if (ftw->level > 0 || getpid() == scratch_owner)
        remove(path);
    return 0;
}

static void scratch_cleanup(void) {
    if (scratch_dir[0]) {
        nftw(scratch_dir, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
        scratch_dir[0] = 0;
    }
}

__attribute__((constructor)) static void maptool_scratch_init(int argc, char **argv, char **envp) {
    (void)envp;
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && argv[i + 1][0] != '/') {
            char *abs = realpath(argv[i + 1], NULL);
            if (abs)
                argv[i + 1] = abs;
        }
    }
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp)
        tmp = "/tmp";
    snprintf(scratch_dir, sizeof(scratch_dir), "%s/maptool-afl.XXXXXX", tmp);
    if (!mkdtemp(scratch_dir) || chdir(scratch_dir) != 0) {
        perror("maptool_scratch: cannot create a writable scratch directory");
        scratch_dir[0] = 0;
        return;
    }
    scratch_owner = getpid();
    atexit(scratch_cleanup);
    if (__sanitizer_set_death_callback)
        __sanitizer_set_death_callback(scratch_cleanup);
}
