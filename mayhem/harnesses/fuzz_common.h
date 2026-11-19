/* Shared scaffolding for the navit libFuzzer harnesses (mayhem/ layer, not upstream code).
 *
 * Initialisation mirrors navit/start_real.c (atom, debug, file, builtin plugin registry,
 * linguistics, geom) so map drivers are reached through navit's public map_new() API exactly
 * as navit.xml <map type=... data=...> would reach them.
 *
 * Each input is written to a fresh scratch directory under $TMPDIR, so a map driver opens it by
 * path like it opens a real map file. State kept across inputs: the atom table and plugin
 * registry (read-only after init) and the file cache, which is reset after every input
 * (file_deinit/file_init) because it is keyed by file name and would otherwise serve the previous
 * input's bytes.
 */
#ifndef NAVIT_FUZZ_COMMON_H
#define NAVIT_FUZZ_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <glib.h>

#include "config.h"
#include "atom.h"
#include "attr.h"
#include "coord.h"
#include "item.h"
#include "map.h"
#include "file.h"
#include "debug.h"
#include "linguistics.h"
#include "geom.h"

extern void builtin_init(void);

static char fuzz_dir[4096];

static void fuzz_navit_init(void) {
    static int done;
    const char *tmp;
    if (done)
        return;
    done = 1;
    struct sigaction prev_segv;
    atom_init();
    /* debug_init() installs navit's own SIGSEGV handler, which prints a line and calls exit(1)
     * (navit/debug.c sigsegv). That turns every wild read into a clean "exit", hiding it from the
     * sanitizer and the fuzzer; restore the sanitizer's handler so a SEGV is reported as a crash. */
    sigaction(SIGSEGV, NULL, &prev_segv);
    debug_init("navit-fuzz");
    sigaction(SIGSEGV, &prev_segv, NULL);
    file_init();
    builtin_init();
    linguistics_init();
    geom_init();
    tmp = getenv("TMPDIR");
    if (!tmp || !*tmp)
        tmp = "/tmp";
    snprintf(fuzz_dir, sizeof(fuzz_dir), "%s/navit-fuzz-XXXXXX", tmp);
    if (!mkdtemp(fuzz_dir)) {
        perror("mkdtemp");
        abort();
    }
}

/* Write data to <scratch>/<name>; returns the g_malloc'd path. */
static char *fuzz_write_file(const char *name, const uint8_t *data, size_t size) {
    char *path = g_strdup_printf("%s/%s", fuzz_dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        abort();
    }
    if (size && fwrite(data, 1, size, f) != size) {
        perror("fwrite");
        abort();
    }
    fclose(f);
    return path;
}

static void fuzz_reset_file_cache(void) {
    file_deinit();
    file_init();
}

/* Read everything a consumer (the renderer, search, routing) reads from one item. */
static void fuzz_walk_item(struct map *m, struct item *item) {
    struct attr attr;
    struct coord c[64];
    int n, guard = 0;
    item_attr_rewind(item);
    while (item_attr_get(item, attr_any, &attr) && guard++ < 4096) {
        char *s = attr_to_text(&attr, m, 1);
        g_free(s);
    }
    item_coord_rewind(item);
    guard = 0;
    while ((n = item_coord_get(item, c, 64)) > 0 && guard++ < 4096) {
        /* touch the coordinates so they are really read */
        /* unsigned: summing attacker-controlled coordinates must not be signed overflow (UB) */
        volatile unsigned sink = 0;
        for (int i = 0; i < n; i++)
            sink += (unsigned)c[i].x ^ (unsigned)c[i].y;
        (void)sink;
    }
}

/* Iterate the whole map; with byid, re-fetch the first items by their ids. */
static void fuzz_walk_map(struct map *m, struct map_selection *sel, int byid) {
    struct map_rect *mr = map_rect_new(m, sel);
    struct item *item;
    int count = 0;
    int ids[32][2];
    int nids = 0;
    if (!mr)
        return;
    while ((item = map_rect_get_item(mr)) && count++ < 100000) {
        if (nids < 32) {
            ids[nids][0] = item->id_hi;
            ids[nids][1] = item->id_lo;
            nids++;
        }
        fuzz_walk_item(m, item);
    }
    map_rect_destroy(mr);
    if (!byid)
        return;
    for (int i = 0; i < nids; i++) {
        mr = map_rect_new(m, NULL);
        if (!mr)
            return;
        item = map_rect_get_item_byid(mr, ids[i][0], ids[i][1]);
        if (item)
            fuzz_walk_item(m, item);
        map_rect_destroy(mr);
    }
}

#endif
