/* Fuzz navit's bookmark and former-destination handling (navit/bookmarks.c), the files navit keeps
 * in its user data directory: bookmark.txt (folder tree built by bookmarks_new/bookmarks_load_hash),
 * destination.txt (read back by read_former_destinations_from_file + bookmarks_append_destinations,
 * which re-parses and rewrites it every time a destination is set). Both are textfile-format
 * lines, so the one input is written to both files.
 *
 * center.txt (bookmarks_set_center_from_file) is deliberately not fuzzed: on an empty file
 * getline() fails and bookmarks.c:426 runs g_strchomp() on the unterminated getline buffer, a heap
 * overflow that fires on the empty input and would stop every libFuzzer run before it starts. It
 * is reported in the integration PR.
 *
 * NAVIT_USER_DATADIR points at the harness scratch dir (set once, read-only afterwards); the
 * rewritten destination file goes to a separate name so the next input never sees it. */
#include "fuzz_common.h"
#include "bookmarks.h"
#include "transform.h"
#include "projection.h"

struct map *read_former_destinations_from_file(void);

static void walk_bookmarks(struct bookmarks *b, int depth) {
    struct item *item;
    GList *folders = NULL, *l;
    int guard = 0;
    bookmarks_item_rewind(b);
    while ((item = bookmarks_get_item(b)) && guard++ < 1000) {
        struct attr label;
        if (item->type == type_bookmark_folder && item_attr_get(item, attr_label, &label) && depth < 4)
            folders = g_list_append(folders, g_strdup(label.u.str));
    }
    for (l = folders; l; l = g_list_next(l)) {
        if (bookmarks_move_down(b, l->data)) {
            walk_bookmarks(b, depth + 1);
            bookmarks_move_up(b);
        }
    }
    g_list_free_full(folders, g_free);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int env_set;
    struct attr parent = {attr_navit, {NULL}};
    struct pcoord center = {projection_mg, 0x138999, 0x5d567c};
    struct transformation *trans;
    struct bookmarks *b;
    struct map *former;
    char *bm, *dest, *out;

    fuzz_navit_init();
    if (!env_set) {
        setenv("NAVIT_USER_DATADIR", fuzz_dir, 1);
        env_set = 1;
    }
    bm = fuzz_write_file("bookmark.txt", data, size);
    dest = fuzz_write_file("destination.txt", data, size);
    out = g_strdup_printf("%s/destination.out", fuzz_dir);

    trans = transform_new(&center, 16, 0);
    b = bookmarks_new(&parent, NULL, trans);
    if (b) {
        bookmarks_move_root(b);
        walk_bookmarks(b, 0);
        (void)bookmarks_get_bookmark_count(b);
        bookmarks_destroy(b);
    }
    former = read_former_destinations_from_file();
    if (former) {
        fuzz_walk_map(former, NULL, 0);
        bookmarks_append_destinations(former, out, &center, 1, type_former_destination, NULL, 5);
        map_destroy(former);
    }
    transform_destroy(trans);
    unlink(bm);
    unlink(dest);
    unlink(out);
    g_free(bm);
    g_free(dest);
    g_free(out);
    fuzz_reset_file_cache();
    return 0;
}
