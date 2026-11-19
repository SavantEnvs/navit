/* Fuzz navit's textfile map driver (navit/map/textfile): the line format shared by map .txt
 * files, bookmark.txt and destination.txt (attr_from_line, attr_new_from_text, coord_parse, item
 * type names). Loaded via map_new(type=textfile, data=<file>); every item, attribute and coordinate
 * is read and printed back with attr_to_text, then items are re-fetched by id. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct attr type = {attr_type, {"textfile"}};
    struct attr adata;
    struct attr *attrs[] = {&type, &adata, NULL};
    struct map *m;
    char *path;

    fuzz_navit_init();
    path = fuzz_write_file("input.txt", data, size);
    adata.type = attr_data;
    adata.u.str = path;
    m = map_new(NULL, attrs);
    if (m) {
        fuzz_walk_map(m, NULL, 1);
        map_destroy(m);
    }
    unlink(path);
    g_free(path);
    fuzz_reset_file_cache();
    return 0;
}
