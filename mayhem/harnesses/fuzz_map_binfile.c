/* Fuzz navit's binfile map driver (navit/map/binfile): the zip container (EOC/CD/LFH, zip64,
 * deflate/LZMA tiles) and the tile/item stream inside it, loaded as navit loads a .bin map:
 * map_new(type=binfile, data=<file>), then every item, attribute and coordinate is read, once over
 * the whole map, once through a world-wide selection (tile selection by order), and items are
 * re-fetched by id (map_rect_get_item_byid). */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct attr type = {attr_type, {"binfile"}};
    struct attr adata;
    struct attr *attrs[] = {&type, &adata, NULL};
    struct map *m;
    char *path;

    fuzz_navit_init();
    path = fuzz_write_file("input.bin", data, size);
    adata.type = attr_data;
    adata.u.str = path;
    m = map_new(NULL, attrs);
    if (m) {
        struct map_selection sel;
        memset(&sel, 0, sizeof(sel));
        sel.u.c_rect.lu.x = -0x7fffffff;
        sel.u.c_rect.lu.y = 0x7fffffff;
        sel.u.c_rect.rl.x = 0x7fffffff;
        sel.u.c_rect.rl.y = -0x7fffffff;
        sel.order = 18;
        sel.range.min = type_none;
        sel.range.max = type_last;
        fuzz_walk_map(m, NULL, 1);
        fuzz_walk_map(m, &sel, 0);
        map_destroy(m);
    }
    unlink(path);
    g_free(path);
    fuzz_reset_file_cache();
    return 0;
}
