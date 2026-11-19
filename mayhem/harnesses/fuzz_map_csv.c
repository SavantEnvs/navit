/* Fuzz navit's csv map driver (navit/map/csv): line tokenizer, per-column attribute typing and
 * the quadtree it builds. Configured as a navit.xml <map type="csv"> for POIs would be:
 * attr_types = id,position_longitude,position_latitude,label,phone, item_type = poi_custom0.
 * Every item is read over the whole map, then items are re-fetched by id. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    enum attr_type types[] = {attr_id, attr_position_longitude, attr_position_latitude, attr_label,
                              attr_phone, attr_none};
    struct attr type = {attr_type, {"csv"}};
    struct attr atypes;
    struct attr itype;
    struct attr adata;
    struct attr *attrs[] = {&type, &atypes, &itype, &adata, NULL};
    struct map *m;
    char *path;

    fuzz_navit_init();
    path = fuzz_write_file("input.csv", data, size);
    atypes.type = attr_attr_types;
    atypes.u.attr_types = types;
    itype.type = attr_item_type;
    itype.u.item_type = type_poi_custom0;
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
