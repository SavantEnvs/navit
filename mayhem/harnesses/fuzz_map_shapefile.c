/* Fuzz navit's shapefile map driver (navit/map/shapefile + the bundled shapelib in
 * navit/support/shapefile): SHPOpen/SHPReadObject over the .shp geometry and its .shx index,
 * loaded via map_new(type=shapefile, data=<basename>) and walked item by item.
 *
 * Input layout: [u32 little-endian length N][N bytes of .shp][rest = .shx].
 *
 * The .dbf attribute table is a fixed, valid one-column table written by this harness, not fuzz
 * input: map_new_shapefile() calls DBFGetFieldCount() on the result of DBFOpen() without a NULL
 * check (navit/map/shapefile/shapefile.c:611, shapelib dbfopen.c:1327 dereferences it), so any
 * missing or rejected .dbf crashes at open. Fuzzing the .dbf would stop at that one known bug on
 * nearly every input; it is reported in the integration PR instead. */
#include "fuzz_common.h"

static const unsigned char fixed_dbf[] = {
    0x03, 0x7d, 0x01, 0x01,             /* version, YMD */
    0x00, 0x00, 0x00, 0x00,             /* 0 records */
    0x41, 0x00,                         /* header length 65 */
    0x0b, 0x00,                         /* record length 11 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    'N', 'A', 'M', 'E', 0, 0, 0, 0, 0, 0, 0, /* field name */
    'C', 0, 0, 0, 0,                    /* type, reserved */
    10, 0,                              /* length, decimals */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x0d, 0x1a};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct attr type = {attr_type, {"shapefile"}};
    struct attr adata;
    struct attr *attrs[] = {&type, &adata, NULL};
    struct map *m;
    char *shp, *shx, *dbf, *base;
    uint32_t n;

    if (size < 4)
        return -1;
    fuzz_navit_init();
    n = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    data += 4;
    size -= 4;
    if (n > size)
        n = size;
    shp = fuzz_write_file("input.shp", data, n);
    shx = fuzz_write_file("input.shx", data + n, size - n);
    dbf = fuzz_write_file("input.dbf", fixed_dbf, sizeof(fixed_dbf));
    base = g_strdup_printf("%s/input", fuzz_dir);
    adata.type = attr_data;
    adata.u.str = base;
    m = map_new(NULL, attrs);
    if (m) {
        fuzz_walk_map(m, NULL, 1);
        map_destroy(m);
    }
    unlink(shp);
    unlink(shx);
    unlink(dbf);
    g_free(shp);
    g_free(shx);
    g_free(dbf);
    g_free(base);
    fuzz_reset_file_cache();
    return 0;
}
