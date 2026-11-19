/* navit_selftest — known-answer oracle for mayhem/test.sh (mayhem/ layer, not upstream code).
 *
 *   navit_selftest map <type> <path>   dump every item of a navit map: item type, every attribute
 *                                      (attr_to_text) and every coordinate, one line each
 *   navit_selftest traffic <xml-file>  dump every TraFF message parsed from the file
 *   navit_selftest expr <expression>   evaluate a navit command-language expression (string, int,
 *                                      boolean) with an empty context
 *
 * test.sh diffs the dumps against committed golden files, so any change in what navit decodes
 * (or a program that does nothing) fails the suite. Built with upstream's normal flags. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "traffic.h"
#include "command.h"

extern void builtin_init(void);

static int dump_map(const char *type, char *path) {
    struct attr atype = {attr_type, {(char *)type}};
    struct attr adata = {attr_data, {path}};
    enum attr_type csv_types[] = {attr_id, attr_position_longitude, attr_position_latitude, attr_label, attr_phone,
                                  attr_none};
    struct attr acsv = {attr_attr_types, {(void *)csv_types}};
    struct attr aitem;
    struct attr *attrs[] = {&atype, &adata, NULL, NULL, NULL};
    struct map *m;
    struct map_rect *mr;
    struct item *item;
    int n = 0;

    if (!strcmp(type, "csv")) {
        aitem.type = attr_item_type;
        aitem.u.item_type = type_poi_custom0;
        attrs[2] = &acsv;
        attrs[3] = &aitem;
    }
    m = map_new(NULL, attrs);
    if (!m) {
        printf("map_new failed\n");
        return 1;
    }
    mr = map_rect_new(m, NULL);
    while ((item = map_rect_get_item(mr))) {
        struct attr attr;
        struct coord c;
        printf("item %s\n", item_to_name(item->type));
        item_attr_rewind(item);
        while (item_attr_get(item, attr_any, &attr)) {
            char *s = attr_to_text(&attr, m, 1);
            printf("  attr %s=%s\n", attr_to_name(attr.type), s ? s : "(null)");
            g_free(s);
        }
        /* The csv driver hands out its one coordinate on every call (it never reports the end), so the
         * dump stops after one coordinate for csv and after 1000 for the other drivers. */
        item_coord_rewind(item);
        for (int k = 0; k < (strcmp(type, "csv") ? 1000 : 1) && item_coord_get(item, &c, 1); k++)
            printf("  coord 0x%x 0x%x\n", c.x, c.y);
        n++;
    }
    map_rect_destroy(mr);
    map_destroy(m);
    printf("items %d\n", n);
    return 0;
}

static int dump_traffic(const char *path) {
    gchar *xml = NULL;
    struct traffic_message **msgs, **mp;
    int n = 0;
    if (!g_file_get_contents(path, &xml, NULL, NULL)) {
        printf("cannot read %s\n", path);
        return 1;
    }
    msgs = traffic_get_messages_from_xml_string(NULL, xml);
    for (mp = msgs; mp && *mp; mp++) {
        struct traffic_message *msg = *mp;
        printf("message %s cancel=%d forecast=%d replaces=%d events=%d location=%s\n", msg->id, msg->is_cancellation,
               msg->is_forecast, msg->replaced_count, msg->event_count, msg->location ? "yes" : "no");
        for (int i = 0; i < msg->event_count; i++) {
            struct traffic_event *ev = msg->events[i];
            printf("  event %s %s length=%d speed=%d si=%d\n", event_class_to_string(ev->event_class),
                   event_type_to_string(ev->type), ev->length, ev->speed, ev->si_count);
        }
        traffic_message_destroy(msg);
        n++;
    }
    g_free(msgs);
    g_free(xml);
    printf("messages %d\n", n);
    return 0;
}

static int eval_expr(char *expr) {
    struct attr ctx = {attr_none, {NULL}};
    int err_s = 0, err_i = 0, err_b = 0;
    char *s = command_evaluate_to_string(&ctx, expr, &err_s);
    int i = command_evaluate_to_int(&ctx, expr, &err_i);
    int b = command_evaluate_to_boolean(&ctx, expr, &err_b);
    printf("string=%s/%d int=%d/%d bool=%d/%d\n", s ? s : "(null)", err_s, i, err_i, b, err_b);
    g_free(s);
    return 0;
}

int main(int argc, char **argv) {
    atom_init();
    debug_init("navit_selftest");
    file_init();
    builtin_init();
    linguistics_init();
    geom_init();
    if (argc == 4 && !strcmp(argv[1], "map"))
        return dump_map(argv[2], argv[3]);
    if (argc == 3 && !strcmp(argv[1], "expr"))
        return eval_expr(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "traffic"))
        return dump_traffic(argv[2]);
    fprintf(stderr, "usage: %s map <type> <path> | traffic <xml> | expr <expression>\n", argv[0]);
    return 2;
}
