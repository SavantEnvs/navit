/* Fuzz navit's TraFF traffic feed parser (navit/traffic.c): xml_parse_text plus the
 * message/location/event/supplementary-info builders, through the public
 * traffic_get_messages_from_xml_string(), which is what traffic backends feed received feeds to.
 * The traffic instance is not used by the parser (traffic.c:5870), so NULL is passed. Every
 * returned message is destroyed with traffic_message_destroy. */
#include "fuzz_common.h"
#include "traffic.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *xml;
    struct traffic_message **msgs;

    fuzz_navit_init();
    xml = g_malloc(size + 1);
    memcpy(xml, data, size);
    xml[size] = '\0';
    msgs = traffic_get_messages_from_xml_string(NULL, xml);
    if (msgs) {
        for (struct traffic_message **m = msgs; *m; m++)
            traffic_message_destroy(*m);
        g_free(msgs);
    }
    g_free(xml);
    return 0;
}
