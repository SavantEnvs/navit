/* Fuzz navit's command/expression language (navit/command.c): the lexer, parser and evaluator that
 * navit.xml uses for OSD/gui conditions and values (e.g. osd enable_expression, command attributes).
 * The input is evaluated as an expression with command_evaluate_to_string, _to_int and _to_boolean,
 * the three entry points navit's config objects call. The evaluation context is an empty attr, so
 * object/attribute lookups resolve to nothing and no navit action can run. */
#include "fuzz_common.h"
#include "command.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct attr ctx = {attr_none, {NULL}};
    char *expr;
    char *s;
    int error = 0;

    fuzz_navit_init();
    expr = g_malloc(size + 1);
    memcpy(expr, data, size);
    expr[size] = '\0';
    s = command_evaluate_to_string(&ctx, expr, &error);
    g_free(s);
    error = 0;
    (void)command_evaluate_to_int(&ctx, expr, &error);
    error = 0;
    (void)command_evaluate_to_boolean(&ctx, expr, &error);
    g_free(expr);
    return 0;
}
