#include "tlcgka.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static void u32(unsigned char **p, uint32_t n) {
    for (int i = 3; i >= 0; i--)
        *(*p)++ = (unsigned char)(n >> (8 * i));
}
static void uintval(unsigned char **p, uint64_t n) {
    *(*p)++ = 'i';
    for (int i = 7; i >= 0; i--)
        *(*p)++ = (unsigned char)(n >> (8 * i));
}
static int invoke(const char *op, unsigned char **state, size_t *size, const uint64_t *init) {
    size_t k = strlen(op), n = 5 + 5 + k + 5 + (init ? 27 : *size);
    unsigned char *req = malloc(n), *p = req, *out = NULL;
    size_t len = 0;
    if (!req)
        return 1;
    *p++ = 'l';
    u32(&p, 2);
    *p++ = 's';
    u32(&p, (uint32_t)k);
    memcpy(p, op, k);
    p += k;
    *p++ = 'l';
    u32(&p, init ? 3 : 1);
    if (init) {
        for (int i = 0; i < 3; i++)
            uintval(&p, init[i]);
    } else {
        memcpy(p, *state, *size);
        p += *size;
    }
    int rc = tlcgka_call(req, (size_t)(p - req), &out, &len);
    tlcgka_free(req, n);
    if (rc) {
        fprintf(stderr, "%s failed: %.*s\n", op, (int)len, out ? (char *)out : "");
        tlcgka_free(out, len);
        return 1;
    }
    tlcgka_free(*state, *size);
    *state = out;
    *size = len;
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2 || (!strcmp(argv[1], "--help"))) {
        printf("%s\nUsage: tlcgka_cli demo|membership|ordinary-membership [N=16 G=2 q=2 rounds=5]\n", tlcgka_version());
        return 0;
    }
    int ordinary = !strcmp(argv[1], "ordinary-membership");
    int membership = !strcmp(argv[1], "membership") || ordinary;
    if (strcmp(argv[1], "demo") && !membership)
        return 2;
    uint64_t config[3] = {16, 2, 2};
    for (int i = 0; i < 3 && i + 2 < argc; i++) {
        char *end;
        config[i] = strtoull(argv[i + 2], &end, 10);
        if (*end)
            return 2;
    }
    unsigned rounds = argc > 5 ? (unsigned)strtoul(argv[5], NULL, 10) : 5;
    unsigned char *state = NULL;
    size_t size = 0;
    int rc = invoke("demo.init", &state, &size, config);
    for (unsigned i = 0; i < rounds && !rc; i++)
        rc = invoke("demo.round", &state, &size, NULL);
    if (membership && !rc) {
        rc = invoke(ordinary ? "demo.add_ordinary" : "demo.add", &state, &size, NULL);
        for (unsigned i = 0; i < rounds && !rc; i++)
            rc = invoke("demo.round", &state, &size, NULL);
        if (!rc)
            rc = invoke(ordinary ? "demo.remove_ordinary" : "demo.remove", &state, &size, NULL);
        for (unsigned i = 0; i < rounds && !rc; i++)
            rc = invoke("demo.round", &state, &size, NULL);
    }
    if (!rc) {
        rc = invoke("demo.result", &state, &size, NULL);
        if (!rc) {
            printf("PASS %s: N=%llu G=%llu q=%llu, rounds=%u, all active keys and history digests "
                   "agree\n",
                   argv[1], (unsigned long long)config[0], (unsigned long long)config[1],
                   (unsigned long long)config[2], rounds);
        }
    }
    tlcgka_free(state, size);
    return rc;
}
