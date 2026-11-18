#include "internal.h"
_Thread_local Arena *arena;
void fail(const char *message) {
    arena->error = message;
    longjmp(arena->trap, 1);
}
void *mem(size_t n) {
    REQUIRE(n <= 256 * 1024 * 1024 && arena->used <= 256 * 1024 * 1024 - n, "allocation limit");
    Allocation *p = calloc(1, sizeof(*p) + (n ? n : 1));
    REQUIRE(p, "out of memory");
    p->size = n ? n : 1;
    p->next = arena->alloc;
    arena->alloc = p;
    arena->used += n;
    return p + 1;
}
static V *value(char t) {
    V *v = mem(sizeof(*v));
    v->t = t;
    return v;
}
V *nil(void) {
    return value('n');
}
V *num(uint64_t n) {
    V *v = value('i');
    v->u = n;
    return v;
}
V *boolean(int n) {
    return value(n ? 't' : 'f');
}
V *bytes(const void *p, size_t n) {
    V *v = value('b');
    v->n = n;
    v->b = mem(n);
    if (p && n)
        memcpy(v->b, p, n);
    return v;
}
V *str(const char *p) {
    V *v = bytes(p, strlen(p));
    v->t = 's';
    return v;
}
V *empty(void) {
    return value('l');
}
V *list(size_t n, ...) {
    V *v = empty();
    v->n = n;
    v->v = mem(n * sizeof(V *));
    va_list ap;
    va_start(ap, n);
    for (size_t i = 0; i < n; i++)
        v->v[i] = va_arg(ap, V *);
    va_end(ap);
    return v;
}
void push(V *v, V *x) {
    REQUIRE(v && v->t == 'l', "expected sequence");
    if (v->n >= v->capacity) {
        size_t cap = v->n ? 2 * v->n : 4;
        V **p = mem(cap * sizeof(V *));
        if (v->n)
            memcpy(p, v->v, v->n * sizeof(V *));
        v->v = p;
        v->capacity = cap;
    }
    v->v[v->n++] = x;
}
V *at_checked(V *v, size_t i, const char *file, int line) {
    if (!(v && v->t == 'l' && i < v->n)) {
        char *message = mem(512);
        snprintf(message, 512, "invalid tuple shape/index (%c[%zu]/%zu at %s:%d)", v ? v->t : '?',
                 i, v ? v->n : 0, file, line);
        fail(message);
    }
    return v->v[i];
}
void put(V *v, size_t i, V *x) {
    (void)at(v, i);
    v->v[i] = x;
}
uint64_t integer(V *v) {
    REQUIRE(v && v->t == 'i', "expected uint64");
    return v->u;
}
int truth(V *v) {
    return v && v->t != 'n' && v->t != 'f' &&
           ((v->t == 'i')                                 ? v->u != 0
            : (v->t == 'l' || v->t == 'b' || v->t == 's') ? v->n != 0
                                                          : 1);
}
int eq(V *a, V *b) {
    if (!a || !b)
        return a == b;
    if (a->t != b->t)
        return 0;
    if (a->t == 'i')
        return a->u == b->u;
    if (a->n != b->n)
        return 0;
    if (a->t == 'b' || a->t == 's')
        return !memcmp(a->b, b->b, a->n);
    if (a->t == 'l') {
        EACH(i, a) if (!eq(A(a, i), A(b, i))) return 0;
    }
    return 1;
}
int is(V *a, const char *s) {
    return a && a->t == 's' && a->n == strlen(s) && !memcmp(a->b, s, a->n);
}
V *clone(V *v) {
    if (v->t == 'l') {
        V *r = E;
        EACH(i, v) push(r, clone(A(v, i)));
        return r;
    }
    V *r = mem(sizeof(V));
    *r = *v;
    return r;
}
static int cmpv(V *a, V *b) {
    REQUIRE(a->t == b->t, "incomparable values");
    if (a->t == 'i')
        return (a->u > b->u) - (a->u < b->u);
    if (a->t == 'l') {
        size_t n = a->n < b->n ? a->n : b->n;
        for (size_t i = 0; i < n; i++) {
            int c = cmpv(A(a, i), A(b, i));
            if (c)
                return c;
        }
        return (a->n > b->n) - (a->n < b->n);
    }
    if (a->t == 'b' || a->t == 's') {
        size_t n = a->n < b->n ? a->n : b->n;
        int c = memcmp(a->b, b->b, n);
        return c ? c : (a->n > b->n) - (a->n < b->n);
    }
    return 0;
}
static int cmp(const void *a, const void *b) {
    return cmpv(*(V *const *)a, *(V *const *)b);
}
V *sort(V *v) {
    REQUIRE(v->t == 'l', "expected list");
    V *r = clone(v);
    if (r->n > 1)
        qsort(r->v, r->n, sizeof(V *), cmp);
    return r;
}
V *keys(V *m) {
    V *r = E;
    EACH(i, m) {
        shape(A(m, i), 2);
        push(r, A(A(m, i), 0));
    }
    return r;
}
V *get(V *m, V *k) {
    REQUIRE(m->t == 'l', "expected map");
    EACH(i, m) {
        shape(A(m, i), 2);
        if (eq(A(A(m, i), 0), k))
            return A(A(m, i), 1);
    }
    return Z;
}
V *need(V *m, V *k) {
    V *r = get(m, k);
    REQUIRE(r->t != 'n', "missing map entry");
    return r;
}
void set(V *m, V *k, V *v) {
    EACH(i, m) if (eq(A(A(m, i), 0), k)) {
        put(m, i, L(k, v));
        return;
    }
    push(m, L(k, v));
    if (m->n > 1)
        qsort(m->v, m->n, sizeof(V *), cmp);
}
void del(V *m, V *k) {
    EACH(i, m) if (eq(A(A(m, i), 0), k)) {
        memmove(m->v + i, m->v + i + 1, (m->n - i - 1) * sizeof(V *));
        m->n--;
        return;
    }
}
int contains(V *v, V *x) {
    EACH(i, v) if (eq(A(v, i), x)) return 1;
    return 0;
}
V *without(V *v, V *x) {
    V *r = E;
    EACH(i, v) if (!eq(A(v, i), x)) push(r, A(v, i));
    return r;
}
V *range(uint64_t start, uint64_t end) {
    REQUIRE(end >= start && end - start <= 1000000, "range too large");
    V *r = E;
    for (uint64_t i = start; i < end; i++)
        push(r, N(i));
    return r;
}
V *cat(V *a, V *b) {
    V *r = clone(a);
    EACH(i, b) push(r, A(b, i));
    return r;
}
void shape(V *v, size_t n) {
    REQUIRE(v && v->t == 'l' && v->n == n, "invalid tuple shape");
}
void blob(V *v, size_t n) {
    REQUIRE(v && v->t == 'b' && v->n == n, "invalid byte length");
}
void canonical_ids(V *v, int nonempty) {
    REQUIRE(v->t == 'l' && (!nonempty || v->n), "empty/invalid set");
    EACH(i, v) {
        integer(A(v, i));
        if (i)
            REQUIRE(integer(A(v, i - 1)) < integer(A(v, i)), "noncanonical set");
    }
}
static size_t wire_size(V *v, int depth) {
    REQUIRE(depth <= 32, "nesting limit");
    size_t n = 1;
    if (v->t == 'i')
        return 9;
    if (v->t == 'b' || v->t == 's')
        n += 4 + v->n;
    else if (v->t == 'l') {
        n += 4;
        EACH(i, v) {
            size_t k = wire_size(A(v, i), depth + 1);
            REQUIRE(n <= 64 * 1024 * 1024 - k, "wire limit");
            n += k;
        }
    }
    REQUIRE(n <= 64 * 1024 * 1024, "wire limit");
    return n;
}
static void be(unsigned char **p, uint64_t v, size_t n) {
    for (size_t i = n; i > 0; i--)
        *(*p)++ = (unsigned char)(v >> ((i - 1) * 8));
}
static void encode(V *v, unsigned char **p) {
    *(*p)++ = (unsigned char)v->t;
    if (v->t == 'i')
        be(p, v->u, 8);
    else if (v->t == 'b' || v->t == 's') {
        be(p, v->n, 4);
        memcpy(*p, v->b, v->n);
        *p += v->n;
    } else if (v->t == 'l') {
        be(p, v->n, 4);
        EACH(i, v) encode(A(v, i), p);
    }
}
V *pack(V *v) {
    V *r = bytes(NULL, wire_size(v, 0));
    unsigned char *p = r->b;
    encode(v, &p);
    return r;
}
static uint64_t read_be(const unsigned char **p, const unsigned char *end, size_t n) {
    REQUIRE((size_t)(end - *p) >= n, "truncated integer");
    uint64_t v = 0;
    while (n--)
        v = (v << 8) | *(*p)++;
    return v;
}
static int utf8(const unsigned char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint32_t c = p[i++];
        if (c < 128)
            continue;
        unsigned k;
        uint32_t min;
        if (c >= 0xc2 && c <= 0xdf) {
            k = 1;
            min = 128;
            c &= 31;
        } else if (c >= 0xe0 && c <= 0xef) {
            k = 2;
            min = 2048;
            c &= 15;
        } else if (c >= 0xf0 && c <= 0xf4) {
            k = 3;
            min = 65536;
            c &= 7;
        } else
            return 0;
        if (n - i < k)
            return 0;
        while (k--) {
            unsigned d = p[i++];
            if ((d & 0xc0) != 0x80)
                return 0;
            c = (c << 6) | (d & 63);
        }
        if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
            return 0;
    }
    return 1;
}
static V *decode(const unsigned char **p, const unsigned char *end, int depth) {
    REQUIRE(depth <= 32 && *p < end, "truncated/deep wire");
    char t = (char)*(*p)++;
    if (t == 'n')
        return Z;
    if (t == 't' || t == 'f')
        return boolean(t == 't');
    if (t == 'i')
        return N(read_be(p, end, 8));
    REQUIRE(t == 'b' || t == 's' || t == 'l', "invalid wire tag");
    size_t n = (size_t)read_be(p, end, 4);
    REQUIRE(n <= (size_t)(end - *p), "invalid wire length");
    if (t == 'l') {
        V *r = E;
        r->n = n;
        r->v = mem(n * sizeof(V *));
        for (size_t i = 0; i < n; i++)
            r->v[i] = decode(p, end, depth + 1);
        return r;
    }
    V *r = bytes(*p, n);
    r->t = t;
    *p += n;
    if (t == 's')
        REQUIRE(utf8(r->b, n), "invalid UTF-8");
    return r;
}
V *unpack(V *v) {
    REQUIRE(v->t == 'b' && v->n <= 64 * 1024 * 1024, "invalid wire buffer");
    const unsigned char *p = v->b, *end = p + v->n;
    V *r = decode(&p, end, 0);
    REQUIRE(p == end, "trailing wire bytes");
    return r;
}
