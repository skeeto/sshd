// Foundation: types, arenas, strings, buffers, slices, base64
// This is free and unencumbered software released into the public domain.

using u8   = unsigned char;
using i8   = signed char;
using u16  = decltype((unsigned short)0);
using i16  = decltype((short)0);
using b32  = decltype(0);
using i32  = decltype(0);
using u32  = decltype(0u);
using i64  = decltype(0ll);
using u64  = decltype(0ull);
using iz   = decltype((u8 *)0 - (u8 *)0);
using uz   = decltype(sizeof(0));
using byte = decltype('0');
using c16  = char16_t;

#define assert(c)   while (!(c)) __builtin_unreachable()
#define countof(a)  (iz)(sizeof(a) / sizeof(*(a)))

template<typename T>
void *operator new(uz, T *p) noexcept { return p; }

struct Arena {
    byte *beg = {};
    byte *end = {};
};

// Provided by the platform layer: report out-of-memory and exit.
[[noreturn]] static void os_oom();

template<typename T>
static T *alloc(Arena *a, iz count = 1)
{
    iz size = sizeof(T);
    iz pad  = -(uz)a->beg & (alignof(T) - 1);
    if (count < 0 || count >= (a->end - a->beg - pad)/size) {
        os_oom();
    }
    T *r = (T *)(a->beg + pad);
    a->beg += pad + count*size;
    for (iz i = 0; i < count; i++) {
        new (r+i) T();
    }
    return r;
}

// Like alloc<u8>, but does not zero the memory.
static u8 *allocbytes(Arena *a, iz count)
{
    if (count < 0 || count > a->end - a->beg) {
        os_oom();
    }
    u8 *r = (u8 *)a->beg;
    a->beg += count;
    return r;
}

static void copybytes(void *dst, void const *src, iz len)
{
    if (len) __builtin_memcpy(dst, src, (uz)len);
}


// Strings

struct Str {
    union {
        u8         *data = 0;
        char const *cdata;
    };
    iz len = 0;

    Str() = default;

    constexpr Str(u8 *data, iz len) : data{data}, len{len} {}

    template<iz N>
    constexpr Str(char const (&s)[N]) : cdata{s}, len{N-1} {}

    u8 &operator[](iz i)
    {
        assert(i >= 0 && i < len);
        return data[i];
    }

    bool operator==(Str s)
    {
        return len==s.len && (!len || !__builtin_memcmp(data, s.data, (uz)len));
    }
};

static Str span(u8 *beg, u8 *end)
{
    return {beg, end - beg};
}

// Wrap a null-terminated string (runtime length).
static Str cstr(char const *s)
{
    iz n = 0;
    while (s[n]) {
        n++;
    }
    return {(u8 *)s, n};
}

static Str trimleft(Str s)
{
    for (; s.len && (s.data[0]==' ' || s.data[0]=='\t' ||
                     s.data[0]=='\r' || s.data[0]=='\n'); s.data++, s.len--) {}
    return s;
}

static Str trimright(Str s)
{
    for (; s.len && (s.data[s.len-1]==' ' || s.data[s.len-1]=='\t' ||
                     s.data[s.len-1]=='\r' || s.data[s.len-1]=='\n'); s.len--) {}
    return s;
}

static Str trim(Str s)
{
    return trimleft(trimright(s));
}

// Consume and return the next whitespace-delimited token.
static Str nexttoken(Str *s)
{
    iz i = 0;
    while (i < s->len && (s->data[i]==' ' || s->data[i]=='\t')) {
        i++;
    }
    s->data += i;
    s->len  -= i;
    iz j = 0;
    while (j < s->len && s->data[j]!=' ' && s->data[j]!='\t') {
        j++;
    }
    Str tok = {s->data, j};
    s->data += j;
    s->len  -= j;
    return tok;
}

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = allocbytes(a, s.len);
    copybytes(r.data, s.data, s.len);
    return r;
}

// Case-insensitive ASCII equality.
static b32 iequals(Str a, Str b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (iz i = 0; i < a.len; i++) {
        u8 x = a[i], y = b[i];
        if (x>='A' && x<='Z') x += 32;
        if (y>='A' && y<='Z') y += 32;
        if (x != y) {
            return 0;
        }
    }
    return 1;
}


// Dynamic arrays

template<typename T>
struct Slice {
    T *data = {};
    iz len  = {};
    iz cap  = {};

    T &operator[](iz i)
    {
        assert(i >= 0 && i < len);
        return data[i];
    }
};

template<typename T>
static Slice<T> push(Arena *a, Slice<T> s, T v)
{
    if (s.len == s.cap) {
        if (!s.data || (byte *)(s.data+s.cap) != a->beg) {
            T *data = alloc<T>(a, s.cap);
            for (iz i = 0; i < s.len; i++) {
                data[i] = s.data[i];
            }
            s.data = data;
        }
        iz extend = s.cap ? s.cap : 8;
        alloc<T>(a, extend);
        s.cap += extend;
    }
    s.data[s.len++] = v;
    return s;
}


// Output buffers: appending grows in the arena, in place when possible.

struct Buf {
    u8    *data = {};
    iz     len  = {};
    iz     cap  = {};
    Arena *a    = {};

    Buf() = default;
    Buf(Arena *a, iz cap = 1<<12) : data{allocbytes(a, cap)}, cap{cap}, a{a} {}
};

static void reserve(Buf *b, iz need)
{
    if (b->cap - b->len >= need) {
        return;
    }
    Arena *a = b->a;
    iz extend = b->cap > need ? b->cap : need;
    if ((byte *)(b->data+b->cap) == a->beg) {
        allocbytes(a, extend);
    } else {
        u8 *data = allocbytes(a, b->cap+extend);
        copybytes(data, b->data, b->len);
        b->data = data;
    }
    b->cap += extend;
}

static void print(Buf *b, Str s)
{
    reserve(b, s.len);
    copybytes(b->data+b->len, s.data, s.len);
    b->len += s.len;
}

static void print(Buf *b, i64 v)
{
    u8  tmp[32];
    u8 *end = tmp + countof(tmp);
    u8 *beg = end;
    i64 t   = v<0 ? v : -v;
    do {
        *--beg = (u8)('0' - t%10);
    } while (t /= 10);
    if (v < 0) {
        *--beg = '-';
    }
    print(b, span(beg, end));
}

static Str finish(Buf *b)
{
    return {b->data, b->len};
}


// Base64

static i32 b64val(u8 c)
{
    if (c>='A' && c<='Z') return c - 'A';
    if (c>='a' && c<='z') return c - 'a' + 26;
    if (c>='0' && c<='9') return c - '0' + 52;
    if (c=='+') return 62;
    if (c=='/') return 63;
    return -1;
}

// Decode base64 into out[0..cap). Whitespace is skipped, '=' terminates.
static b32 b64decode(Str s, u8 *out, iz cap, iz *outlen)
{
    i32 acc  = 0;
    i32 nbit = 0;
    iz  n    = 0;
    for (iz i = 0; i < s.len; i++) {
        u8 c = s[i];
        if (c=='=' ) {
            break;
        }
        if (c==' ' || c=='\t' || c=='\r' || c=='\n') {
            continue;
        }
        i32 v = b64val(c);
        if (v < 0) {
            return 0;
        }
        acc = acc<<6 | v;
        nbit += 6;
        if (nbit >= 8) {
            nbit -= 8;
            if (n >= cap) {
                return 0;
            }
            out[n++] = (u8)(acc >> nbit);
        }
    }
    if (nbit >= 6) {
        return 0;  // leftover bits that do not form a byte are invalid
    }
    *outlen = n;
    return 1;
}

static Str b64encode(Arena *a, u8 const *data, iz len)
{
    static char const t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    iz  cap = (len + 2)/3*4;
    u8 *out = allocbytes(a, cap);
    iz  n   = 0;
    for (iz i = 0; i < len; i += 3) {
        u32 v = (u32)data[i]<<16;
        if (i+1 < len) v |= (u32)data[i+1]<<8;
        if (i+2 < len) v |= (u32)data[i+2];
        out[n++] = (u8)t[v>>18 & 63];
        out[n++] = (u8)t[v>>12 & 63];
        out[n++] = i+1<len ? (u8)t[v>>6 & 63] : '=';
        out[n++] = i+2<len ? (u8)t[v & 63] : '=';
    }
    return {out, n};
}