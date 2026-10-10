// sshd - a minimal public-key-only SSH server for Windows
// $ cc -nostartfiles -o sshd.exe sshd.cpp -lws2_32
// This is free and unencumbered software released into the public domain.

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

// Crypto: SHA-256, SHA-512, ChaCha20, Poly1305, X25519, Ed25519
// This is free and unencumbered software released into the public domain.

static u32 rotr32(u32 x, i32 n) { return x>>n | x<<(32-n); }
static u64 rotr64(u64 x, i32 n) { return x>>n | x<<(64-n); }
static u32 rotl32(u32 x, i32 n) { return x<<n | x>>(32-n); }

static b32 ct_eq(u8 const *a, u8 const *b, iz len)
{
    u8 r = 0;
    for (iz i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }
    return r == 0;
}


// SHA-256

struct Sha256 {
    u32 h[8];
    u64 len;
    u8  buf[64];
    iz  n;
};

static void sha256_compress(Sha256 *s, u8 const *p)
{
    static u32 const k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    u32 w[64];
    for (i32 i = 0; i < 16; i++) {
        w[i] = (u32)p[4*i]<<24 | (u32)p[4*i+1]<<16 | (u32)p[4*i+2]<<8 | p[4*i+3];
    }
    for (i32 i = 16; i < 64; i++) {
        u32 a = w[i-15], b = w[i-2];
        u32 s0 = rotr32(a,7) ^ rotr32(a,18) ^ (a>>3);
        u32 s1 = rotr32(b,17) ^ rotr32(b,19) ^ (b>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u32 a=s->h[0], b=s->h[1], c=s->h[2], d=s->h[3];
    u32 e=s->h[4], f=s->h[5], g=s->h[6], h=s->h[7];
    for (i32 i = 0; i < 64; i++) {
        u32 S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        u32 ch = (e&f) ^ (~e&g);
        u32 t1 = h + S1 + ch + k[i] + w[i];
        u32 S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        u32 mj = (a&b) ^ (a&c) ^ (b&c);
        u32 t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void sha256_init(Sha256 *s)
{
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85;
    s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c;
    s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
    s->len = 0;
    s->n   = 0;
}

static void sha256_update(Sha256 *s, void const *data, iz len)
{
    u8 const *p = (u8 const *)data;
    s->len += (u64)len * 8;
    while (len) {
        iz take = 64 - s->n;
        if (take > len) {
            take = len;
        }
        copybytes(s->buf + s->n, p, take);
        s->n += take;
        p    += take;
        len  -= take;
        if (s->n == 64) {
            sha256_compress(s, s->buf);
            s->n = 0;
        }
    }
}

static void sha256_final(Sha256 *s, u8 out[32])
{
    u64 bits = s->len;
    u8  c = 0x80;
    sha256_update(s, &c, 1);
    c = 0;
    while (s->n != 56) {
        sha256_update(s, &c, 1);
    }
    u8 lenb[8];
    for (i32 i = 0; i < 8; i++) {
        lenb[i] = (u8)(bits >> (56 - 8*i));
    }
    sha256_update(s, lenb, 8);
    for (i32 i = 0; i < 8; i++) {
        out[4*i]   = (u8)(s->h[i] >> 24);
        out[4*i+1] = (u8)(s->h[i] >> 16);
        out[4*i+2] = (u8)(s->h[i] >> 8);
        out[4*i+3] = (u8)(s->h[i]);
    }
}

static void sha256(u8 out[32], void const *data, iz len)
{
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, data, len);
    sha256_final(&s, out);
}


// SHA-512

struct Sha512 {
    u64 h[8];
    u64 len;
    u8  buf[128];
    iz  n;
};

static void sha512_compress(Sha512 *s, u8 const *p)
{
    static u64 const k[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
        0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210,
        0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910,
        0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60,
        0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9,
        0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    };
    u64 w[80];
    for (i32 i = 0; i < 16; i++) {
        u64 v = 0;
        for (i32 j = 0; j < 8; j++) {
            v = v<<8 | p[8*i+j];
        }
        w[i] = v;
    }
    for (i32 i = 16; i < 80; i++) {
        u64 a = w[i-15], b = w[i-2];
        u64 s0 = rotr64(a,1) ^ rotr64(a,8) ^ (a>>7);
        u64 s1 = rotr64(b,19) ^ rotr64(b,61) ^ (b>>6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u64 a=s->h[0], b=s->h[1], c=s->h[2], d=s->h[3];
    u64 e=s->h[4], f=s->h[5], g=s->h[6], h=s->h[7];
    for (i32 i = 0; i < 80; i++) {
        u64 S1 = rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41);
        u64 ch = (e&f) ^ (~e&g);
        u64 t1 = h + S1 + ch + k[i] + w[i];
        u64 S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
        u64 mj = (a&b) ^ (a&c) ^ (b&c);
        u64 t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void sha512_init(Sha512 *s)
{
    s->h[0]=0x6a09e667f3bcc908; s->h[1]=0xbb67ae8584caa73b;
    s->h[2]=0x3c6ef372fe94f82b; s->h[3]=0xa54ff53a5f1d36f1;
    s->h[4]=0x510e527fade682d1; s->h[5]=0x9b05688c2b3e6c1f;
    s->h[6]=0x1f83d9abfb41bd6b; s->h[7]=0x5be0cd19137e2179;
    s->len = 0;
    s->n   = 0;
}

static void sha512_update(Sha512 *s, void const *data, iz len)
{
    u8 const *p = (u8 const *)data;
    s->len += (u64)len * 8;
    while (len) {
        iz take = 128 - s->n;
        if (take > len) {
            take = len;
        }
        copybytes(s->buf + s->n, p, take);
        s->n += take;
        p    += take;
        len  -= take;
        if (s->n == 128) {
            sha512_compress(s, s->buf);
            s->n = 0;
        }
    }
}

static void sha512_final(Sha512 *s, u8 out[64])
{
    u64 bits = s->len;
    u8  c = 0x80;
    sha512_update(s, &c, 1);
    c = 0;
    while (s->n != 112) {
        sha512_update(s, &c, 1);
    }
    u8 lenb[16] = {};
    for (i32 i = 0; i < 8; i++) {
        lenb[8+i] = (u8)(bits >> (56 - 8*i));
    }
    sha512_update(s, lenb, 16);
    for (i32 i = 0; i < 8; i++) {
        for (i32 j = 0; j < 8; j++) {
            out[8*i+j] = (u8)(s->h[i] >> (56 - 8*j));
        }
    }
}

static void sha512(u8 out[64], void const *data, iz len)
{
    Sha512 s;
    sha512_init(&s);
    sha512_update(&s, data, len);
    sha512_final(&s, out);
}


// ChaCha20 (original 64-bit nonce / 64-bit counter variant)

struct Chacha {
    u32 k[8];
    u32 nonce[2];
    u64 ctr;
};

#define QR(a, b, c, d) \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 8); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 7);

static void chacha_block(u8 out[64], Chacha const *c)
{
    u32 x[16], o[16];
    x[0]=0x61707865; x[1]=0x3320646e; x[2]=0x79622d32; x[3]=0x6b206574;
    for (i32 i = 0; i < 8; i++) {
        x[4+i] = c->k[i];
    }
    x[12] = (u32)c->ctr;
    x[13] = (u32)(c->ctr >> 32);
    x[14] = c->nonce[0];
    x[15] = c->nonce[1];
    for (i32 i = 0; i < 16; i++) {
        o[i] = x[i];
    }
    for (i32 i = 0; i < 10; i++) {
        QR(x[0],x[4],x[8], x[12]) QR(x[1],x[5],x[9], x[13])
        QR(x[2],x[6],x[10],x[14]) QR(x[3],x[7],x[11],x[15])
        QR(x[0],x[5],x[10],x[15]) QR(x[1],x[6],x[11],x[12])
        QR(x[2],x[7],x[8], x[13]) QR(x[3],x[4],x[9], x[14])
    }
    for (i32 i = 0; i < 16; i++) {
        u32 v = x[i] + o[i];
        out[4*i]   = (u8)v;
        out[4*i+1] = (u8)(v>>8);
        out[4*i+2] = (u8)(v>>16);
        out[4*i+3] = (u8)(v>>24);
    }
}

static void chacha_keysetup(Chacha *c, u8 const key[32])
{
    for (i32 i = 0; i < 8; i++) {
        c->k[i] = (u32)key[4*i] | (u32)key[4*i+1]<<8 |
                  (u32)key[4*i+2]<<16 | (u32)key[4*i+3]<<24;
    }
    c->nonce[0] = 0;
    c->nonce[1] = 0;
    c->ctr      = 0;
}

static void chacha_ivsetup(Chacha *c, u8 const iv[8], u64 ctr)
{
    c->nonce[0] = (u32)iv[0] | (u32)iv[1]<<8 | (u32)iv[2]<<16 | (u32)iv[3]<<24;
    c->nonce[1] = (u32)iv[4] | (u32)iv[5]<<8 | (u32)iv[6]<<16 | (u32)iv[7]<<24;
    c->ctr      = ctr;
}

// XOR keystream into dst; src may equal dst or be null (keystream output).
static void chacha_xor(Chacha *c, u8 *dst, u8 const *src, iz len)
{
    u8 ks[64];
    while (len > 0) {
        chacha_block(ks, c);
        c->ctr++;
        iz take = len < 64 ? len : 64;
        for (iz i = 0; i < take; i++) {
            dst[i] = (src ? src[i] : 0) ^ ks[i];
        }
        dst += take;
        if (src) {
            src += take;
        }
        len -= take;
    }
}


// Poly1305

struct Poly1305 {
    u32 r[5];
    u32 h[5];
    u32 pad[4];
};

static u32 le32(u8 const *p)
{
    return (u32)p[0] | (u32)p[1]<<8 | (u32)p[2]<<16 | (u32)p[3]<<24;
}

static void poly1305_init(Poly1305 *st, u8 const *key)
{
    u32 t0=le32(key), t1=le32(key+4), t2=le32(key+8), t3=le32(key+12);
    st->r[0] = t0 & 0x3ffffff;
    st->r[1] = ((t0>>26) | (t1<<6))  & 0x3ffff03;
    st->r[2] = ((t1>>20) | (t2<<12)) & 0x3ffc0ff;
    st->r[3] = ((t2>>14) | (t3<<18)) & 0x3f03fff;
    st->r[4] = (t3>>8) & 0x00fffff;
    for (i32 i = 0; i < 5; i++) {
        st->h[i] = 0;
    }
    st->pad[0]=le32(key+16); st->pad[1]=le32(key+20);
    st->pad[2]=le32(key+24); st->pad[3]=le32(key+28);
}

static void poly1305_blocks(Poly1305 *st, u8 const *m, iz len, u32 hibit)
{
    u32 r0=st->r[0], r1=st->r[1], r2=st->r[2], r3=st->r[3], r4=st->r[4];
    u32 h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4];
    u32 s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    while (len >= 16) {
        u32 m0=le32(m), m1=le32(m+4), m2=le32(m+8), m3=le32(m+12);
        h0 += m0 & 0x3ffffff;
        h1 += ((m0>>26) | (m1<<6))  & 0x3ffffff;
        h2 += ((m1>>20) | (m2<<12)) & 0x3ffffff;
        h3 += ((m2>>14) | (m3<<18)) & 0x3ffffff;
        h4 += (m3>>8) | hibit;
        u64 d0 = (u64)h0*r0 + (u64)h1*s4 + (u64)h2*s3 + (u64)h3*s2 + (u64)h4*s1;
        u64 d1 = (u64)h0*r1 + (u64)h1*r0 + (u64)h2*s4 + (u64)h3*s3 + (u64)h4*s2;
        u64 d2 = (u64)h0*r2 + (u64)h1*r1 + (u64)h2*r0 + (u64)h3*s4 + (u64)h4*s3;
        u64 d3 = (u64)h0*r3 + (u64)h1*r2 + (u64)h2*r1 + (u64)h3*r0 + (u64)h4*s4;
        u64 d4 = (u64)h0*r4 + (u64)h1*r3 + (u64)h2*r2 + (u64)h3*r1 + (u64)h4*r0;
        u32 c;
        c=(u32)(d0>>26); h0=(u32)d0 & 0x3ffffff;
        d1+=c; c=(u32)(d1>>26); h1=(u32)d1 & 0x3ffffff;
        d2+=c; c=(u32)(d2>>26); h2=(u32)d2 & 0x3ffffff;
        d3+=c; c=(u32)(d3>>26); h3=(u32)d3 & 0x3ffffff;
        d4+=c; c=(u32)(d4>>26); h4=(u32)d4 & 0x3ffffff;
        h0 += c*5; c = h0>>26; h0 &= 0x3ffffff;
        h1 += c;
        m   += 16;
        len -= 16;
    }
    st->h[0]=h0; st->h[1]=h1; st->h[2]=h2; st->h[3]=h3; st->h[4]=h4;
}

static void poly1305_update(Poly1305 *st, u8 const *m, iz len)
{
    if (len >= 16) {
        iz n = len & ~(iz)15;
        poly1305_blocks(st, m, n, 1u<<24);
        m   += n;
        len -= n;
    }
    if (len) {
        u8 buf[16] = {};
        copybytes(buf, m, len);
        buf[len] = 1;
        poly1305_blocks(st, buf, 16, 0);
    }
}

static void poly1305_final(Poly1305 *st, u8 tag[16])
{
    u32 h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4];
    u32 c;
    c=h1>>26; h1&=0x3ffffff; h2+=c;
    c=h2>>26; h2&=0x3ffffff; h3+=c;
    c=h3>>26; h3&=0x3ffffff; h4+=c;
    c=h4>>26; h4&=0x3ffffff; h0+=c*5;
    c=h0>>26; h0&=0x3ffffff; h1+=c;

    u32 g0=h0+5;      c=g0>>26; g0&=0x3ffffff;
    u32 g1=h1+c;      c=g1>>26; g1&=0x3ffffff;
    u32 g2=h2+c;      c=g2>>26; g2&=0x3ffffff;
    u32 g3=h3+c;      c=g3>>26; g3&=0x3ffffff;
    u32 g4=h4+c-(1u<<26);

    u32 mask = (g4>>31) - 1;
    g0&=mask; g1&=mask; g2&=mask; g3&=mask; g4&=mask;
    mask = ~mask;
    h0 = (h0&mask) | g0;
    h1 = (h1&mask) | g1;
    h2 = (h2&mask) | g2;
    h3 = (h3&mask) | g3;
    h4 = (h4&mask) | g4;

    h0 = (h0      ) | (h1<<26);
    h1 = (h1>>6   ) | (h2<<20);
    h2 = (h2>>12  ) | (h3<<14);
    h3 = (h3>>18  ) | (h4<<8);

    u64 f;
    f = (u64)h0 + st->pad[0];        h0 = (u32)f;
    f = (u64)h1 + st->pad[1] + (f>>32); h1 = (u32)f;
    f = (u64)h2 + st->pad[2] + (f>>32); h2 = (u32)f;
    f = (u64)h3 + st->pad[3] + (f>>32); h3 = (u32)f;

    tag[0]=(u8)h0; tag[1]=(u8)(h0>>8); tag[2]=(u8)(h0>>16); tag[3]=(u8)(h0>>24);
    tag[4]=(u8)h1; tag[5]=(u8)(h1>>8); tag[6]=(u8)(h1>>16); tag[7]=(u8)(h1>>24);
    tag[8]=(u8)h2; tag[9]=(u8)(h2>>8); tag[10]=(u8)(h2>>16); tag[11]=(u8)(h2>>24);
    tag[12]=(u8)h3; tag[13]=(u8)(h3>>8); tag[14]=(u8)(h3>>16); tag[15]=(u8)(h3>>24);
}


// chacha20-poly1305@openssh.com packet handling. Key material is 64 bytes:
// K_1 (first half) protects the payload, K_2 (second half) the length. The
// nonce is the 64-bit packet sequence number; the length uses counter 0 and
// the payload counter 1. The Poly1305 key is K_1's counter-0 keystream.

static void seq_nonce(u8 nonce[8], u64 seq)
{
    for (i32 i = 0; i < 8; i++) {
        nonce[i] = (u8)(seq >> (56 - 8*i));
    }
}

static u32 chachapoly_len(u8 const pkt[4], u8 const key[64], u64 seq)
{
    u8 nonce[8], blk[64];
    Chacha c;
    seq_nonce(nonce, seq);
    chacha_keysetup(&c, key+32);
    chacha_ivsetup(&c, nonce, 0);
    chacha_block(blk, &c);
    return ((u32)(pkt[0]^blk[0]) << 24) | ((u32)(pkt[1]^blk[1]) << 16) |
           ((u32)(pkt[2]^blk[2]) <<  8) |  (u32)(pkt[3]^blk[3]);
}

// Encrypt len bytes in place (4-byte length field plus packet body) and
// append the 16-byte tag. Output occupies len+16 bytes.
static void chachapoly_seal(u8 *pkt, iz len, u8 const key[64], u64 seq)
{
    u8 nonce[8], blk[64], tag[16];
    Chacha c;
    Poly1305 poly;

    seq_nonce(nonce, seq);

    chacha_keysetup(&c, key+32);
    chacha_ivsetup(&c, nonce, 0);
    chacha_block(blk, &c);
    for (i32 i = 0; i < 4; i++) {
        pkt[i] ^= blk[i];
    }

    chacha_keysetup(&c, key);
    chacha_ivsetup(&c, nonce, 0);
    chacha_block(blk, &c);
    poly1305_init(&poly, blk);

    chacha_ivsetup(&c, nonce, 1);
    chacha_xor(&c, pkt+4, pkt+4, len-4);

    poly1305_update(&poly, pkt, len);
    poly1305_final(&poly, tag);
    copybytes(pkt+len, tag, 16);
}

// Verify and decrypt a packet in place. len is the ciphertext size excluding
// the trailing tag (4-byte length field plus packet body). The length field
// is left decrypted. Returns 0 on authentication failure.
static b32 chachapoly_open(u8 *pkt, iz len, u8 const key[64], u64 seq)
{
    u8 nonce[8], blk[64], tag[16];
    Chacha c;
    Poly1305 poly;

    seq_nonce(nonce, seq);
    chacha_keysetup(&c, key);
    chacha_ivsetup(&c, nonce, 0);
    chacha_block(blk, &c);
    poly1305_init(&poly, blk);
    poly1305_update(&poly, pkt, len);
    poly1305_final(&poly, tag);
    if (!ct_eq(tag, pkt+len, 16)) {
        return 0;
    }

    chacha_ivsetup(&c, nonce, 1);
    chacha_xor(&c, pkt+4, pkt+4, len-4);
    return 1;
}


// Curve25519 field arithmetic (radix 2^16 limbs)

typedef i64 gf[16];

static gf gf0       = {0};
static gf gf1       = {1};
static gf gf121665  = {0xdb41, 1};

static void gf_car(gf o)
{
    for (i32 i = 0; i < 16; i++) {
        o[i] += (i64)1 << 16;
        i64 c = o[i] >> 16;
        o[(i+1)*(i<15)] += c - 1 + 37*(c-1)*(i==15);
        o[i] -= c << 16;
    }
}

static void gf_sel(gf p, gf q, i64 b)
{
    i64 c = ~(b-1);
    for (i32 i = 0; i < 16; i++) {
        i64 t = c & (p[i]^q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void gf_set(gf r, gf a)
{
    for (i32 i = 0; i < 16; i++) {
        r[i] = a[i];
    }
}

static void gf_add(gf o, gf a, gf b)
{
    for (i32 i = 0; i < 16; i++) {
        o[i] = a[i] + b[i];
    }
}

static void gf_sub(gf o, gf a, gf b)
{
    for (i32 i = 0; i < 16; i++) {
        o[i] = a[i] - b[i];
    }
}

static void gf_mul(gf o, gf a, gf b)
{
    i64 t[31];
    for (i32 i = 0; i < 31; i++) {
        t[i] = 0;
    }
    for (i32 i = 0; i < 16; i++) {
        for (i32 j = 0; j < 16; j++) {
            t[i+j] += a[i] * b[j];
        }
    }
    for (i32 i = 0; i < 15; i++) {
        t[i] += 38 * t[i+16];
    }
    for (i32 i = 0; i < 16; i++) {
        o[i] = t[i];
    }
    gf_car(o);
    gf_car(o);
}

static void gf_sq(gf o, gf a)
{
    gf_mul(o, a, a);
}

static void gf_pack(u8 *o, gf n)
{
    gf m, t;
    gf_set(t, n);
    gf_car(t);
    gf_car(t);
    gf_car(t);
    for (i32 j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i32 i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
        i64 b = (m[15]>>16) & 1;
        m[14] &= 0xffff;
        gf_sel(t, m, 1-b);
    }
    for (i32 i = 0; i < 16; i++) {
        o[2*i]   = (u8)t[i];
        o[2*i+1] = (u8)(t[i]>>8);
    }
}

static void gf_unpack(gf o, u8 const *n)
{
    for (i32 i = 0; i < 16; i++) {
        o[i] = n[2*i] + ((i64)n[2*i+1] << 8);
    }
    o[15] &= 0x7fff;
}

static b32 gf_neq(gf a, gf b)
{
    u8 pa[32], pb[32];
    gf_pack(pa, a);
    gf_pack(pb, b);
    return !ct_eq(pa, pb, 32);
}

static i32 gf_par(gf a)
{
    u8 d[32];
    gf_pack(d, a);
    return d[0] & 1;
}

static void gf_inv(gf o, gf i)
{
    gf c;
    gf_set(c, i);
    for (i32 a = 253; a >= 0; a--) {
        gf_sq(c, c);
        if (a != 2 && a != 4) {
            gf_mul(c, c, i);
        }
    }
    gf_set(o, c);
}

static void gf_pow2523(gf o, gf i)
{
    gf c;
    gf_set(c, i);
    for (i32 a = 250; a >= 0; a--) {
        gf_sq(c, c);
        if (a != 1) {
            gf_mul(c, c, i);
        }
    }
    gf_set(o, c);
}


// X25519

static b32 x25519(u8 out[32], u8 const scalar[32], u8 const point[32])
{
    u8  z[32];
    i64 x[80];
    gf  a, b, c, d, e, f;
    i64 r, i;

    for (i = 0; i < 31; i++) {
        z[i] = scalar[i];
    }
    z[31] = (scalar[31] & 127) | 64;
    z[0] &= 248;

    gf_unpack(x, point);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (i = 254; i >= 0; --i) {
        r = (z[i>>3] >> (i&7)) & 1;
        gf_sel(a, b, r); gf_sel(c, d, r);
        gf_add(e, a, c); gf_sub(a, a, c); gf_add(c, b, d); gf_sub(b, b, d);
        gf_sq(d, e);     gf_sq(f, a);     gf_mul(a, c, a); gf_mul(c, b, e);
        gf_add(e, a, c); gf_sub(a, a, c); gf_sq(b, a);     gf_sub(c, d, f);
        gf_mul(a, c, gf121665); gf_add(a, a, d); gf_mul(c, c, a); gf_mul(a, d, f);
        gf_mul(d, b, x); gf_sq(b, e);
        gf_sel(a, b, r); gf_sel(c, d, r);
    }
    for (i = 0; i < 16; i++) {
        x[i+16] = a[i];
        x[i+32] = c[i];
        x[i+48] = b[i];
        x[i+64] = d[i];
    }
    gf_inv(x+32, x+32);
    gf_mul(x+16, x+16, x+32);
    gf_pack(out, x+16);

    u8 zero[32] = {};
    return !ct_eq(out, zero, 32);
}

static b32 x25519_base(u8 out[32], u8 const scalar[32])
{
    u8 base[32] = {9};
    return x25519(out, scalar, base);
}


// Ed25519

static gf ed_d, ed_d2, ed_sqrtm1;
static gf ed_basex, ed_basey;

static void ed25519_init(void)
{
    static u8 const bx[32] = {
        0x1a,0xd5,0x25,0x8f,0x60,0x2d,0x56,0xc9,
        0xb2,0xa7,0x25,0x95,0x60,0xc7,0x2c,0x69,
        0x5c,0xdc,0xd6,0xfd,0x31,0xe2,0xa4,0xc0,
        0xfe,0x53,0x6e,0xcd,0xd3,0x36,0x69,0x21,
    };
    static u8 const by[32] = {
        0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    };
    static u8 const si[32] = {
        0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,
        0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
        0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,
        0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b,
    };
    gf t1, t2;
    gf_unpack(ed_basex, bx);
    gf_unpack(ed_basey, by);
    gf_unpack(ed_sqrtm1, si);

    gf_set(t1, gf121665);
    for (i32 i = 0; i < 16; i++) {
        t2[i] = 0;
    }
    t2[0] = 0xdb42;
    t2[1] = 1;
    gf_inv(t2, t2);
    gf_mul(ed_d, t1, t2);
    gf_sub(ed_d, gf0, ed_d);
    gf_add(ed_d2, ed_d, ed_d);
}

static void ge_add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    gf_sub(a, p[1], p[0]);
    gf_sub(t, q[1], q[0]);
    gf_mul(a, a, t);
    gf_add(b, p[0], p[1]);
    gf_add(t, q[0], q[1]);
    gf_mul(b, b, t);
    gf_mul(c, p[3], q[3]);
    gf_mul(c, c, ed_d2);
    gf_mul(d, p[2], q[2]);
    gf_add(d, d, d);
    gf_sub(e, b, a);
    gf_sub(f, d, c);
    gf_add(g, d, c);
    gf_add(h, b, a);
    gf_mul(p[0], e, f);
    gf_mul(p[1], h, g);
    gf_mul(p[2], g, f);
    gf_mul(p[3], e, h);
}

static void ge_cswap(gf p[4], gf q[4], i64 b)
{
    for (i32 i = 0; i < 4; i++) {
        gf_sel(p[i], q[i], b);
    }
}

static void ge_scalarmult(gf p[4], gf q[4], u8 const *s)
{
    gf_set(p[0], gf0);
    gf_set(p[1], gf1);
    gf_set(p[2], gf1);
    gf_set(p[3], gf0);
    for (i32 i = 255; i >= 0; i--) {
        u8 b = (s[i/8] >> (i&7)) & 1;
        ge_cswap(p, q, b);
        ge_add(q, p);
        ge_add(p, p);
        ge_cswap(p, q, b);
    }
}

static void ge_scalarbase(gf p[4], u8 const *s)
{
    gf q[4];
    gf_set(q[0], ed_basex);
    gf_set(q[1], ed_basey);
    gf_set(q[2], gf1);
    gf_mul(q[3], ed_basex, ed_basey);
    ge_scalarmult(p, q, s);
}

static void ge_pack(u8 *r, gf p[4])
{
    gf tx, ty, zi;
    gf_inv(zi, p[2]);
    gf_mul(tx, p[0], zi);
    gf_mul(ty, p[1], zi);
    gf_pack(r, ty);
    r[31] ^= (u8)(gf_par(tx) << 7);
}

static b32 ge_unpackneg(gf r[4], u8 const *p)
{
    gf t, chk, num, den, den2, den4, den6;
    gf_set(r[2], gf1);
    gf_unpack(r[1], p);
    gf_sq(num, r[1]);
    gf_mul(den, num, ed_d);
    gf_sub(num, num, r[2]);
    gf_add(den, r[2], den);

    gf_sq(den2, den);
    gf_sq(den4, den2);
    gf_mul(den6, den4, den2);
    gf_mul(t, den6, num);
    gf_mul(t, t, den);

    gf_pow2523(t, t);
    gf_mul(t, t, num);
    gf_mul(t, t, den);
    gf_mul(t, t, den);
    gf_mul(r[0], t, den);

    gf_sq(chk, r[0]);
    gf_mul(chk, chk, den);
    if (gf_neq(chk, num)) {
        gf_mul(r[0], r[0], ed_sqrtm1);
    }
    gf_sq(chk, r[0]);
    gf_mul(chk, chk, den);
    if (gf_neq(chk, num)) {
        return 0;
    }
    if (gf_par(r[0]) == (p[31]>>7)) {
        gf_sub(r[0], gf0, r[0]);
    }
    gf_mul(r[3], r[0], r[1]);
    return 1;
}


// Scalar arithmetic modulo the Ed25519 group order

static u32 const sc_L[8] = {
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
    0x00000000, 0x00000000, 0x00000000, 0x10000000,
};

static void sc_load(u32 x[8], u8 const *s)
{
    for (i32 i = 0; i < 8; i++) {
        x[i] = (u32)s[4*i] | (u32)s[4*i+1]<<8 |
               (u32)s[4*i+2]<<16 | (u32)s[4*i+3]<<24;
    }
}

static void sc_store(u8 *s, u32 const x[8])
{
    for (i32 i = 0; i < 8; i++) {
        s[4*i]   = (u8)x[i];
        s[4*i+1] = (u8)(x[i]>>8);
        s[4*i+2] = (u8)(x[i]>>16);
        s[4*i+3] = (u8)(x[i]>>24);
    }
}

static b32 sc_lt_l(u8 const *s)
{
    u32 x[8];
    sc_load(x, s);
    for (i32 i = 7; i >= 0; i--) {
        if (x[i] < sc_L[i]) return 1;
        if (x[i] > sc_L[i]) return 0;
    }
    return 0;
}

static void sc_reduce(u8 out[32], u8 const in[64])
{
    u32 rem[8] = {};
    for (i32 i = 511; i >= 0; i--) {
        u32 carry = (in[i>>3] >> (i&7)) & 1;
        for (i32 j = 0; j < 8; j++) {
            u32 nc = rem[j] >> 31;
            rem[j] = (rem[j] << 1) | carry;
            carry = nc;
        }
        b32 ge = 1;
        for (i32 j = 7; j >= 0; j--) {
            if (rem[j] < sc_L[j]) { ge = 0; break; }
            if (rem[j] > sc_L[j]) { break; }
        }
        if (ge) {
            u64 borrow = 0;
            for (i32 j = 0; j < 8; j++) {
                u64 t = (u64)rem[j] - sc_L[j] - borrow;
                rem[j] = (u32)t;
                borrow = (t >> 32) & 1;
            }
        }
    }
    sc_store(out, rem);
}

static void sc_muladd(u8 out[32], u8 const *a, u8 const *b, u8 const *c)
{
    u32 A[8], B[8], C[8], P[16] = {};
    sc_load(A, a);
    sc_load(B, b);
    sc_load(C, c);
    for (i32 i = 0; i < 8; i++) {
        u64 carry = 0;
        for (i32 j = 0; j < 8; j++) {
            u64 t = (u64)A[i]*B[j] + P[i+j] + carry;
            P[i+j] = (u32)t;
            carry = t >> 32;
        }
        P[i+8] = (u32)carry;
    }
    u64 carry = 0;
    for (i32 i = 0; i < 8; i++) {
        u64 t = (u64)P[i] + C[i] + carry;
        P[i] = (u32)t;
        carry = t >> 32;
    }
    for (i32 i = 8; i < 16 && carry; i++) {
        u64 t = (u64)P[i] + carry;
        P[i] = (u32)t;
        carry = t >> 32;
    }
    u8 buf[64];
    for (i32 i = 0; i < 16; i++) {
        buf[4*i]   = (u8)P[i];
        buf[4*i+1] = (u8)(P[i]>>8);
        buf[4*i+2] = (u8)(P[i]>>16);
        buf[4*i+3] = (u8)(P[i]>>24);
    }
    sc_reduce(out, buf);
}


// Ed25519 signatures

static void ed25519_pubkey(u8 out[32], u8 const seed[32])
{
    u8 h[64];
    gf p[4];
    sha512(h, seed, 32);
    h[0]  &= 248;
    h[31] &= 127;
    h[31] |= 64;
    ge_scalarbase(p, h);
    ge_pack(out, p);
}

static void ed25519_sign(u8 sig[64], u8 const *msg, iz len, u8 const seed[32])
{
    u8 h[64], r[64], k[64], a[32], prefix[32], A[32], rr[32], kk[32];
    gf p[4];
    Sha512 s;

    sha512(h, seed, 32);
    for (i32 i = 0; i < 32; i++) {
        a[i]      = h[i];
        prefix[i] = h[32+i];
    }
    a[0]  &= 248;
    a[31] &= 127;
    a[31] |= 64;

    ge_scalarbase(p, a);
    ge_pack(A, p);

    sha512_init(&s);
    sha512_update(&s, prefix, 32);
    sha512_update(&s, msg, len);
    sha512_final(&s, r);
    sc_reduce(rr, r);
    ge_scalarbase(p, rr);
    ge_pack(sig, p);

    sha512_init(&s);
    sha512_update(&s, sig, 32);
    sha512_update(&s, A, 32);
    sha512_update(&s, msg, len);
    sha512_final(&s, k);
    sc_reduce(kk, k);

    sc_muladd(sig+32, kk, a, rr);
}

static b32 ed25519_verify(u8 const *sig, u8 const *msg, iz len, u8 const *pub)
{
    gf A[4], p[4], q[4];
    u8 h[64], kk[32], check[32];
    Sha512 s;

    if (!ge_unpackneg(A, pub)) {
        return 0;
    }
    if (!sc_lt_l(sig+32)) {
        return 0;
    }
    sha512_init(&s);
    sha512_update(&s, sig, 32);
    sha512_update(&s, pub, 32);
    sha512_update(&s, msg, len);
    sha512_final(&s, h);
    sc_reduce(kk, h);

    ge_scalarmult(p, A, kk);
    ge_scalarbase(q, sig+32);
    ge_add(p, q);
    ge_pack(check, p);
    return ct_eq(check, sig, 32);
}

// SSH protocol: transport, key exchange, authentication, channels
// This is free and unencumbered software released into the public domain.

// Platform interface (implemented in win32.cpp)

struct Proc {
    uz  hproc   = {};
    uz  hstdin  = {};
    uz  hstdout = {};
    uz  hstderr = {};
    b32 running = {};
};

enum {
    SOCK_ERR       = -1,
    SOCK_WOULDBLOCK = -2,
};

static i32  sock_recv(uz sock, u8 *buf, iz len);
static b32  sock_send(uz sock, u8 const *buf, iz len);
static i32  sock_wait(uz sock, i32 ms);
static void os_random(u8 *buf, iz len);
static void os_log(Str s);
static iz   utf8_to_wide(u16 *dst, iz cap, Str s);
static Str  wide_to_utf8(Arena *a, u16 const *s, iz len);
static b32  proc_spawn(Proc *p, Str shell, Str cmd,
                       Slice<Str> names, Slice<Str> vals, Arena *a);
static iz   proc_pending(Proc *p, i32 which);
static iz   proc_read(Proc *p, u8 *buf, iz len, i32 which);
static b32  proc_write(Proc *p, u8 const *buf, iz len);
static b32  proc_alive(Proc *p);
static u32  proc_status(Proc *p);
static void proc_kill(Proc *p);
static void proc_close_stdin(Proc *p);
static b32  os_readfile(Arena *a, Str path, Str *out);
static b32  os_writefile(Str path, u8 const *data, iz len);


// Configuration

struct Config {
    i32 port;
    Str keysfile;
    Str hostkeyfile;
    Str shell;
    u8  hostseed[32];
    u8  hostpub[32];
};

static Config config;


// Protocol constants

enum {
    MSG_DISCONNECT              = 1,
    MSG_IGNORE                  = 2,
    MSG_UNIMPLEMENTED           = 3,
    MSG_DEBUG                   = 4,
    MSG_SERVICE_REQUEST         = 5,
    MSG_SERVICE_ACCEPT          = 6,
    MSG_EXT_INFO                = 7,
    MSG_KEXINIT                 = 20,
    MSG_NEWKEYS                 = 21,
    MSG_KEX_ECDH_INIT           = 30,
    MSG_KEX_ECDH_REPLY          = 31,
    MSG_USERAUTH_REQUEST        = 50,
    MSG_USERAUTH_FAILURE        = 51,
    MSG_USERAUTH_SUCCESS        = 52,
    MSG_USERAUTH_PK_OK          = 60,
    MSG_GLOBAL_REQUEST          = 80,
    MSG_REQUEST_FAILURE         = 82,
    MSG_CHANNEL_OPEN            = 90,
    MSG_CHANNEL_OPEN_CONFIRM    = 91,
    MSG_CHANNEL_OPEN_FAILURE    = 92,
    MSG_CHANNEL_WINDOW_ADJUST   = 93,
    MSG_CHANNEL_DATA            = 94,
    MSG_CHANNEL_EXTENDED_DATA   = 95,
    MSG_CHANNEL_EOF             = 96,
    MSG_CHANNEL_CLOSE           = 97,
    MSG_CHANNEL_REQUEST         = 98,
    MSG_CHANNEL_SUCCESS         = 99,
    MSG_CHANNEL_FAILURE         = 100,
};

enum {
    DISCONNECT_PROTOCOL_ERROR       = 2,
    DISCONNECT_KEY_EXCHANGE_FAILED  = 3,
    DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
    DISCONNECT_TOO_MANY_CONNECTIONS = 12,
    DISCONNECT_NO_MORE_AUTH_METHODS = 14,
};

enum {
    MAXPACKET = 1 << 16,
    CHAN_MAXPKT = 32768,
    CHAN_WINDOW = 2 << 20,
};

static Str const ALG_HOSTKEY   = "ssh-ed25519";
static Str const ALG_CIPHER    = "chacha20-poly1305@openssh.com";
static Str const ALG_COMP      = "none";
static Str const SERVER_ID     = "SSH-2.0-sshd";


// Wire encoding

struct Wr {
    u8 *data;
    iz  len;
    iz  cap;
    b32 err;
};

static void w8(Wr *w, u8 v)
{
    if (w->len < w->cap) {
        w->data[w->len++] = v;
    } else {
        w->err = 1;
    }
}

static void w32(Wr *w, u32 v)
{
    w8(w, (u8)(v>>24));
    w8(w, (u8)(v>>16));
    w8(w, (u8)(v>>8));
    w8(w, (u8)v);
}

static void wraw(Wr *w, void const *p, iz n)
{
    u8 const *s = (u8 const *)p;
    for (iz i = 0; i < n; i++) {
        w8(w, s[i]);
    }
}

static void wstr(Wr *w, Str s)
{
    w32(w, (u32)s.len);
    wraw(w, s.data, s.len);
}

static void wcstr(Wr *w, char const *s)
{
    wstr(w, cstr(s));
}

// Raw bytes as an SSH mpint (big-endian, minimal, positive).
static void wmpint_be(Wr *w, u8 const *be, iz n)
{
    iz i = 0;
    while (i < n && be[i] == 0) {
        i++;
    }
    b32 pad = i < n && (be[i] & 0x80);
    w32(w, (u32)(n - i + pad));
    if (pad) {
        w8(w, 0);
    }
    for (; i < n; i++) {
        w8(w, be[i]);
    }
}

struct Rd {
    u8 const *data;
    iz        len;
    iz        pos;
    b32       err;
};

static u8 r8(Rd *r)
{
    if (r->pos < r->len) {
        return r->data[r->pos++];
    }
    r->err = 1;
    return 0;
}

static u32 r32(Rd *r)
{
    u32 a = r8(r);
    u32 b = r8(r);
    u32 c = r8(r);
    u32 d = r8(r);
    return a<<24 | b<<16 | c<<8 | d;
}

static Str rstr(Rd *r)
{
    u32 n = r32(r);
    if (r->err || n > (u32)(r->len - r->pos)) {
        r->err = 1;
        return {};
    }
    Str s = {(u8 *)(r->data + r->pos), (iz)n};
    r->pos += n;
    return s;
}


// Name-list helpers

static b32 namelist_has(Str list, Str name)
{
    iz i = 0;
    for (;;) {
        iz j = i;
        while (j < list.len && list.data[j] != ',') {
            j++;
        }
        if (Str{list.data + i, j-i} == name) {
            return 1;
        }
        if (j >= list.len) {
            return 0;
        }
        i = j + 1;
    }
}

static Str namelist_first(Str list)
{
    iz j = 0;
    while (j < list.len && list.data[j] != ',') {
        j++;
    }
    return {list.data, j};
}


// Connection state

struct Key {
    u8 pk[32];
};

struct Conn {
    uz      sock;
    Arena   arena;
    Config *cfg;

    u8  rx[MAXPACKET + 64];
    iz  rxbeg, rxend;

    u32 seqsend, seqrecv;
    b32 send_enc, recv_enc;
    u8  ksend[64], krecv[64];
    b32 strict;
    b32 initial_done;
    u8  session_id[32];

    Str vc, vs;

    Str user;

    b32 chan_open;
    u32 chan_local, chan_remote;
    u32 win_remote, win_local, win_local_max, pkt_remote;
    b32 got_pty;

    Proc proc;
    b32  child_started;
    b32  sent_exit, sent_eof, sent_close, got_close;

    Slice<Str> envname, envval;

    u8 tx[MAXPACKET + 64];
};


// Packet I/O

static b32 send_packet(Conn *c, u8 const *payload, iz len)
{
    if (len + 1 > MAXPACKET - 4) {
        return 0;
    }
    iz pad = 8 - (((c->send_enc ? 1 : 5) + len) & 7);
    if (pad < 4) {
        pad += 8;
    }
    iz plen = 1 + len + pad;

    u8 *p = c->tx;
    p[0] = (u8)(plen>>24);
    p[1] = (u8)(plen>>16);
    p[2] = (u8)(plen>>8);
    p[3] = (u8)plen;
    p[4] = (u8)pad;
    copybytes(p+5, payload, len);
    os_random(p+5+len, pad);

    iz total;
    if (c->send_enc) {
        chachapoly_seal(p, 4+plen, c->ksend, c->seqsend);
        total = 4 + plen + 16;
    } else {
        total = 4 + plen;
    }
    c->seqsend++;
    return sock_send(c->sock, p, total);
}

static void send_disconnect(Conn *c, u32 reason, char const *desc)
{
    u8 buf[256];
    Wr w = {buf, 0, sizeof(buf), 0};
    w8(&w, MSG_DISCONNECT);
    w32(&w, reason);
    wcstr(&w, desc);
    wcstr(&w, "");
    send_packet(c, buf, w.len);
}

// Returns 1 = packet ready, 0 = need more bytes, -1 = protocol error.
static i32 recv_packet(Conn *c, u8 **payload, iz *plen)
{
    u8 *p = c->rx + c->rxbeg;
    if (c->rxend - c->rxbeg < 4) {
        return 0;
    }
    u32 pktlen;
    if (c->recv_enc) {
        pktlen = chachapoly_len(p, c->krecv, c->seqrecv);
    } else {
        pktlen = (u32)p[0]<<24 | (u32)p[1]<<16 | (u32)p[2]<<8 | p[3];
    }
    if (pktlen < 5 || pktlen > MAXPACKET) {
        return -1;
    }
    iz need = 4 + (iz)pktlen + (c->recv_enc ? 16 : 0);
    if (c->rxend - c->rxbeg < need) {
        return 0;
    }
    if (c->recv_enc) {
        if (!chachapoly_open(p, 4 + (iz)pktlen, c->krecv, c->seqrecv)) {
            return -1;
        }
    }
    u8 padlen = p[4];
    if ((iz)padlen + 1 > (iz)pktlen) {
        return -1;
    }
    *payload = p + 5;
    *plen    = (iz)pktlen - padlen - 1;
    c->rxbeg += need;
    if (c->rxbeg == c->rxend) {
        c->rxbeg = 0;
        c->rxend = 0;
    }
    c->seqrecv++;
    return 1;
}

// Append whatever the socket has to the receive buffer. Returns 1 data,
// 0 would-block, -1 closed/error.
static i32 read_available(Conn *c)
{
    if (c->rxend == (iz)sizeof(c->rx)) {
        if (c->rxbeg == 0) {
            return 0;
        }
        __builtin_memmove(c->rx, c->rx + c->rxbeg, c->rxend - c->rxbeg);
        c->rxend -= c->rxbeg;
        c->rxbeg  = 0;
    }
    iz room = (iz)sizeof(c->rx) - c->rxend;
    if (room <= 0) {
        return 0;
    }
    i32 got = sock_recv(c->sock, c->rx + c->rxend, room);
    if (got > 0) {
        c->rxend += got;
        return 1;
    }
    if (got == 0 || got == SOCK_ERR) {
        return -1;
    }
    return 0;
}

// Blocking read of one complete packet.
static i32 read_packet(Conn *c, u8 **payload, iz *plen)
{
    for (;;) {
        i32 r = recv_packet(c, payload, plen);
        if (r) {
            return r;
        }
        i32 a = read_available(c);
        if (a < 0) {
            return -1;
        }
        if (a == 0 && !sock_wait(c->sock, 10000)) {
            return -1;
        }
    }
}

static i32 read_byte(Conn *c, u8 *out)
{
    for (;;) {
        if (c->rxend > c->rxbeg) {
            *out = c->rx[c->rxbeg++];
            if (c->rxbeg == c->rxend) {
                c->rxbeg = 0;
                c->rxend = 0;
            }
            return 1;
        }
        i32 a = read_available(c);
        if (a < 0) {
            return -1;
        }
        if (a == 0 && !sock_wait(c->sock, 10000)) {
            return -1;
        }
    }
}


// Version exchange

static b32 version_exchange(Conn *c)
{
    u8 line[256];
    for (i32 tries = 0; tries < 20; tries++) {
        iz n = 0;
        for (;;) {
            u8 ch;
            if (read_byte(c, &ch) < 0) {
                return 0;
            }
            if (ch == '\n') {
                break;
            }
            if (n < (iz)sizeof(line) - 1) {
                line[n++] = ch;
            }
        }
        if (n && line[n-1] == '\r') {
            n--;
        }
        if (n >= 4 && !__builtin_memcmp(line, "SSH-", 4)) {
            if (!(n >= 8 && (!__builtin_memcmp(line, "SSH-2.0-", 8) ||
                             !__builtin_memcmp(line, "SSH-1.99-", 9)))) {
                return 0;
            }
            c->vc = clone(&c->arena, Str{line, n});
            c->vs = SERVER_ID;
            if (!sock_send(c->sock, (u8 const *)SERVER_ID.data, SERVER_ID.len)) {
                return 0;
            }
            return sock_send(c->sock, (u8 const *)"\r\n", 2);
        }
    }
    return 0;
}


// Key exchange

static Str build_kexinit(Arena *scratch, b32 initial)
{
    u8 *buf = allocbytes(scratch, 512);
    Wr w = {buf, 0, 512, 0};
    w8(&w, MSG_KEXINIT);
    u8 cookie[16];
    os_random(cookie, 16);
    wraw(&w, cookie, 16);
    if (initial) {
        wcstr(&w, "curve25519-sha256,curve25519-sha256@libssh.org,"
                  "kex-strict-s,kex-strict-s-v00@openssh.com");
    } else {
        wcstr(&w, "curve25519-sha256,curve25519-sha256@libssh.org");
    }
    wcstr(&w, "ssh-ed25519");
    wcstr(&w, "chacha20-poly1305@openssh.com");
    wcstr(&w, "chacha20-poly1305@openssh.com");
    wcstr(&w, "hmac-sha2-256");
    wcstr(&w, "hmac-sha2-256");
    wcstr(&w, "none");
    wcstr(&w, "none");
    wcstr(&w, "");
    wcstr(&w, "");
    w8(&w, 0);
    w32(&w, 0);
    assert(!w.err);
    return {buf, w.len};
}

// Derive key material per RFC 4253 section 7.2.
static void derive_key(u8 *out, iz need, Str K, u8 const *h,
                       u8 letter, u8 const *sid)
{
    u8 blk[32];
    Sha256 s;
    iz have = 0;

    sha256_init(&s);
    sha256_update(&s, K.data, K.len);
    sha256_update(&s, h, 32);
    sha256_update(&s, &letter, 1);
    sha256_update(&s, sid, 32);
    sha256_final(&s, blk);

    while (have < need) {
        iz take = need - have < 32 ? need - have : 32;
        copybytes(out + have, blk, take);
        have += take;
        if (have < need) {
            sha256_init(&s);
            sha256_update(&s, K.data, K.len);
            sha256_update(&s, h, 32);
            sha256_update(&s, blk, 32);
            sha256_final(&s, blk);
        }
    }
}

static b32 do_kex(Conn *c, Arena *a, b32 initial, Str ic_in)
{
    Arena scratch = *a;
    b32   ok      = 0;
    Str   ic = {}, is = {};
    u8   *pl = 0;
    iz    plen = 0;
    u8    qc[32], qs[32], eph[32], shared[32];
    u8    ks[64];
    Str   KS = {};
    u8    K[40];
    iz    Klen = 0;
    Str   Kstr = {};
    u8    h[32];
    u8    sig[64], sigblob[96];
    Str   sigstr = {};
    u8    sid[32];

    is = build_kexinit(&scratch, initial);
    if (!send_packet(c, is.data, is.len)) {
        goto done;
    }

    if (ic_in.len) {
        ic = clone(&scratch, ic_in);
    } else {
        for (;;) {
            if (read_packet(c, &pl, &plen) <= 0) {
                goto done;
            }
            if (plen >= 1 && pl[0] == MSG_KEXINIT) {
                ic = clone(&scratch, Str{pl, plen});
                break;
            }
            if (!(initial && c->strict) && plen >= 1 &&
                    (pl[0] == MSG_IGNORE || pl[0] == MSG_DEBUG)) {
                continue;
            }
            goto done;
        }
    }

    // Negotiate.
    {
        Rd r = {ic.data, ic.len, 0, 0};
        r8(&r);  // message number
        for (i32 i = 0; i < 16; i++) {
            r8(&r);
        }
        Str kex     = rstr(&r);
        Str hostkey = rstr(&r);
        Str enc1    = rstr(&r);
        Str enc2    = rstr(&r);
        rstr(&r); rstr(&r);          // MAC c2s/s2c (ignored for AEAD)
        Str comp1   = rstr(&r);
        Str comp2   = rstr(&r);
        rstr(&r); rstr(&r);          // languages
        u8  follows = r8(&r);
        r32(&r);
        if (r.err) {
            goto done;
        }

        if (!namelist_has(kex, "curve25519-sha256") &&
                !namelist_has(kex, "curve25519-sha256@libssh.org")) {
            send_disconnect(c, DISCONNECT_KEY_EXCHANGE_FAILED, "no kex");
            goto done;
        }
        if (!namelist_has(hostkey, ALG_HOSTKEY) ||
                !namelist_has(enc1, ALG_CIPHER) ||
                !namelist_has(enc2, ALG_CIPHER) ||
                !namelist_has(comp1, ALG_COMP) ||
                !namelist_has(comp2, ALG_COMP)) {
            send_disconnect(c, DISCONNECT_KEY_EXCHANGE_FAILED, "no algorithm");
            goto done;
        }
        if (initial) {
            c->strict = namelist_has(kex, "kex-strict-c") ||
                        namelist_has(kex, "kex-strict-c-v00@openssh.com");
        }
        if (follows) {
            Str fk = namelist_first(kex);
            Str fh = namelist_first(hostkey);
            if (!(fk == "curve25519-sha256" || fk == "curve25519-sha256@libssh.org")
                    || fh != ALG_HOSTKEY) {
                // Guessed packet follows but is wrong; discard it.
                if (read_packet(c, &pl, &plen) <= 0) {
                    goto done;
                }
            }
        }
    }

    // Client ephemeral public key.
    for (;;) {
        if (read_packet(c, &pl, &plen) <= 0) {
            goto done;
        }
        if (plen >= 1 && pl[0] == MSG_KEX_ECDH_INIT) {
            break;
        }
        if (!(initial && c->strict) && plen >= 1 &&
                (pl[0] == MSG_IGNORE || pl[0] == MSG_DEBUG)) {
            continue;
        }
        goto done;
    }

    {
        Rd r = {pl, plen, 0, 0};
        r8(&r);
        Str q = rstr(&r);
        if (r.err || q.len != 32) {
            goto done;
        }
        copybytes(qc, q.data, 32);
    }
    os_random(eph, 32);
    if (!x25519_base(qs, eph)) {
        goto done;
    }
    if (!x25519(shared, eph, qc)) {
        send_disconnect(c, DISCONNECT_KEY_EXCHANGE_FAILED, "weak shared secret");
        goto done;
    }

    {
        Wr w = {ks, 0, sizeof(ks), 0};
        wcstr(&w, "ssh-ed25519");
        wstr(&w, Str{config.hostpub, 32});
        KS = {ks, w.len};
    }

    {
        Wr w = {K, 0, sizeof(K), 0};
        wmpint_be(&w, shared, 32);
        Klen = w.len;
    }
    Kstr = {K, Klen};

    {
        u8 *hb = allocbytes(&scratch, 4096);
        Wr  w  = {hb, 0, 4096, 0};
        wstr(&w, c->vc);
        wstr(&w, c->vs);
        wstr(&w, ic);
        wstr(&w, is);
        wstr(&w, KS);
        wstr(&w, Str{qc, 32});
        wstr(&w, Str{qs, 32});
        wraw(&w, K, Klen);       // mpint is already length-prefixed
        assert(!w.err);
        sha256(h, hb, w.len);
    }

    ed25519_sign(sig, h, 32, config.hostseed);
    {
        Wr w = {sigblob, 0, sizeof(sigblob), 0};
        wcstr(&w, "ssh-ed25519");
        wstr(&w, Str{sig, 64});
        sigstr = {sigblob, w.len};
    }

    {
        u8 buf[256];
        Wr w = {buf, 0, sizeof(buf), 0};
        w8(&w, MSG_KEX_ECDH_REPLY);
        wstr(&w, KS);
        wstr(&w, Str{qs, 32});
        wstr(&w, sigstr);
        assert(!w.err);
        if (!send_packet(c, buf, w.len)) {
            goto done;
        }
    }

    if (initial) {
        copybytes(c->session_id, h, 32);
    }
    copybytes(sid, c->session_id, 32);

    derive_key(c->ksend, 64, Kstr, h, 'D', sid);
    derive_key(c->krecv, 64, Kstr, h, 'C', sid);

    {
        u8 nk = MSG_NEWKEYS;
        if (!send_packet(c, &nk, 1)) {
            goto done;
        }
    }
    c->send_enc = 1;
    if (c->strict) {
        c->seqsend = 0;
    }

    for (;;) {
        if (read_packet(c, &pl, &plen) <= 0) {
            goto done;
        }
        if (plen >= 1 && pl[0] == MSG_NEWKEYS) {
            break;
        }
        if (!(initial && c->strict) && plen >= 1 &&
                (pl[0] == MSG_IGNORE || pl[0] == MSG_DEBUG)) {
            continue;
        }
        goto done;
    }
    c->recv_enc = 1;
    if (c->strict) {
        c->seqrecv = 0;
    }

    if (initial) {
        c->initial_done = 1;
    }
    ok = 1;

done:
    *a = scratch;
    return ok;
}


// Authentication

static Slice<Key> load_authorized(Conn *c)
{
    Slice<Key> keys = {};
    Str data;
    if (!os_readfile(&c->arena, c->cfg->keysfile, &data)) {
        return keys;
    }
    iz i = 0;
    while (i < data.len) {
        iz j = i;
        while (j < data.len && data.data[j] != '\n') {
            j++;
        }
        Str line = trim(Str{data.data + i, j - i});
        i = j + 1;
        if (!line.len || line.data[0] == '#') {
            continue;
        }
        Str rest = line;
        Str type = nexttoken(&rest);
        Str b64  = nexttoken(&rest);
        if (type != ALG_HOSTKEY || !b64.len) {
            continue;
        }
        u8  blob[64];
        iz  blen = 0;
        if (!b64decode(b64, blob, sizeof(blob), &blen) || blen != 51) {
            continue;
        }
        if (blob[3] != 11 || __builtin_memcmp(blob+4, "ssh-ed25519", 11)) {
            continue;
        }
        Key k;
        copybytes(k.pk, blob + 19, 32);
        keys = push(&c->arena, keys, k);
    }
    return keys;
}

static b32 send_auth_failure(Conn *c)
{
    u8 buf[64];
    Wr w = {buf, 0, sizeof(buf), 0};
    w8(&w, MSG_USERAUTH_FAILURE);
    wcstr(&w, "publickey");
    w8(&w, 0);
    return send_packet(c, buf, w.len);
}

static b32 auth_phase(Conn *c)
{
    Slice<Key> keys = load_authorized(c);
    u8 *pl = 0;
    iz  plen = 0;

    if (read_packet(c, &pl, &plen) <= 0) {
        return 0;
    }
    {
        Rd r = {pl, plen, 0, 0};
        u8 msg = r8(&r);
        Str svc = rstr(&r);
        if (msg != MSG_SERVICE_REQUEST || r.err || svc != "ssh-userauth") {
            send_disconnect(c, DISCONNECT_SERVICE_NOT_AVAILABLE, "no service");
            return 0;
        }
        u8 buf[64];
        Wr w = {buf, 0, sizeof(buf), 0};
        w8(&w, MSG_SERVICE_ACCEPT);
        wstr(&w, svc);
        if (!send_packet(c, buf, w.len)) {
            return 0;
        }
    }

    for (i32 fails = 0; fails < 20; ) {
        if (read_packet(c, &pl, &plen) <= 0) {
            return 0;
        }
        Rd r = {pl, plen, 0, 0};
        u8 msg = r8(&r);

        if (msg == MSG_IGNORE || msg == MSG_DEBUG || msg == MSG_EXT_INFO) {
            continue;
        }
        if (msg == MSG_DISCONNECT) {
            return 0;
        }
        if (msg != MSG_USERAUTH_REQUEST) {
            return 0;
        }

        Str user    = rstr(&r);
        Str service = rstr(&r);
        Str method  = rstr(&r);
        if (r.err) {
            return 0;
        }
        if (service != "ssh-connection") {
            if (!send_auth_failure(c)) return 0;
            fails++;
            continue;
        }
        if (method != "publickey") {
            if (!send_auth_failure(c)) return 0;
            fails++;
            continue;
        }

        b32 have_sig = r8(&r);
        Str alg      = rstr(&r);
        Str blob     = rstr(&r);
        if (r.err) {
            return 0;
        }

        u8 const *pk = 0;
        if (alg == ALG_HOSTKEY && blob.len == 51 &&
                blob.data[3] == 11 &&
                !__builtin_memcmp(blob.data+4, "ssh-ed25519", 11)) {
            pk = blob.data + 19;
        }
        b32 authorized = 0;
        if (pk) {
            for (iz i = 0; i < keys.len; i++) {
                if (!__builtin_memcmp(keys[i].pk, pk, 32)) {
                    authorized = 1;
                    break;
                }
            }
        }
        if (!authorized) {
            if (!send_auth_failure(c)) return 0;
            fails++;
            continue;
        }
        if (!have_sig) {
            u8 buf[128];
            Wr w = {buf, 0, sizeof(buf), 0};
            w8(&w, MSG_USERAUTH_PK_OK);
            wstr(&w, alg);
            wstr(&w, blob);
            if (!send_packet(c, buf, w.len)) {
                return 0;
            }
            continue;
        }

        Str sig = rstr(&r);
        if (r.err) {
            return 0;
        }
        iz sigoff = r.pos - sig.len - 4;  // start of the signature field

        b32 good = 0;
        if (sig.len == 83 && sig.data[3] == 11 &&
                !__builtin_memcmp(sig.data+4, "ssh-ed25519", 11)) {
            Arena scratch = c->arena;
            u8 *sd = allocbytes(&scratch, 4 + 32 + sigoff);
            Wr  w  = {sd, 0, 4 + 32 + sigoff, 0};
            wstr(&w, Str{c->session_id, 32});
            wraw(&w, pl, sigoff);
            good = ed25519_verify(sig.data + 19, sd, w.len, pk);
            c->arena = scratch;
        }
        if (good) {
            c->user = user;
            u8 ok = MSG_USERAUTH_SUCCESS;
            return send_packet(c, &ok, 1);
        }
        if (!send_auth_failure(c)) return 0;
        fails++;
    }

    send_disconnect(c, DISCONNECT_NO_MORE_AUTH_METHODS, "too many failures");
    return 0;
}


// Channels and session

static b32 channel_reply(Conn *c, u8 msg)
{
    u8 buf[8];
    Wr w = {buf, 0, sizeof(buf), 0};
    w8(&w, msg);
    w32(&w, c->chan_remote);
    return send_packet(c, buf, w.len);
}

static b32 start_child(Conn *c, Str cmd)
{
    if (c->child_started) {
        return 0;
    }
    {
        Buf b = Buf(&c->arena, 256);
        print(&b, cstr(cmd.len ? "sshd: exec: " : "sshd: shell"));
        if (cmd.len) {
            print(&b, cmd);
        }
        os_log(finish(&b));
    }
    if (!proc_spawn(&c->proc, c->cfg->shell, cmd, c->envname, c->envval,
                    &c->arena)) {
        os_log("sshd: spawn failed");
        return 0;
    }
    c->child_started = 1;
    return 1;
}

static b32 adjust_window(Conn *c)
{
    if (c->win_local < c->win_local_max / 2) {
        u32 add = c->win_local_max - c->win_local;
        u8  buf[16];
        Wr  w = {buf, 0, sizeof(buf), 0};
        w8(&w, MSG_CHANNEL_WINDOW_ADJUST);
        w32(&w, c->chan_remote);
        w32(&w, add);
        c->win_local = c->win_local_max;
        return send_packet(c, buf, w.len);
    }
    return 1;
}

static b32 send_channel_data(Conn *c, u8 const *data, iz len, i32 which)
{
    u8 buf[9 + 16384];
    Wr w = {buf, 0, sizeof(buf), 0};
    w8(&w, which ? MSG_CHANNEL_EXTENDED_DATA : MSG_CHANNEL_DATA);
    w32(&w, c->chan_remote);
    if (which) {
        w32(&w, 1);  // SSH_EXTENDED_DATA_STDERR
    }
    wstr(&w, Str{(u8 *)data, len});
    if (w.err) {
        return 0;
    }
    return send_packet(c, buf, w.len);
}

static void pump_output(Conn *c)
{
    for (i32 which = 0; which < 2; which++) {
        while (c->win_remote > 0) {
            iz avail = proc_pending(&c->proc, which);
            if (avail <= 0) {
                break;
            }
            iz cap = 16384;
            if (avail < cap) cap = avail;
            if (c->win_remote < (u32)cap) cap = c->win_remote;
            if (c->pkt_remote && c->pkt_remote < (u32)cap) cap = c->pkt_remote;
            if (cap <= 0) {
                break;
            }
            u8 buf[16384];
            iz got = proc_read(&c->proc, buf, cap, which);
            if (got <= 0) {
                break;
            }
            if (!send_channel_data(c, buf, got, which)) {
                return;
            }
            c->win_remote -= (u32)got;
        }
    }
}

static b32 finish_child(Conn *c)
{
    u32 status = proc_status(&c->proc);

    u8  buf[64];
    Wr  w = {buf, 0, sizeof(buf), 0};
    w8(&w, MSG_CHANNEL_REQUEST);
    w32(&w, c->chan_remote);
    wcstr(&w, "exit-status");
    w8(&w, 0);
    w32(&w, status);
    if (!send_packet(c, buf, w.len)) return 0;

    u8 e[8];
    Wr we = {e, 0, sizeof(e), 0};
    w8(&we, MSG_CHANNEL_EOF);
    w32(&we, c->chan_remote);
    if (!send_packet(c, e, we.len)) return 0;

    u8 cl[8];
    Wr wc = {cl, 0, sizeof(cl), 0};
    w8(&wc, MSG_CHANNEL_CLOSE);
    w32(&wc, c->chan_remote);
    if (!send_packet(c, cl, wc.len)) return 0;

    c->sent_exit = 1;
    c->sent_eof  = 1;
    c->sent_close = 1;
    return 1;
}

static b32 handle_request(Conn *c, Rd *r)
{
    u32 rec  = r32(r);
    Str req  = rstr(r);
    b32 want = r8(r);
    if (r->err) {
        return 0;
    }
    if (rec != c->chan_local) {
        return want ? channel_reply(c, MSG_CHANNEL_FAILURE) : 1;
    }
    if (req == "pty-req") {
        rstr(r); r32(r); r32(r); r32(r); r32(r); rstr(r);
        if (!r->err) {
            c->got_pty = 1;
        }
        return want ? channel_reply(c, MSG_CHANNEL_SUCCESS) : 1;
    }
    if (req == "env") {
        Str name = rstr(r);
        Str val  = rstr(r);
        if (!r->err) {
            c->envname = push(&c->arena, c->envname, clone(&c->arena, name));
            c->envval  = push(&c->arena, c->envval,  clone(&c->arena, val));
        }
        return want ? channel_reply(c, MSG_CHANNEL_SUCCESS) : 1;
    }
    if (req == "shell") {
        b32 ok = start_child(c, Str{});
        return want ? channel_reply(c, ok ? MSG_CHANNEL_SUCCESS
                                          : MSG_CHANNEL_FAILURE) : 1;
    }
    if (req == "exec") {
        Str cmd = rstr(r);
        b32 ok = !r->err && start_child(c, cmd);
        return want ? channel_reply(c, ok ? MSG_CHANNEL_SUCCESS
                                          : MSG_CHANNEL_FAILURE) : 1;
    }
    if (req == "window-change") {
        r32(r); r32(r); r32(r); r32(r);
        return 1;
    }
    if (req == "signal") {
        rstr(r);
        if (c->child_started) {
            proc_kill(&c->proc);
        }
        return 1;
    }
    return want ? channel_reply(c, MSG_CHANNEL_FAILURE) : 1;
}

static b32 handle_msg(Conn *c, u8 const *pl, iz plen)
{
    Rd r = {pl, plen, 0, 0};
    u8 msg = r8(&r);

    switch (msg) {
    case MSG_DISCONNECT:
        return 0;
    case MSG_IGNORE:
    case MSG_DEBUG:
    case MSG_UNIMPLEMENTED:
    case MSG_EXT_INFO:
        return 1;
    case MSG_KEXINIT:
        return do_kex(c, &c->arena, 0, Str{(u8 *)pl, plen});

    case MSG_GLOBAL_REQUEST: {
        rstr(&r);
        b32 want = r8(&r);
        if (want) {
            u8 b = MSG_REQUEST_FAILURE;
            return send_packet(c, &b, 1);
        }
        return 1;
    }

    case MSG_CHANNEL_OPEN: {
        Str type   = rstr(&r);
        u32 sender = r32(&r);
        u32 win    = r32(&r);
        u32 maxpkt = r32(&r);
        if (r.err) {
            return 0;
        }
        if (type == "session" && !c->chan_open) {
            c->chan_open     = 1;
            c->chan_remote   = sender;
            c->chan_local    = 0;
            c->win_remote    = win;
            c->pkt_remote    = maxpkt;
            c->win_local_max = CHAN_WINDOW;
            c->win_local     = CHAN_WINDOW;
            u8 buf[32];
            Wr w = {buf, 0, sizeof(buf), 0};
            w8(&w, MSG_CHANNEL_OPEN_CONFIRM);
            w32(&w, sender);
            w32(&w, 0);
            w32(&w, CHAN_WINDOW);
            w32(&w, CHAN_MAXPKT);
            return send_packet(c, buf, w.len);
        }
        u8 buf[64];
        Wr w = {buf, 0, sizeof(buf), 0};
        w8(&w, MSG_CHANNEL_OPEN_FAILURE);
        w32(&w, sender);
        w32(&w, type == "session" ? 1 : 3);
        wcstr(&w, "unsupported channel");
        wcstr(&w, "");
        return send_packet(c, buf, w.len);
    }

    case MSG_CHANNEL_WINDOW_ADJUST: {
        u32 rec = r32(&r);
        u32 add = r32(&r);
        if (!r.err && rec == c->chan_local) {
            u64 nw = (u64)c->win_remote + add;
            c->win_remote = nw > 0xffffffffu ? 0xffffffffu : (u32)nw;
        }
        return 1;
    }

    case MSG_CHANNEL_DATA: {
        u32 rec  = r32(&r);
        Str data = rstr(&r);
        if (r.err) {
            return 0;
        }
        if (rec == c->chan_local) {
            if (data.len > (iz)c->win_local) {
                data.len = c->win_local;
            }
            c->win_local -= (u32)data.len;
            if (c->child_started) {
                proc_write(&c->proc, data.data, data.len);
            }
            return adjust_window(c);
        }
        return 1;
    }

    case MSG_CHANNEL_EXTENDED_DATA: {
        u32 rec = r32(&r);
        r32(&r);
        Str data = rstr(&r);
        if (!r.err && rec == c->chan_local) {
            if (data.len > (iz)c->win_local) {
                data.len = c->win_local;
            }
            c->win_local -= (u32)data.len;
            return adjust_window(c);
        }
        return 1;
    }

    case MSG_CHANNEL_EOF: {
        r32(&r);
        if (c->child_started) {
            proc_close_stdin(&c->proc);
        }
        return 1;
    }

    case MSG_CHANNEL_CLOSE: {
        r32(&r);
        c->got_close = 1;
        if (!c->sent_close) {
            if (c->child_started) {
                proc_kill(&c->proc);
            }
            u8 buf[8];
            Wr w = {buf, 0, sizeof(buf), 0};
            w8(&w, MSG_CHANNEL_CLOSE);
            w32(&w, c->chan_remote);
            if (!send_packet(c, buf, w.len)) {
                return 0;
            }
            c->sent_close = 1;
        }
        return 1;
    }

    case MSG_CHANNEL_REQUEST:
        return handle_request(c, &r);

    case MSG_CHANNEL_SUCCESS:
    case MSG_CHANNEL_FAILURE:
        r32(&r);
        return 1;

    default: {
        u8 buf[8];
        Wr w = {buf, 0, sizeof(buf), 0};
        w8(&w, MSG_UNIMPLEMENTED);
        w32(&w, c->seqrecv - 1);
        return send_packet(c, buf, w.len);
    }
    }
}

static void session_phase(Conn *c)
{
    for (;;) {
        i32 a = read_available(c);
        if (a < 0) {
            break;
        }
        for (;;) {
            u8 *pl = 0;
            iz  plen = 0;
            i32 r = recv_packet(c, &pl, &plen);
            if (r == 0) {
                break;
            }
            if (r < 0) {
                return;
            }
            if (!handle_msg(c, pl, plen)) {
                return;
            }
        }
        if (c->child_started) {
            pump_output(c);
            if (!proc_alive(&c->proc) && !c->sent_exit) {
                if (proc_pending(&c->proc, 0) <= 0 &&
                        proc_pending(&c->proc, 1) <= 0) {
                    finish_child(c);
                }
            }
        }
        if (c->sent_close && c->got_close) {
            return;
        }
        if (a == 0 && sock_wait(c->sock, 10) < 0) {
            return;
        }
    }
}


// Per-connection entry point

static void conn_run(Conn *c)
{
    os_log("sshd: connect");
    if (!version_exchange(c)) {
        os_log("sshd: version exchange failed");
        return;
    }
    if (!do_kex(c, &c->arena, 1, Str{})) {
        os_log("sshd: kex failed");
        return;
    }
    if (!auth_phase(c)) {
        os_log("sshd: auth failed");
        return;
    }
    os_log("sshd: authenticated");
    session_phase(c);
    os_log("sshd: session ended");
}


// Self-test (known-answer tests for the crypto primitives)

static i32 hexval(u8 c)
{
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='f') return c - 'a' + 10;
    if (c>='A' && c<='F') return c - 'A' + 10;
    return -1;
}

static b32 unhex(u8 *out, iz cap, Str hex, iz *outlen)
{
    iz n = 0;
    for (iz i = 0; i + 1 < hex.len; i += 2) {
        i32 hi = hexval(hex[i]);
        i32 lo = hexval(hex[i+1]);
        if (hi < 0 || lo < 0 || n >= cap) {
            return 0;
        }
        out[n++] = (u8)(hi<<4 | lo);
    }
    *outlen = n;
    return 1;
}

static void report(Arena *a, Str name, b32 ok, i32 *fails)
{
    Buf b = Buf(a, 64);
    print(&b, name);
    print(&b, cstr(ok ? " ok" : " FAIL"));
    os_log(finish(&b));
    if (!ok) {
        (*fails)++;
    }
}

static b32 selftest_eq(u8 const *got, u8 const *want, iz n)
{
    return !__builtin_memcmp(got, want, n);
}

static i32 selftest(Arena *a)
{
    ed25519_init();
    i32 fails = 0;
    u8  got[128], want[128];
    iz  glen = 0, wlen = 0;

    sha256(got, "abc", 3);
    unhex(want, sizeof(want),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          &wlen);
    report(a, "sha256", selftest_eq(got, want, 32), &fails);

    sha512(got, "abc", 3);
    unhex(want, sizeof(want),
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
          &wlen);
    report(a, "sha512", selftest_eq(got, want, 64), &fails);

    {
        u8 key[32];
        unhex(key, sizeof(key),
              "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
              &glen);
        Poly1305 p;
        poly1305_init(&p, key);
        poly1305_update(&p, (u8 const *)"Cryptographic Forum Research Group", 34);
        poly1305_final(&p, got);
        unhex(want, sizeof(want), "a8061dc1305136c6c22b8baf0c0127a9", &wlen);
        report(a, "poly1305", selftest_eq(got, want, 16), &fails);
    }

    {
        u8 key[64], pkt[128];
        unhex(key, sizeof(key),
              "8bbff6855fc102338c373e73aac0c914f076a905b2444a32eecaffaae22becc5"
              "e9b7a7a5825a8249346ec1c28301cf394543fc7569887d76e168f37562ac0740",
              &glen);
        unhex(pkt, sizeof(pkt),
              "00000048065e00000000000000384c6f72656d20697073756d20646f6c6f72"
              "2073697420616d65742c20636f6e7365637465747572206164697069736963"
              "696e6720656c69744e43e804dc6c", &glen);
        chachapoly_seal(pkt, 4 + 0x48, key, 7);
        unhex(want, sizeof(want),
              "2c3ecce48921cda73f112f076252c1dbc166dcc0f8b6caacfb7904c7ccce6e3b"
              "137b337f633452691a6a23e1c9c8a4b59ca515adea4ff360d9c77c0ffeddc655"
              "64861469d73cf158c1a3d94eabe197ad1a5f91762a6cfa8e41b50719", &wlen);
        report(a, "chachapoly", selftest_eq(pkt, want, 4 + 0x48 + 16), &fails);
    }

    {
        u8 k[32], u[32], out[32];
        unhex(k, sizeof(k),
              "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
              &glen);
        unhex(u, sizeof(u),
              "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
              &glen);
        x25519(out, k, u);
        unhex(want, sizeof(want),
              "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
              &wlen);
        report(a, "x25519", selftest_eq(out, want, 32), &fails);
    }

    {
        u8 seed[32], pub[32], sig[64];
        unhex(seed, sizeof(seed),
              "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
              &glen);
        ed25519_pubkey(pub, seed);
        unhex(want, sizeof(want),
              "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
              &wlen);
        report(a, "ed25519 pub", selftest_eq(pub, want, 32), &fails);

        ed25519_sign(sig, (u8 const *)"", 0, seed);
        unhex(want, sizeof(want),
              "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
              "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
              &wlen);
        report(a, "ed25519 sign", selftest_eq(sig, want, 64), &fails);
        report(a, "ed25519 verify", ed25519_verify(sig, (u8 const *)"", 0, pub),
               &fails);
        sig[0] ^= 1;
        report(a, "ed25519 reject", !ed25519_verify(sig, (u8 const *)"", 0, pub),
               &fails);
    }

    {
        // UTF-8 -> UTF-16 -> UTF-8 round trip, including a surrogate pair.
        Str src = "h\xc3\xa9" "llo \xf0\x9f\x98\x80";
        u16 wide[32];
        iz n = utf8_to_wide(wide, countof(wide), src);
        Str back = wide_to_utf8(a, wide, n);
        report(a, "utf8 roundtrip", back == src, &fails);

        // Invalid UTF-8 becomes U+FFFD.
        iz m = utf8_to_wide(wide, countof(wide), Str{"\xff"});
        report(a, "utf8 invalid", m == 1 && wide[0] == 0xfffd, &fails);
    }

    return fails;
}

// Win32 platform layer: no CRT, kernel32/ws2_32/advapi32/shell32 only.
// Win32 calls use the W APIs; strings are UTF-8 and converted at the boundary.
// This is free and unencumbered software released into the public domain.
//
// Build (32-bit Windows XP):
//   i686-w64-mingw32-g++ -std=c++20 -O2 -nostartfiles -static-libgcc ...
// Build (64-bit):
//   x86_64-w64-mingw32-g++ ...

enum : i32 {
    CP_UTF8                    = 65001,
    CREATE_ALWAYS              = 2,
    CREATE_NO_WINDOW           = 0x08000000,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CRYPT_VERIFYCONTEXT        = (i32)0xF0000000,
    FILE_ATTRIBUTE_NORMAL      = 0x80,
    FILE_SHARE_READ            = 1,
    FIONBIO                    = (i32)0x8004667e,
    GENERIC_READ               = (i32)0x80000000,
    GENERIC_WRITE              = 0x40000000,
    HANDLE_FLAG_INHERIT        = 1,
    INVALID_FILE_ATTRIBUTES    = -1,
    MEM_COMMIT                 = 0x1000,
    MEM_RESERVE                = 0x2000,
    OPEN_EXISTING              = 3,
    PAGE_READWRITE             = 4,
    PROV_RSA_FULL              = 1,
    STARTF_USESTDHANDLES       = 0x100,
    STD_ERROR_HANDLE           = -12,
    WAIT_OBJECT_0              = 0,
    AF_INET                    = 2,
    SOCK_STREAM                = 1,
    IPPROTO_TCP                = 6,
    SOL_SOCKET                 = 0xffff,
    SO_REUSEADDR               = 4,
    TCP_NODELAY                = 1,
    WSAEWOULDBLOCK             = 10035,
};

enum : uz {
    INVALID_HANDLE_VALUE = (uz)-1,
    INVALID_SOCKET       = (uz)-1,
};

struct SecurityAttributes {
    u32 nLength;
    void *lpSecurityDescriptor;
    i32 bInheritHandle;
};

struct CriticalSection {  // opaque CRITICAL_SECTION
    uz opaque[8];
};

struct StartupInfo {  // STARTUPINFOW
    u32 cb;
    u16 *lpReserved;
    u16 *lpDesktop;
    u16 *lpTitle;
    u32 dwX, dwY, dwXSize, dwYSize;
    u32 dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    u16 wShowWindow, cbReserved2;
    void *lpReserved2;
    uz  hStdInput, hStdOutput, hStdError;
};

struct ProcessInfo {  // PROCESS_INFORMATION
    uz  hProcess;
    uz  hThread;
    u32 dwProcessId;
    u32 dwThreadId;
};

struct SockaddrIn {
    u16 family;
    u16 port;
    u32 addr;
    u8  zero[8];
};

struct FdSet {  // Windows fd_set
    u32 count;
    uz  fd[64];
};

struct Timeval {
    i32 sec;
    i32 usec;
};

#define W32(r, p) extern "C" __declspec(dllimport) r __stdcall p noexcept
W32(b32,    CloseHandle(uz));
W32(u16 **, CommandLineToArgvW(u16 const *, i32 *));
W32(uz,     CreateFileW(u16 const *, u32, u32, void *, u32, u32, uz));
W32(b32,    CreatePipe(uz *, uz *, void *, u32));
W32(b32,    CreateProcessW(u16 const *, u16 *, void *, void *, b32, u32,
                           void *, u16 const *, void *, void *));
W32(uz,     CreateThread(void *, uz, u32 (__stdcall *)(void *), void *, u32, u32 *));
W32(void,   DeleteCriticalSection(void *));
W32(void,   EnterCriticalSection(void *));
W32(void,   ExitProcess[[noreturn]](u32));
W32(b32,    FreeEnvironmentStringsW(u16 *));
W32(u16 *,  GetCommandLineW());
W32(u16 *,  GetEnvironmentStringsW());
W32(b32,    GetExitCodeProcess(uz, u32 *));
W32(u32,    GetFileAttributesW(u16 const *));
W32(u32,    GetFileSize(uz, u32 *));
W32(u32,    GetLastError());
W32(u32,    GetModuleFileNameW(uz, u16 *, u32));
W32(uz,     GetStdHandle(i32));
W32(void,   InitializeCriticalSection(void *));
W32(void,   LeaveCriticalSection(void *));
W32(uz,     LocalFree(uz));
W32(i32,    MultiByteToWideChar(u32, u32, char const *, i32, u16 *, i32));
W32(b32,    PeekNamedPipe(uz, void *, u32, u32 *, u32 *, u32 *));
W32(b32,    ReadFile(uz, void *, u32, u32 *, void *));
W32(b32,    SetHandleInformation(uz, u32, u32));
W32(void,   Sleep(u32));
W32(b32,    TerminateProcess(uz, u32));
W32(byte *, VirtualAlloc(uz, uz, u32, u32));
W32(u32,    WaitForSingleObject(uz, u32));
W32(i32,    WideCharToMultiByte(u32, u32, u16 const *, i32, char *, i32,
                                char const *, b32 *));
W32(b32,    WriteFile(uz, void const *, u32, u32 *, void *));
W32(i32,    WSAStartup(u16, void *));
W32(i32,    WSAGetLastError());
W32(uz,     accept(uz, void *, i32 *));
W32(i32,    bind(uz, void *, i32));
W32(i32,    closesocket(uz));
W32(i32,    ioctlsocket(uz, i32, u32 *));
W32(i32,    listen(uz, i32));
W32(i32,    recv(uz, char *, i32, i32));
W32(i32,    select(i32, void *, void *, void *, void *));
W32(i32,    send(uz, char const *, i32, i32));
W32(i32,    setsockopt(uz, i32, i32, char const *, i32));
W32(uz,     socket(i32, i32, i32));
W32(b32,    CryptAcquireContextW(uz *, u16 const *, u16 const *, u32, u32));
W32(b32,    CryptGenRandom(uz, u32, u8 *));
W32(b32,    CryptReleaseContext(uz, u32));

// GCC emits calls to these even without a CRT. Defining them keeps
// msvcrt.dll out of the imports.
#if defined(__x86_64__) || defined(__i386__)
extern "C" void *memcpy(void *dst, void const *src, uz len)
{
    void *r = dst;
    __asm volatile ("rep movsb" : "+D"(dst), "+S"(src), "+c"(len) : : "memory");
    return r;
}

extern "C" void *memset(void *dst, i32 c, uz len)
{
    void *r = dst;
    __asm volatile ("rep stosb" : "+D"(dst), "+c"(len) : "a"(c) : "memory");
    return r;
}

extern "C" void *memmove(void *dst, void const *src, uz len)
{
    u8 *d = (u8 *)dst;
    u8 const *s = (u8 const *)src;
    if (d < s) {
        for (uz i = 0; i < len; i++) {
            d[i] = s[i];
        }
    } else {
        for (uz i = len; i > 0; i--) {
            d[i-1] = s[i-1];
        }
    }
    return dst;
}

extern "C" i32 memcmp(void const *a, void const *b, uz len)
{
    u8 const *x = (u8 const *)a;
    u8 const *y = (u8 const *)b;
    for (uz i = 0; i < len; i++) {
        if (x[i] != y[i]) {
            return x[i] - y[i];
        }
    }
    return 0;
}

extern "C" uz strlen(char const *s)
{
    char const *p = s;
    while (*p) {
        p++;
    }
    return (uz)(p - s);
}
#endif

// UTF-8 <-> UTF-16 conversion. Invalid UTF-8 becomes U+FFFD.

static iz utf8_to_wide(u16 *dst, iz cap, Str s)
{
    i32 n = MultiByteToWideChar(CP_UTF8, 0, (char const *)s.data, (i32)s.len,
                                dst, (i32)cap);
    return n > 0 ? (iz)n : 0;
}

static iz utf8_count16(Str s)
{
    return utf8_to_wide(0, 0, s);
}

static u16 *utf8_to_wide_alloc(Arena *a, Str s)
{
    u16 *w = alloc<u16>(a, s.len + 1);
    iz n = utf8_to_wide(w, s.len + 1, s);
    w[n] = 0;
    return w;
}

static iz wstrlen(u16 const *s)
{
    iz n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

static Str wide_to_utf8(Arena *a, u16 const *s, iz len)
{
    i32 n = WideCharToMultiByte(CP_UTF8, 0, s, (i32)len, 0, 0, 0, 0);
    if (n <= 0) {
        return {};
    }
    u8 *buf = allocbytes(a, n);
    WideCharToMultiByte(CP_UTF8, 0, s, (i32)len, (char *)buf, n, 0, 0);
    return {buf, (iz)n};
}

// Case-insensitive ASCII equality on UTF-16.
static b32 w_iequals(u16 const *a, iz alen, u16 const *b, iz blen)
{
    if (alen != blen) {
        return 0;
    }
    for (iz i = 0; i < alen; i++) {
        u16 x = a[i], y = b[i];
        if (x>='A' && x<='Z') x += 32;
        if (y>='A' && y<='Z') y += 32;
        if (x != y) {
            return 0;
        }
    }
    return 1;
}

static CriticalSection log_lock;
static CriticalSection spawn_lock;
static b32 selftest_flag;

static void writeall(uz h, u8 const *data, iz len)
{
    while (len > 0) {
        u32 cap = len > (1<<20) ? (1<<20) : (u32)len;
        u32 wrote = 0;
        if (!WriteFile(h, data, cap, &wrote, 0) || !wrote) {
            return;
        }
        data += wrote;
        len  -= wrote;
    }
}

[[noreturn]] static void os_oom()
{
    os_log("sshd: out of memory");
    ExitProcess(2);
}

static void os_log(Str s)
{
    EnterCriticalSection(&log_lock);
    uz h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        writeall(h, s.data, s.len);
        writeall(h, (u8 const *)"\n", 1);
    }
    LeaveCriticalSection(&log_lock);
}

static void os_random(u8 *buf, iz len)
{
    uz prov = 0;
    if (!CryptAcquireContextW(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        os_log("sshd: cannot acquire crypto provider");
        ExitProcess(1);
    }
    iz off = 0;
    while (off < len) {
        u32 cap = len-off > 0x1000 ? 0x1000 : (u32)(len-off);
        if (!CryptGenRandom(prov, cap, buf+off)) {
            CryptReleaseContext(prov, 0);
            os_log("sshd: random failed");
            ExitProcess(1);
        }
        off += cap;
    }
    CryptReleaseContext(prov, 0);
}


// Files

static b32 pathbuf(u16 *dst, iz cap, Str path)
{
    if (cap < 1) {
        return 0;
    }
    iz n = utf8_to_wide(dst, cap-1, path);
    if (!n && path.len) {
        return 0;
    }
    dst[n] = 0;
    return 1;
}

static b32 os_readfile(Arena *a, Str path, Str *out)
{
    u16 pbuf[512];
    if (!pathbuf(pbuf, countof(pbuf), path)) {
        return 0;
    }
    uz h = CreateFileW(pbuf, GENERIC_READ, FILE_SHARE_READ, 0,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    u32 size = GetFileSize(h, 0);
    if (size == 0xffffffff) {
        CloseHandle(h);
        return 0;
    }
    u8 *buf = allocbytes(a, (iz)size);
    iz off = 0;
    while (off < (iz)size) {
        u32 got = 0;
        if (!ReadFile(h, buf+off, (u32)(size-off), &got, 0) || !got) {
            CloseHandle(h);
            return 0;
        }
        off += got;
    }
    CloseHandle(h);
    *out = {buf, (iz)size};
    return 1;
}

static b32 os_writefile(Str path, u8 const *data, iz len)
{
    u16 pbuf[512];
    if (!pathbuf(pbuf, countof(pbuf), path)) {
        return 0;
    }
    uz h = CreateFileW(pbuf, GENERIC_WRITE, 0, 0,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    b32 ok = 1;
    iz off = 0;
    while (off < len) {
        u32 wrote = 0;
        if (!WriteFile(h, data+off, (u32)(len-off), &wrote, 0) || !wrote) {
            ok = 0;
            break;
        }
        off += wrote;
    }
    CloseHandle(h);
    return ok;
}


// Sockets

static i32 sock_recv(uz sock, u8 *buf, iz len)
{
    i32 cap = len > (1<<20) ? (1<<20) : (i32)len;
    i32 got = recv(sock, (char *)buf, cap, 0);
    if (got > 0) {
        return got;
    }
    if (got == 0) {
        return 0;
    }
    return WSAGetLastError() == WSAEWOULDBLOCK ? SOCK_WOULDBLOCK : SOCK_ERR;
}

static b32 sock_send(uz sock, u8 const *buf, iz len)
{
    iz off = 0;
    while (off < len) {
        i32 cap = len-off > (1<<20) ? (1<<20) : (i32)(len-off);
        i32 sent = send(sock, (char const *)(buf+off), cap, 0);
        if (sent > 0) {
            off += sent;
            continue;
        }
        if (sent < 0 && WSAGetLastError() == WSAEWOULDBLOCK) {
            FdSet wf = {};
            wf.count = 1;
            wf.fd[0] = sock;
            Timeval tv;
            tv.sec  = 10;
            tv.usec = 0;
            if (select(0, 0, &wf, 0, &tv) <= 0) {
                return 0;
            }
            continue;
        }
        return 0;
    }
    return 1;
}

static i32 sock_wait(uz sock, i32 ms)
{
    FdSet rf = {};
    rf.count = 1;
    rf.fd[0] = sock;
    Timeval tv;
    tv.sec  = ms/1000;
    tv.usec = (ms%1000)*1000;
    i32 r = select(0, &rf, 0, 0, &tv);
    if (r > 0) {
        return 1;
    }
    return r == 0 ? 0 : -1;
}


// Child processes

static b32 str_contains_ci(Str hay, char const *needle)
{
    iz nlen = 0;
    while (needle[nlen]) {
        nlen++;
    }
    if (nlen > hay.len) {
        return 0;
    }
    for (iz i = 0; i + nlen <= hay.len; i++) {
        b32 ok = 1;
        for (iz j = 0; j < nlen; j++) {
            u8 a = hay[i+j], b = (u8)needle[j];
            if (a>='A' && a<='Z') a += 32;
            if (b>='A' && b<='Z') b += 32;
            if (a != b) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            return 1;
        }
    }
    return 0;
}

static b32 is_powershell(Str shell)
{
    iz start = 0;
    for (iz i = 0; i < shell.len; i++) {
        if (shell.data[i]=='\\' || shell.data[i]=='/') {
            start = i + 1;
        }
    }
    Str base = {shell.data + start, shell.len - start};
    return str_contains_ci(base, "powershell") || str_contains_ci(base, "pwsh");
}

static void append_arg(u8 *buf, iz cap, iz *len, Str arg)
{
    b32 quote = arg.len == 0;
    for (iz i = 0; i < arg.len; i++) {
        if (arg.data[i]==' ' || arg.data[i]=='\t' || arg.data[i]=='"') {
            quote = 1;
        }
    }
    if (*len && *len < cap) {
        buf[(*len)++] = ' ';
    }
    if (!quote) {
        for (iz i = 0; i < arg.len && *len < cap; i++) {
            buf[(*len)++] = arg.data[i];
        }
        return;
    }
    if (*len < cap) {
        buf[(*len)++] = '"';
    }
    iz bs = 0;
    for (iz i = 0; i < arg.len; i++) {
        u8 c = arg.data[i];
        if (c == '\\') {
            bs++;
            if (*len < cap) buf[(*len)++] = c;
        } else if (c == '"') {
            for (iz k = 0; k < bs && *len < cap; k++) buf[(*len)++] = '\\';
            if (*len < cap) buf[(*len)++] = '\\';
            if (*len < cap) buf[(*len)++] = '"';
            bs = 0;
        } else {
            bs = 0;
            if (*len < cap) buf[(*len)++] = c;
        }
    }
    for (iz k = 0; k < bs && *len < cap; k++) {
        buf[(*len)++] = '\\';
    }
    if (*len < cap) {
        buf[(*len)++] = '"';
    }
}

static u16 *build_env(Arena *a, Slice<Str> names, Slice<Str> vals)
{
    iz n = names.len;
    u16 **wname = alloc<u16 *>(a, n);
    u16 **wval  = alloc<u16 *>(a, n);
    iz   *wnlen = alloc<iz>(a, n);
    iz   *wvlen = alloc<iz>(a, n);
    for (iz i = 0; i < n; i++) {
        wnlen[i] = utf8_count16(names[i]);
        wname[i] = alloc<u16>(a, wnlen[i]+1);
        utf8_to_wide(wname[i], wnlen[i], names[i]);
        wname[i][wnlen[i]] = 0;
        wvlen[i] = utf8_count16(vals[i]);
        wval[i]  = alloc<u16>(a, wvlen[i]+1);
        utf8_to_wide(wval[i], wvlen[i], vals[i]);
        wval[i][wvlen[i]] = 0;
    }

    u16 *parent = GetEnvironmentStringsW();
    iz total = 0;
    if (parent) {
        u16 *q = parent;
        while (*q) {
            iz l = 0;
            while (q[l]) l++;
            total += l + 1;
            q += l + 1;
        }
    }
    for (iz i = 0; i < n; i++) {
        total += wnlen[i] + 1 + wvlen[i] + 1;
    }

    u16 *blk = alloc<u16>(a, total + 2);
    iz m = 0;
    if (parent) {
        u16 *q = parent;
        while (*q) {
            iz l = 0;
            while (q[l]) l++;
            iz eq = 0;
            while (eq < l && q[eq] != '=') eq++;
            b32 skip = 0;
            for (iz i = 0; i < n; i++) {
                if (w_iequals(q, eq, wname[i], wnlen[i])) {
                    skip = 1;
                    break;
                }
            }
            if (!skip) {
                for (iz j = 0; j <= l; j++) {
                    blk[m++] = q[j];
                }
            }
            q += l + 1;
        }
        FreeEnvironmentStringsW(parent);
    }
    for (iz i = 0; i < n; i++) {
        for (iz j = 0; j < wnlen[i]; j++) blk[m++] = wname[i][j];
        blk[m++] = '=';
        for (iz j = 0; j < wvlen[i]; j++) blk[m++] = wval[i][j];
        blk[m++] = 0;
    }
    blk[m++] = 0;
    return blk;
}

static b32 proc_spawn(Proc *p, Str shell, Str cmd,
                      Slice<Str> names, Slice<Str> vals, Arena *a)
{
    b32 pwsh = is_powershell(shell);

    Str argv[8];
    i32 argc = 0;
    argv[argc++] = shell;
    if (cmd.len) {
        if (pwsh) {
            argv[argc++] = "-NoLogo";
            argv[argc++] = "-NoProfile";
            argv[argc++] = "-Command";
            argv[argc++] = cmd;
        } else {
            argv[argc++] = "-c";
            argv[argc++] = cmd;
        }
    } else if (pwsh) {
        argv[argc++] = "-NoLogo";
        argv[argc++] = "-NoProfile";
        argv[argc++] = "-Command";
        argv[argc++] = "-";
    }

    u8 *line = allocbytes(a, 4096);
    iz  linelen = 0;
    for (i32 i = 0; i < argc; i++) {
        append_arg(line, 4096 - 1, &linelen, argv[i]);
    }

    u16 *wline = utf8_to_wide_alloc(a, Str{line, linelen});
    u16 *env   = build_env(a, names, vals);

    SecurityAttributes sa = {sizeof(sa), 0, 1};
    uz in_r = 0, in_w = 0, out_r = 0, out_w = 0, err_r = 0, err_w = 0;

    EnterCriticalSection(&spawn_lock);
    b32 ok = CreatePipe(&in_r, &in_w, &sa, 0) &&
             CreatePipe(&out_r, &out_w, &sa, 0) &&
             CreatePipe(&err_r, &err_w, &sa, 0);
    if (ok) {
        SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);

        StartupInfo si = {};
        si.cb         = sizeof(si);
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.hStdInput  = in_r;
        si.hStdOutput = out_w;
        si.hStdError  = err_w;
        ProcessInfo pi = {};
        ok = CreateProcessW(0, wline, 0, 0, 1,
                            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                            env, 0, &si, &pi);
        if (ok) {
            CloseHandle(pi.hThread);
            p->hproc   = pi.hProcess;
            p->hstdin  = in_w;
            p->hstdout = out_r;
            p->hstderr = err_r;
            p->running = 1;
        }
    }
    LeaveCriticalSection(&spawn_lock);

    if (in_r)  CloseHandle(in_r);
    if (out_w) CloseHandle(out_w);
    if (err_w) CloseHandle(err_w);
    if (!ok) {
        if (in_w)  CloseHandle(in_w);
        if (out_r) CloseHandle(out_r);
        if (err_r) CloseHandle(err_r);
    }
    return ok;
}

static iz proc_pending(Proc *p, i32 which)
{
    uz h = which ? p->hstderr : p->hstdout;
    if (!h || h == INVALID_HANDLE_VALUE) {
        return -1;
    }
    u32 avail = 0;
    if (!PeekNamedPipe(h, 0, 0, 0, &avail, 0)) {
        return -1;
    }
    return (iz)avail;
}

static iz proc_read(Proc *p, u8 *buf, iz len, i32 which)
{
    uz h = which ? p->hstderr : p->hstdout;
    u32 got = 0;
    i32 cap = len > (1<<20) ? (1<<20) : (i32)len;
    if (!ReadFile(h, buf, cap, &got, 0)) {
        return -1;
    }
    return (iz)got;
}

static b32 proc_write(Proc *p, u8 const *buf, iz len)
{
    if (!p->hstdin) {
        return 0;
    }
    iz off = 0;
    while (off < len) {
        u32 wrote = 0;
        i32 cap = len-off > (1<<20) ? (1<<20) : (i32)(len-off);
        if (!WriteFile(p->hstdin, buf+off, cap, &wrote, 0) || !wrote) {
            return 0;
        }
        off += wrote;
    }
    return 1;
}

static b32 proc_alive(Proc *p)
{
    return p->hproc && WaitForSingleObject(p->hproc, 0) != WAIT_OBJECT_0;
}

static u32 proc_status(Proc *p)
{
    u32 s = 0;
    GetExitCodeProcess(p->hproc, &s);
    return s;
}

static void proc_close_stdin(Proc *p)
{
    if (p->hstdin) {
        CloseHandle(p->hstdin);
        p->hstdin = 0;
    }
}

static void proc_kill(Proc *p)
{
    if (p->hproc) {
        TerminateProcess(p->hproc, 1);
    }
    proc_close_stdin(p);
}


// Connection pool: freelist of fixed regions.

enum { BLOCKSIZE = 1<<20, MAXCONNS = 32 };

struct Block {
    Block *next;
    byte  *mem;
};

struct ConnBox {
    Conn  c;
    Block *block;
};

static struct {
    Block           *free;
    i32              used;
    CriticalSection lock;
} pool;

static Conn *pool_get(void)
{
    EnterCriticalSection(&pool.lock);
    Block *b = pool.free;
    if (b) {
        pool.free = b->next;
    } else if (pool.used < MAXCONNS) {
        byte *mem = VirtualAlloc(0, BLOCKSIZE, MEM_COMMIT|MEM_RESERVE,
                                 PAGE_READWRITE);
        if (mem) {
            b = (Block *)mem;
            b->mem = mem;
            pool.used++;
        }
    }
    LeaveCriticalSection(&pool.lock);
    if (!b) {
        return 0;
    }
    Arena a = {b->mem + sizeof(Block), b->mem + BLOCKSIZE};
    ConnBox *box = alloc<ConnBox>(&a);
    box->block   = b;
    box->c.arena = a;
    box->c.cfg   = &config;
    return &box->c;
}

static void pool_put(Conn *c)
{
    ConnBox *box = (ConnBox *)c;  // Conn is the first member
    Block   *b   = box->block;
    EnterCriticalSection(&pool.lock);
    b->next   = pool.free;
    pool.free = b;
    LeaveCriticalSection(&pool.lock);
}

static u32 __stdcall conn_thread(void *param)
{
    Conn *c = (Conn *)param;
    conn_run(c);
    if (c->sock) {
        closesocket(c->sock);
    }
    if (c->child_started) {
        proc_kill(&c->proc);
        if (c->proc.hproc)   CloseHandle(c->proc.hproc);
        if (c->proc.hstdout) CloseHandle(c->proc.hstdout);
        if (c->proc.hstderr) CloseHandle(c->proc.hstderr);
        if (c->proc.hstdin)  CloseHandle(c->proc.hstdin);
    }
    pool_put(c);
    return 0;
}


// Startup

static uz make_listener(i32 port)
{
    uz s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return s;
    }
    i32 one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char const *)&one, sizeof(one));

    SockaddrIn addr = {};
    addr.family = AF_INET;
    addr.port   = (u16)(((port & 0xff) << 8) | ((port >> 8) & 0xff));
    addr.addr   = 0;
    if (bind(s, &addr, sizeof(addr)) || listen(s, 16)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static i32 parse_int(Str s, i32 dflt)
{
    if (!s.len) {
        return dflt;
    }
    i32 v = 0;
    for (iz i = 0; i < s.len; i++) {
        if (s.data[i] < '0' || s.data[i] > '9') {
            return dflt;
        }
        v = v*10 + (s.data[i] - '0');
    }
    return v;
}

static void usage(void)
{
    os_log("usage: sshd [-p port] [-k authorized_keys] [-s shell] "
           "[-H hostkey] [-selftest]");
}

static Str resolve_shell(Arena *a, Str shell)
{
    for (iz i = 0; i < shell.len; i++) {
        if (shell.data[i]=='\\' || shell.data[i]=='/') {
            return shell;
        }
    }
    u16 exe[260];
    u32 n = GetModuleFileNameW(0, exe, (u32)countof(exe));
    if (!n || n >= countof(exe)) {
        return shell;
    }
    iz d = n;
    while (d > 0 && exe[d-1] != '\\' && exe[d-1] != '/') {
        d--;
    }
    u16 wshell[260];
    iz wlen = utf8_to_wide(wshell, countof(wshell)-1, shell);
    if (!wlen && shell.len) {
        return shell;
    }
    static u16 const suffix[3][9] = {
        {},
        {'b', 'i', 'n', '\\'},
        {'.', '.', '\\', 'b', 'i', 'n', '\\'},
    };
    u16 buf[512];
    for (i32 k = 0; k < 3; k++) {
        iz len = 0;
        for (iz i = 0; i < d && len < countof(buf)-1; i++) {
            buf[len++] = exe[i];
        }
        for (iz i = 0; suffix[k][i] && len < countof(buf)-1; i++) {
            buf[len++] = suffix[k][i];
        }
        for (iz i = 0; i < wlen && len < countof(buf)-1; i++) {
            buf[len++] = wshell[i];
        }
        buf[len] = 0;
        if (GetFileAttributesW(buf) != (u32)INVALID_FILE_ATTRIBUTES) {
            return wide_to_utf8(a, buf, len);
        }
    }
    return shell;
}

static void load_hostkey(Arena *a)
{
    Str data;
    b32 created = 0;
    if (os_readfile(a, config.hostkeyfile, &data) && data.len == 32) {
        copybytes(config.hostseed, data.data, 32);
    } else {
        os_random(config.hostseed, 32);
        if (!os_writefile(config.hostkeyfile, config.hostseed, 32)) {
            os_log("sshd: cannot write host key");
        }
        created = 1;
    }
    ed25519_pubkey(config.hostpub, config.hostseed);
    if (created) {
        Buf b = Buf(a, 128);
        print(&b, "sshd: host key: ssh-ed25519 ");
        print(&b, b64encode(a, config.hostpub, 32));
        os_log(finish(&b));
    }
}

static void parse_args(Arena *a)
{
    config.port        = 22;
    config.keysfile    = "authorized_keys";
    config.hostkeyfile = "hostkey";
    config.shell       = "sh.exe";

    i32 n = 0;
    u16 **argv = CommandLineToArgvW(GetCommandLineW(), &n);
    if (argv) {
        for (i32 i = 1; i < n; i++) {
            Str t = wide_to_utf8(a, argv[i], wstrlen(argv[i]));
            if (t == "-p" && i+1 < n) {
                i++;
                Str v = wide_to_utf8(a, argv[i], wstrlen(argv[i]));
                config.port = parse_int(v, 22);
            } else if (t == "-k" && i+1 < n) {
                i++;
                config.keysfile = wide_to_utf8(a, argv[i], wstrlen(argv[i]));
            } else if (t == "-s" && i+1 < n) {
                i++;
                config.shell = wide_to_utf8(a, argv[i], wstrlen(argv[i]));
            } else if (t == "-H" && i+1 < n) {
                i++;
                config.hostkeyfile = wide_to_utf8(a, argv[i], wstrlen(argv[i]));
            } else if (t == "-selftest") {
                selftest_flag = 1;
            } else if (t == "-h" || t == "-?" || t == "--help") {
                usage();
                ExitProcess(0);
            }
        }
        LocalFree((uz)argv);
    }
}

extern "C" __attribute((force_align_arg_pointer))
void mainCRTStartup()
{
    byte *mem = VirtualAlloc(0, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        os_oom();
    }
    Arena a = {mem, mem + (1<<20)};

    InitializeCriticalSection(&log_lock);
    InitializeCriticalSection(&spawn_lock);
    InitializeCriticalSection(&pool.lock);

    parse_args(&a);

    if (selftest_flag) {
        ExitProcess(selftest(&a) ? 1 : 0);
    }

    u8 wsa[512];
    WSAStartup(0x0202, wsa);

    ed25519_init();
    load_hostkey(&a);
    config.shell = resolve_shell(&a, config.shell);

    uz listener = make_listener(config.port);
    if (listener == INVALID_SOCKET) {
        os_log("sshd: cannot listen");
        ExitProcess(1);
    }
    {
        Buf b = Buf(&a, 64);
        print(&b, "sshd: listening on port ");
        print(&b, (i64)config.port);
        os_log(finish(&b));
    }

    for (;;) {
        uz s = accept(listener, 0, 0);
        if (s == INVALID_SOCKET) {
            continue;
        }
        i32 one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char const *)&one, sizeof(one));
        u32 nonblock = 1;
        ioctlsocket(s, FIONBIO, &nonblock);

        Conn *c = pool_get();
        if (!c) {
            closesocket(s);
            continue;
        }
        c->sock = s;

        u32 tid = 0;
        uz th = CreateThread(0, 0, conn_thread, c, 0, &tid);
        if (th) {
            CloseHandle(th);
        } else {
            closesocket(s);
            pool_put(c);
        }
    }
}
