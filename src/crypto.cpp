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
