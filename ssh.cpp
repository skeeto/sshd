// SSH protocol: transport, key exchange, authentication, channels
// This is free and unencumbered software released into the public domain.

// Platform interface (implemented in win32.cpp)

struct StdinQueue;

struct Proc {
    uz  hproc   = {};
    uz  hjob    = {};  // whole process tree, killed on abnormal end
    StdinQueue *stdinq = {};  // drained to the child by a writer thread
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
static b32  proc_write(Proc *p, u8 const *buf, iz len);  // queues, never blocks
static u32  proc_drained(Proc *p);  // bytes delivered since last call
static b32  proc_alive(Proc *p);
static u32  proc_status(Proc *p);
static void proc_kill(Proc *p);
static void proc_close_stdin(Proc *p);
static b32  os_readfile(Arena *a, Str path, Str *out);
static b32  os_writefile(Str path, u8 const *data, iz len);

// File system, for SFTP. Paths are canonical and absolute ("C:/a/b").
// Errors are reported as SFTP status codes.

enum {
    FS_OK     = 0,
    FS_EOF    = 1,
    FS_NOENT  = 2,
    FS_ACCESS = 3,
    FS_FAIL   = 4,
};

enum {  // os_fopen flags, numerically the same as SFTP's
    FS_READ   = 0x01,
    FS_WRITE  = 0x02,
    FS_APPEND = 0x04,
    FS_CREAT  = 0x08,
    FS_TRUNC  = 0x10,
    FS_EXCL   = 0x20,
};

enum {  // SetAttrs fields, numerically the same as SFTP's
    FS_SIZE = 0x01,
    FS_PERM = 0x04,
    FS_TIME = 0x08,
};

struct FileInfo {
    i64 size;
    i64 atime;  // Unix seconds
    i64 mtime;
    b32 dir;
    b32 readonly;
    i32 err;
};

struct SetAttrs {
    u32 flags;
    i64 size;
    u32 perm;
    i64 atime;
    i64 mtime;
};

struct OsFile {
    uz  h;
    i32 err;
};

struct DirEnt {
    Str      name;
    FileInfo info;
    i32      err;  // FS_EOF after the last entry
};

static OsFile   os_fopen(Arena scratch, Str path, i32 flags);
static i32      os_fread(uz h, i64 off, u8 *buf, i32 len);  // 0 at EOF, or -status
static i32      os_fwrite(uz h, i64 off, u8 const *buf, i32 len);  // off<0 appends
static void     os_fclose(uz h);
static FileInfo os_stat(Arena scratch, Str path);
static FileInfo os_fstat(uz h);
static i32      os_setattrs(Arena scratch, Str path, uz h, SetAttrs a);  // via h if open
static DirEnt   os_dirnext(Arena *a, Str path, uz *find);  // *find starts at 0
static void     os_dirclose(uz find);
static i32      os_mkdir(Arena scratch, Str path);
static i32      os_rmdir(Arena scratch, Str path);
static i32      os_remove(Arena scratch, Str path);
static i32      os_rename(Arena scratch, Str from, Str to, b32 replace);
static u8      *os_bigalloc(iz size);  // zeroed, null on failure
static void     os_bigfree(u8 *p);


// Configuration

struct Config {
    i32 port;
    Str keysfile;
    Str hostkeyfile;
    Str shell;
    Str home;  // sessions start here; base for relative SFTP paths
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

// Generous because the network sometimes stalls for most of a minute.
enum { IO_TIMEOUT_MS = 120000 };

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
    u32 win_credit;  // consumed bytes not yet returned to the peer
    b32 got_pty;

    Proc proc;
    b32  child_started;
    b32  sent_exit, sent_eof, sent_close, got_close, got_eof;

    struct Sftp *sftp;  // subsystem in place of a child process

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
        if (a == 0 && !sock_wait(c->sock, IO_TIMEOUT_MS)) {
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
        if (a == 0 && !sock_wait(c->sock, IO_TIMEOUT_MS)) {
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

// Run one key exchange, initial or a rekey started by the peer's KEXINIT
// (ic_in). Nothing allocated in scratch outlives the exchange.
static b32 do_kex(Conn *c, Arena scratch, b32 initial, Str ic_in)
{
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
    u8    ksend[64], krecv[64];

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

    // On a rekey both NEWKEYS messages travel under the old keys, so each
    // new key is installed only after its direction's NEWKEYS.
    derive_key(ksend, 64, Kstr, h, 'D', sid);
    derive_key(krecv, 64, Kstr, h, 'C', sid);

    {
        u8 nk = MSG_NEWKEYS;
        if (!send_packet(c, &nk, 1)) {
            goto done;
        }
    }
    copybytes(c->ksend, ksend, 64);
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
    copybytes(c->krecv, krecv, 64);
    c->recv_enc = 1;
    if (c->strict) {
        c->seqrecv = 0;
    }

    if (initial) {
        c->initial_done = 1;
    }
    ok = 1;

done:
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
            c->user = clone(&c->arena, user);
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

// Return window only for bytes the child has actually consumed, so that
// queued stdin never exceeds CHAN_WINDOW.
static b32 adjust_window(Conn *c)
{
    if (c->child_started) {
        c->win_credit += proc_drained(&c->proc);
    }
    if (c->win_credit && c->win_local < c->win_local_max / 2) {
        u32 add = c->win_credit;
        u8  buf[16];
        Wr  w = {buf, 0, sizeof(buf), 0};
        w8(&w, MSG_CHANNEL_WINDOW_ADJUST);
        w32(&w, c->chan_remote);
        w32(&w, add);
        c->win_local += add;
        c->win_credit = 0;
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

// Forward child output within the peer's window. Returns true if any
// data was sent.
static b32 pump_output(Conn *c)
{
    b32 sent = 0;
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
                return sent;
            }
            c->win_remote -= (u32)got;
            sent = 1;
        }
    }
    return sent;
}

// SFTP subsystem (sftp.cpp)
static b32  sftp_start(Conn *c);
static void sftp_input(Conn *c, Str data);
static b32  sftp_pump(Conn *c);
static void sftp_free(Conn *c);

// Report the exit status, then end the channel.
static b32 finish_channel(Conn *c, u32 status)
{
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
    if (req == "subsystem") {
        Str name = rstr(r);
        b32 ok   = !r->err && name=="sftp" && !c->child_started && !c->sftp;
        if (ok) {
            os_log("sshd: subsystem sftp");
            ok = sftp_start(c);
        }
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
        return do_kex(c, c->arena, 0, Str{(u8 *)pl, plen});

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
            if (c->sftp) {
                sftp_input(c, data);
            } else if (!c->child_started ||
                    !proc_write(&c->proc, data.data, data.len)) {
                c->win_credit += (u32)data.len;  // discarded
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
            c->win_credit += (u32)data.len;
            return adjust_window(c);
        }
        return 1;
    }

    case MSG_CHANNEL_EOF: {
        r32(&r);
        c->got_eof = 1;
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
        b32 busy = 0;
        if (c->sftp) {
            busy = sftp_pump(c);
            if (!c->sent_close && !adjust_window(c)) {
                return;
            }
        }
        if (c->child_started) {
            busy = pump_output(c);
            if (!c->sent_close && !adjust_window(c)) {
                return;
            }
            if (!proc_alive(&c->proc) && !c->sent_exit) {
                if (proc_pending(&c->proc, 0) <= 0 &&
                        proc_pending(&c->proc, 1) <= 0) {
                    finish_channel(c, proc_status(&c->proc));
                }
            }
        }
        if (c->sent_close && c->got_close) {
            return;
        }
        if (a == 0 && !busy && sock_wait(c->sock, 10) < 0) {
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
    if (!do_kex(c, c->arena, 1, Str{})) {
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

        // Invalid UTF-8 becomes U+FFFD, one per offending byte.
        iz m = utf8_to_wide(wide, countof(wide), Str{"\xff"});
        report(a, "utf8 invalid", m == 1 && wide[0] == 0xfffd, &fails);

        // Overlong, surrogate, truncated, and out-of-range forms.
        Str bad = "a\xc0\xaf" "b\xed\xa0\x80" "c\xf4\x90\x80\x80" "d\xe2\x82";
        m = utf8_to_wide(wide, countof(wide), bad);
        u16 want[] = {'a', 0xfffd, 0xfffd, 'b', 0xfffd, 0xfffd, 0xfffd,
                      'c', 0xfffd, 0xfffd, 0xfffd, 0xfffd, 'd', 0xfffd, 0xfffd};
        b32 same = m == countof(want);
        for (iz i = 0; same && i < m; i++) {
            same = wide[i] == want[i];
        }
        report(a, "utf8 malformed", same, &fails);
    }

    return fails;
}
