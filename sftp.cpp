// SFTP version 3 subsystem, served inside the connection thread
// This is free and unencumbered software released into the public domain.

enum {
    FXP_INIT     = 1,
    FXP_VERSION  = 2,
    FXP_OPEN     = 3,
    FXP_CLOSE    = 4,
    FXP_READ     = 5,
    FXP_WRITE    = 6,
    FXP_LSTAT    = 7,
    FXP_FSTAT    = 8,
    FXP_SETSTAT  = 9,
    FXP_FSETSTAT = 10,
    FXP_OPENDIR  = 11,
    FXP_READDIR  = 12,
    FXP_REMOVE   = 13,
    FXP_MKDIR    = 14,
    FXP_RMDIR    = 15,
    FXP_REALPATH = 16,
    FXP_STAT     = 17,
    FXP_RENAME   = 18,
    FXP_STATUS   = 101,
    FXP_HANDLE   = 102,
    FXP_DATA     = 103,
    FXP_NAME     = 104,
    FXP_ATTRS    = 105,
    FXP_EXTENDED = 200,
};

enum {
    FX_BAD_MESSAGE    = 5,
    FX_OP_UNSUPPORTED = 8,
};

enum {
    ATTR_SIZE     = 0x00000001,
    ATTR_UIDGID   = 0x00000002,
    ATTR_PERM     = 0x00000004,
    ATTR_TIME     = 0x00000008,
    ATTR_EXTENDED = 0x80000000,
};

enum {
    SFTP_INCAP   = CHAN_WINDOW + (1<<16),  // the peer may fill its window
    SFTP_OUTCAP  = 1<<19,
    SFTP_RESERVE = 1<<17,   // free output needed to start a request
    SFTP_SCRATCH = 1<<18,   // per-request memory
    SFTP_MAXREQ  = 1<<18,
    SFTP_MAXREAD = 1<<16,
    SFTP_BATCH   = 1<<15,   // READDIR response size target
    SFTP_HANDLES = 64,
    SFTP_MAXPATH = 1024,
};

enum {
    HANDLE_FREE,
    HANDLE_FILE,
    HANDLE_DIR,
};

struct SftpHandle {
    i32 kind;
    b32 append;
    b32 done;   // directory fully listed
    uz  h;      // file handle or directory search handle
    iz  pathlen;
    u8  path[SFTP_MAXPATH];
};

struct Sftp {
    u8        *in;
    iz         inbeg;
    iz         inlen;
    u8        *out;
    iz         outlen;
    Arena      scratch;
    SftpHandle handles[SFTP_HANDLES];
};


// Paths

static b32 isdrive(Str s)
{
    return s.len>=2 && s.data[1]==':' &&
           ((s.data[0]>='A' && s.data[0]<='Z') || (s.data[0]>='a' && s.data[0]<='z'));
}

// Resolve a client path against the home directory into the canonical
// "C:/a/b" form, collapsing "." and "..". Either slash separates. Returns
// a null string if the result is too long.
static Str sftp_resolve(Arena *a, Str home, Str path)
{
    if (path.len && (path.data[0]=='/' || path.data[0]=='\\')) {
        Str rest = {path.data+1, path.len-1};
        if (isdrive(rest)) {
            path = rest;  // "/C:/x"
        }
    }

    Str drive = isdrive(home) ? Str{home.data, 2} : Str{"C:"};
    Str base  = {};
    if (isdrive(path)) {
        drive = Str{path.data, 2};
        path  = Str{path.data+2, path.len-2};
    } else if (!path.len || (path.data[0]!='/' && path.data[0]!='\\')) {
        base = isdrive(home) ? Str{home.data+2, home.len-2} : Str{};
    }

    u8 *buf = allocbytes(a, SFTP_MAXPATH);
    iz  len = 0;
    buf[len++] = drive.data[0]>='a' ? (u8)(drive.data[0] - 'a' + 'A') : drive.data[0];
    buf[len++] = ':';
    for (i32 pass = 0; pass < 2; pass++) {
        Str s = pass ? path : base;
        for (iz i = 0; i < s.len;) {
            iz j = i;
            for (; j<s.len && s.data[j]!='/' && s.data[j]!='\\'; j++) {}
            Str part = {s.data+i, j-i};
            i = j + 1;
            if (!part.len || part==".") {
                continue;
            }
            if (part == "..") {
                for (; len>2 && buf[len-1]!='/'; len--) {}
                if (len > 2) len--;
                continue;
            }
            if (part.len+1 > SFTP_MAXPATH-len) {
                return {};
            }
            buf[len++] = '/';
            copybytes(buf+len, part.data, part.len);
            len += part.len;
        }
    }
    if (len == 2) {
        buf[len++] = '/';  // drive root
    }
    return {buf, len};
}


// Responses

static Wr sftp_reply(Sftp *s, u8 type, u32 id)
{
    Wr w = {s->out+s->outlen+4, 0, SFTP_OUTCAP-s->outlen-4, 0};
    w8(&w, type);
    w32(&w, id);
    return w;
}

static void sftp_send(Sftp *s, Wr *w)
{
    assert(!w->err);  // guaranteed by SFTP_RESERVE
    u8 *p = s->out + s->outlen;
    p[0] = (u8)(w->len >> 24);
    p[1] = (u8)(w->len >> 16);
    p[2] = (u8)(w->len >>  8);
    p[3] = (u8)(w->len >>  0);
    s->outlen += 4 + w->len;
}

static void sftp_status(Sftp *s, u32 id, i32 code)
{
    static char const *const msgs[] = {
        "Success", "End of file", "No such file", "Permission denied",
        "Failure", "Bad message", "No connection", "Connection lost",
        "Operation unsupported",
    };
    Wr w = sftp_reply(s, FXP_STATUS, id);
    w32(&w, (u32)code);
    wcstr(&w, code>=0 && code<countof(msgs) ? msgs[code] : "Failure");
    wcstr(&w, "");
    sftp_send(s, &w);
}

static void w64(Wr *w, u64 v)
{
    w32(w, (u32)(v >> 32));
    w32(w, (u32)v);
}

static u32 fileperm(FileInfo fi)
{
    u32 mode = fi.dir ? 0040755 : 0100644;
    if (fi.readonly) {
        mode &= ~0222u;
    }
    return mode;
}

static void wattrs(Wr *w, FileInfo fi)
{
    w32(w, ATTR_SIZE | ATTR_UIDGID | ATTR_PERM | ATTR_TIME);
    w64(w, (u64)fi.size);
    w32(w, 0);
    w32(w, 0);
    w32(w, fileperm(fi));
    w32(w, (u32)fi.atime);
    w32(w, (u32)fi.mtime);
}

static u64 r64(Rd *r)
{
    u64 hi = r32(r);
    return hi<<32 | r32(r);
}

static SetAttrs rattrs(Rd *r)
{
    SetAttrs a = {};
    a.flags = r32(r);
    if (a.flags & ATTR_SIZE) {
        a.size = (i64)r64(r);
    }
    if (a.flags & ATTR_UIDGID) {
        r32(r);
        r32(r);
    }
    if (a.flags & ATTR_PERM) {
        a.perm = r32(r);
    }
    if (a.flags & ATTR_TIME) {
        a.atime = r32(r);
        a.mtime = r32(r);
    }
    if (a.flags & ATTR_EXTENDED) {
        u32 n = r32(r);
        for (u32 i = 0; i<n && !r->err; i++) {
            rstr(r);
            rstr(r);
        }
    }
    return a;
}

// Format an "ls -l" style line for READDIR, in UTC.
static Str longname(Arena *a, Str user, Str name, FileInfo fi)
{
    Buf b = Buf(a, 128 + name.len);
    u32 mode = fileperm(fi);
    u8  perm[10];
    perm[0] = fi.dir ? 'd' : '-';
    for (i32 i = 0; i < 9; i++) {
        perm[1+i] = mode>>(8-i) & 1 ? (u8)"rwxrwxrwx"[i] : '-';
    }
    print(&b, Str{perm, 10});
    print(&b, "    1 ");
    Str who = user.len ? user : Str{"user"};
    for (i32 i = 0; i < 2; i++) {
        print(&b, who);
        for (iz n = who.len; n < 8; n++) print(&b, " ");
        print(&b, " ");
    }

    u8  num[24];
    iz  n = 0;
    u64 size = (u64)fi.size;
    do {
        num[n++] = (u8)('0' + size%10);
    } while (size /= 10);
    for (iz i = n; i < 8; i++) print(&b, " ");
    for (iz i = n-1; i >= 0; i--) print(&b, Str{num+i, 1});

    // Days since the epoch to a civil date (Howard Hinnant's algorithm)
    i64 t    = fi.mtime;
    i64 days = (t>=0 ? t : t-86399) / 86400;
    i64 secs = t - days*86400;
    i64 z    = days + 719468;
    i64 era  = (z>=0 ? z : z-146096) / 146097;
    i64 doe  = z - era*146097;
    i64 yoe  = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    i64 doy  = doe - (365*yoe + yoe/4 - yoe/100);
    i64 mp   = (5*doy + 2) / 153;
    i64 day  = doy - (153*mp + 2)/5 + 1;
    i64 mon  = mp<10 ? mp+3 : mp-9;
    static char const months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    print(&b, " ");
    print(&b, Str{(u8 *)months + 3*(mon-1), 3});
    print(&b, cstr(day<10 ? " " : ""));
    print(&b, " ");
    print(&b, day);
    print(&b, " ");
    i64 hh = secs / 3600;
    i64 mm = secs / 60 % 60;
    print(&b, cstr(hh<10 ? "0" : ""));
    print(&b, hh);
    print(&b, cstr(mm<10 ? ":0" : ":"));
    print(&b, mm);
    print(&b, " ");
    print(&b, name);
    return finish(&b);
}


// Handles

static i32 newhandle(Sftp *s, i32 kind, Str path)
{
    for (i32 i = 0; i < SFTP_HANDLES; i++) {
        SftpHandle *h = s->handles + i;
        if (h->kind == HANDLE_FREE) {
            *h = {};
            h->kind    = kind;
            h->pathlen = path.len;
            copybytes(h->path, path.data, path.len);
            return i;
        }
    }
    return -1;
}

static SftpHandle *gethandle(Sftp *s, Str handle, i32 kind)
{
    if (handle.len != 4) {
        return 0;
    }
    u32 i = (u32)handle.data[0]<<24 | (u32)handle.data[1]<<16 |
            (u32)handle.data[2]<< 8 | (u32)handle.data[3];
    if (i >= SFTP_HANDLES) {
        return 0;
    }
    SftpHandle *h = s->handles + i;
    return h->kind && (!kind || h->kind==kind) ? h : 0;
}

static void closehandle(SftpHandle *h)
{
    if (h->kind==HANDLE_FILE && h->h) {
        os_fclose(h->h);
    } else if (h->kind==HANDLE_DIR && h->h) {
        os_dirclose(h->h);
    }
    *h = {};
}

static void sendhandle(Sftp *s, u32 id, i32 i)
{
    u8 bytes[4] = {(u8)(i>>24), (u8)(i>>16), (u8)(i>>8), (u8)i};
    Wr w = sftp_reply(s, FXP_HANDLE, id);
    wstr(&w, Str{bytes, 4});
    sftp_send(s, &w);
}


// Requests

static void sftp_request(Conn *c, Sftp *s, Str req)
{
    Arena scratch = s->scratch;
    Str   home    = c->cfg->home;
    Rd    r       = {req.data, req.len, 0, 0};
    u8    type    = r8(&r);

    if (type == FXP_INIT) {
        Wr w = {s->out+s->outlen+4, 0, SFTP_OUTCAP-s->outlen-4, 0};
        w8(&w, FXP_VERSION);
        w32(&w, 3);
        wcstr(&w, "posix-rename@openssh.com");
        wcstr(&w, "1");
        sftp_send(s, &w);
        return;
    }

    u32 id = r32(&r);
    switch (type) {
    case FXP_OPEN: {
        Str      path  = rstr(&r);
        u32      flags = r32(&r);
        SetAttrs attrs = rattrs(&r);
        if (r.err) break;
        Str p = sftp_resolve(&scratch, home, path);
        if (!p.data) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        i32 i = newhandle(s, HANDLE_FILE, p);
        if (i < 0) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        OsFile f = os_fopen(scratch, p, (i32)flags);
        if (f.err) {
            closehandle(s->handles + i);
            sftp_status(s, id, f.err);
            return;
        }
        s->handles[i].h      = f.h;
        s->handles[i].append = (flags & FS_APPEND) != 0;
        if ((flags & FS_CREAT) && (attrs.flags & ATTR_PERM)) {
            attrs.flags = FS_PERM;
            os_setattrs(scratch, p, f.h, attrs);
        }
        sendhandle(s, id, i);
        return;
    }

    case FXP_CLOSE: {
        SftpHandle *h = gethandle(s, rstr(&r), 0);
        if (r.err) break;
        if (!h) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        closehandle(h);
        sftp_status(s, id, FS_OK);
        return;
    }

    case FXP_READ: {
        SftpHandle *h   = gethandle(s, rstr(&r), HANDLE_FILE);
        i64         off = (i64)r64(&r);
        u32         len = r32(&r);
        if (r.err) break;
        if (!h || off<0) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        len = len<(u32)SFTP_MAXREAD ? len : (u32)SFTP_MAXREAD;
        Wr w = sftp_reply(s, FXP_DATA, id);
        iz lenpos = w.len;
        w32(&w, 0);
        i32 n = os_fread(h->h, off, w.data+w.len, (i32)len);
        if (n <= 0) {
            sftp_status(s, id, n<0 ? -n : FS_EOF);
            return;
        }
        w.len = lenpos;
        w32(&w, (u32)n);
        w.len += n;
        sftp_send(s, &w);
        return;
    }

    case FXP_WRITE: {
        SftpHandle *h    = gethandle(s, rstr(&r), HANDLE_FILE);
        i64         off  = (i64)r64(&r);
        Str         data = rstr(&r);
        if (r.err) break;
        if (!h || off<0) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        i32 st = os_fwrite(h->h, h->append ? -1 : off, data.data, (i32)data.len);
        sftp_status(s, id, st);
        return;
    }

    case FXP_LSTAT:
    case FXP_STAT: {
        Str path = rstr(&r);
        if (r.err) break;
        Str p = sftp_resolve(&scratch, home, path);
        FileInfo fi = p.data ? os_stat(scratch, p) : FileInfo{0,0,0,0,0,FS_NOENT};
        if (fi.err) {
            sftp_status(s, id, fi.err);
            return;
        }
        Wr w = sftp_reply(s, FXP_ATTRS, id);
        wattrs(&w, fi);
        sftp_send(s, &w);
        return;
    }

    case FXP_FSTAT: {
        SftpHandle *h = gethandle(s, rstr(&r), HANDLE_FILE);
        if (r.err) break;
        FileInfo fi = h ? os_fstat(h->h) : FileInfo{0,0,0,0,0,FS_FAIL};
        if (fi.err) {
            sftp_status(s, id, fi.err);
            return;
        }
        Wr w = sftp_reply(s, FXP_ATTRS, id);
        wattrs(&w, fi);
        sftp_send(s, &w);
        return;
    }

    case FXP_SETSTAT: {
        Str      path  = rstr(&r);
        SetAttrs attrs = rattrs(&r);
        if (r.err) break;
        Str p = sftp_resolve(&scratch, home, path);
        attrs.flags &= FS_SIZE | FS_PERM | FS_TIME;
        sftp_status(s, id, p.data ? os_setattrs(scratch, p, 0, attrs) : FS_NOENT);
        return;
    }

    case FXP_FSETSTAT: {
        SftpHandle *h     = gethandle(s, rstr(&r), HANDLE_FILE);
        SetAttrs    attrs = rattrs(&r);
        if (r.err) break;
        if (!h) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        attrs.flags &= FS_SIZE | FS_PERM | FS_TIME;
        Str p = {h->path, h->pathlen};
        sftp_status(s, id, os_setattrs(scratch, p, h->h, attrs));
        return;
    }

    case FXP_OPENDIR: {
        Str path = rstr(&r);
        if (r.err) break;
        Str p = sftp_resolve(&scratch, home, path);
        FileInfo fi = p.data ? os_stat(scratch, p) : FileInfo{0,0,0,0,0,FS_NOENT};
        if (fi.err || !fi.dir) {
            sftp_status(s, id, fi.err ? fi.err : FS_FAIL);
            return;
        }
        i32 i = newhandle(s, HANDLE_DIR, p);
        if (i < 0) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        sendhandle(s, id, i);
        return;
    }

    case FXP_READDIR: {
        SftpHandle *h = gethandle(s, rstr(&r), HANDLE_DIR);
        if (r.err) break;
        if (!h) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        if (h->done) {
            sftp_status(s, id, FS_EOF);
            return;
        }
        Str p     = {h->path, h->pathlen};
        Wr  w     = sftp_reply(s, FXP_NAME, id);
        iz  cpos  = w.len;
        u32 count = 0;
        w32(&w, 0);
        while (w.len < SFTP_BATCH) {
            DirEnt e = os_dirnext(&scratch, p, &h->h);
            if (e.err) {
                h->done = 1;
                if (!count) {
                    sftp_status(s, id, e.err);
                    return;
                }
                break;
            }
            wstr(&w, e.name);
            wstr(&w, longname(&scratch, c->user, e.name, e.info));
            wattrs(&w, e.info);
            count++;
        }
        iz end = w.len;
        w.len = cpos;
        w32(&w, count);
        w.len = end;
        sftp_send(s, &w);
        return;
    }

    case FXP_REMOVE:
    case FXP_RMDIR:
    case FXP_MKDIR: {
        Str path = rstr(&r);
        if (type == FXP_MKDIR) {
            rattrs(&r);
        }
        if (r.err) break;
        Str p = sftp_resolve(&scratch, home, path);
        i32 st = FS_NOENT;
        if (p.data) {
            switch (type) {
            case FXP_REMOVE: st = os_remove(scratch, p); break;
            case FXP_RMDIR:  st = os_rmdir(scratch, p);  break;
            case FXP_MKDIR:  st = os_mkdir(scratch, p);  break;
            }
        }
        sftp_status(s, id, st);
        return;
    }

    case FXP_REALPATH: {
        Str path = rstr(&r);
        if (r.err) break;
        Str p = sftp_resolve(&scratch, home, path);
        if (!p.data) {
            sftp_status(s, id, FS_FAIL);
            return;
        }
        Buf b = Buf(&scratch, p.len+1);
        print(&b, "/");
        print(&b, p);
        Wr w = sftp_reply(s, FXP_NAME, id);
        w32(&w, 1);
        wstr(&w, finish(&b));
        wstr(&w, finish(&b));
        w32(&w, 0);  // no attributes
        sftp_send(s, &w);
        return;
    }

    case FXP_RENAME:
    case FXP_EXTENDED: {
        b32 replace = 0;
        if (type == FXP_EXTENDED) {
            Str name = rstr(&r);
            if (r.err) break;
            if (name != "posix-rename@openssh.com") {
                sftp_status(s, id, FX_OP_UNSUPPORTED);
                return;
            }
            replace = 1;
        }
        Str from = rstr(&r);
        Str to   = rstr(&r);
        if (r.err) break;
        Str a = sftp_resolve(&scratch, home, from);
        Str b = sftp_resolve(&scratch, home, to);
        sftp_status(s, id, a.data && b.data ? os_rename(scratch, a, b, replace)
                                            : FS_NOENT);
        return;
    }

    default:
        if (!r.err) {
            sftp_status(s, id, FX_OP_UNSUPPORTED);
            return;
        }
    }
    sftp_status(s, id, FX_BAD_MESSAGE);
}


// Channel plumbing

static b32 sftp_start(Conn *c)
{
    iz  size = (iz)sizeof(Sftp) + SFTP_INCAP + SFTP_OUTCAP + SFTP_SCRATCH;
    u8 *mem  = os_bigalloc(size);
    if (!mem) {
        return 0;
    }
    Sftp *s = new (mem) Sftp();
    s->in  = mem + sizeof(Sftp);
    s->out = s->in + SFTP_INCAP;
    s->scratch.beg = (byte *)(s->out + SFTP_OUTCAP);
    s->scratch.end = s->scratch.beg + SFTP_SCRATCH;
    c->sftp = s;
    return 1;
}

// Queue channel data. Its window is returned as requests are consumed.
static void sftp_input(Conn *c, Str data)
{
    Sftp *s = c->sftp;
    if (data.len > SFTP_INCAP-s->inlen) {
        c->win_credit += (u32)data.len;  // peer overran its window
        return;
    }
    copybytes(s->in+s->inlen, data.data, data.len);
    s->inlen += data.len;
}

// Answer queued requests while output has room, then forward output
// within the peer's window. Returns true on any progress.
static b32 sftp_pump(Conn *c)
{
    Sftp *s       = c->sftp;
    b32   busy    = 0;
    b32   starved = 0;
    while (SFTP_OUTCAP-s->outlen >= SFTP_RESERVE) {
        iz avail = s->inlen - s->inbeg;
        u8 *p    = s->in + s->inbeg;
        if (avail < 4) {
            starved = 1;
            break;
        }
        u32 n = (u32)p[0]<<24 | (u32)p[1]<<16 | (u32)p[2]<<8 | p[3];
        if (!n || n > SFTP_MAXREQ) {
            os_log("sshd: sftp: bad request length");
            s->inbeg = s->inlen;
            if (!c->sent_exit) finish_channel(c, 1);
            return 1;
        }
        if (n > (u32)(avail-4)) {
            starved = 1;
            break;
        }
        sftp_request(c, s, Str{p+4, (iz)n});
        s->inbeg      += 4 + (iz)n;
        c->win_credit += 4 + n;
        busy = 1;
    }
    if (s->inbeg) {
        __builtin_memmove(s->in, s->in+s->inbeg, (uz)(s->inlen-s->inbeg));
        s->inlen -= s->inbeg;
        s->inbeg  = 0;
    }

    iz off = 0;
    while (off<s->outlen && c->win_remote>0) {
        iz cap = s->outlen - off;
        cap = cap<16384 ? cap : 16384;
        cap = cap<(iz)c->win_remote ? cap : (iz)c->win_remote;
        if (c->pkt_remote && cap>(iz)c->pkt_remote) cap = c->pkt_remote;
        if (!send_channel_data(c, s->out+off, cap, 0)) {
            break;
        }
        c->win_remote -= (u32)cap;
        off  += cap;
        busy  = 1;
    }
    if (off) {
        __builtin_memmove(s->out, s->out+off, (uz)(s->outlen-off));
        s->outlen -= off;
    }

    if (c->got_eof && starved && !s->outlen && !c->sent_exit) {
        finish_channel(c, 0);
    }
    return busy;
}

static void sftp_free(Conn *c)
{
    Sftp *s = c->sftp;
    if (s) {
        for (i32 i = 0; i < SFTP_HANDLES; i++) {
            closehandle(s->handles + i);
        }
        os_bigfree((u8 *)s);
        c->sftp = 0;
    }
}
