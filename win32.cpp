// Win32 platform layer: no CRT, kernel32/ws2_32/advapi32 only.
// This is free and unencumbered software released into the public domain.
//
// Build (32-bit Windows XP):
//   i686-w64-mingw32-g++ -std=c++20 -O2 -nostartfiles -static-libgcc ...
// Build (64-bit):
//   x86_64-w64-mingw32-g++ ...
#include "base.cpp"
#include "crypto.cpp"
#include "ssh.cpp"

enum : i32 {
    CREATE_ALWAYS            = 2,
    CREATE_NO_WINDOW         = 0x08000000,
    CRYPT_VERIFYCONTEXT      = (i32)0xF0000000,
    FILE_ATTRIBUTE_NORMAL    = 0x80,
    FILE_SHARE_READ          = 1,
    FIONBIO                  = (i32)0x8004667e,
    GENERIC_READ             = (i32)0x80000000,
    GENERIC_WRITE            = 0x40000000,
    HANDLE_FLAG_INHERIT      = 1,
    INVALID_FILE_ATTRIBUTES  = -1,
    MEM_COMMIT               = 0x1000,
    MEM_RESERVE              = 0x2000,
    OPEN_EXISTING            = 3,
    PAGE_READWRITE           = 4,
    PROV_RSA_FULL            = 1,
    STARTF_USESTDHANDLES     = 0x100,
    STD_ERROR_HANDLE         = -12,
    WAIT_OBJECT_0            = 0,
    AF_INET                  = 2,
    SOCK_STREAM              = 1,
    IPPROTO_TCP              = 6,
    SOL_SOCKET               = 0xffff,
    SO_REUSEADDR             = 4,
    TCP_NODELAY              = 1,
    WSAEWOULDBLOCK           = 10035,
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

struct StartupInfo {  // STARTUPINFOA
    u32 cb;
    char *lpReserved;
    char *lpDesktop;
    char *lpTitle;
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
W32(uz,     CreateFileA(char *, u32, u32, void *, u32, u32, uz));
W32(b32,    CreatePipe(uz *, uz *, void *, u32));
W32(b32,    CreateProcessA(char *, char *, void *, void *, b32, u32,
                           void *, char *, void *, void *));
W32(uz,     CreateThread(void *, uz, u32 (__stdcall *)(void *), void *, u32, u32 *));
W32(void,   DeleteCriticalSection(void *));
W32(void,   EnterCriticalSection(void *));
W32(void,   ExitProcess[[noreturn]](u32));
W32(b32,    FreeEnvironmentStringsA(char *));
W32(char *, GetCommandLineA());
W32(char *, GetEnvironmentStringsA());
W32(b32,    GetExitCodeProcess(uz, u32 *));
W32(u32,    GetFileAttributesA(char *));
W32(u32,    GetFileSize(uz, u32 *));
W32(u32,    GetLastError());
W32(u32,    GetModuleFileNameA(uz, char *, u32));
W32(uz,     GetStdHandle(i32));
W32(void,   InitializeCriticalSection(void *));
W32(void,   LeaveCriticalSection(void *));
W32(b32,    PeekNamedPipe(uz, void *, u32, u32 *, u32 *, u32 *));
W32(b32,    ReadFile(uz, void *, u32, u32 *, void *));
W32(b32,    SetHandleInformation(uz, u32, u32));
W32(void,   Sleep(u32));
W32(b32,    TerminateProcess(uz, u32));
W32(byte *, VirtualAlloc(uz, uz, u32, u32));
W32(u32,    WaitForSingleObject(uz, u32));
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
W32(b32,    CryptAcquireContextA(uz *, char *, char *, u32, u32));
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
    if (!CryptAcquireContextA(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
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

static b32 pathbuf(char *dst, iz cap, Str path)
{
    if (path.len >= cap) {
        return 0;
    }
    copybytes(dst, path.data, path.len);
    dst[path.len] = 0;
    return 1;
}

static b32 os_readfile(Arena *a, Str path, Str *out)
{
    char pbuf[512];
    if (!pathbuf(pbuf, sizeof(pbuf), path)) {
        return 0;
    }
    uz h = CreateFileA(pbuf, GENERIC_READ, FILE_SHARE_READ, 0,
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
    char pbuf[512];
    if (!pathbuf(pbuf, sizeof(pbuf), path)) {
        return 0;
    }
    uz h = CreateFileA(pbuf, GENERIC_WRITE, 0, 0,
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

static u8 *build_env(Arena *a, Slice<Str> names, Slice<Str> vals)
{
    char *parent = GetEnvironmentStringsA();
    iz total = 0;
    if (parent) {
        char *q = parent;
        while (*q) {
            iz l = 0;
            while (q[l]) l++;
            total += l + 1;
            q += l + 1;
        }
    }
    iz extra = 0;
    for (iz i = 0; i < names.len; i++) {
        extra += names[i].len + 1 + vals[i].len + 1;
    }
    u8 *blk = allocbytes(a, total + extra + 2);
    iz n = 0;
    if (parent) {
        char *q = parent;
        while (*q) {
            iz l = 0;
            while (q[l]) l++;
            Str entry = {(u8 *)q, l};
            iz eq = 0;
            while (eq < entry.len && entry.data[eq] != '=') eq++;
            b32 skip = 0;
            for (iz i = 0; i < names.len; i++) {
                if (iequals(Str{entry.data, eq}, names[i])) {
                    skip = 1;
                    break;
                }
            }
            if (!skip) {
                copybytes(blk+n, entry.data, entry.len);
                n += entry.len;
                blk[n++] = 0;
            }
            q += l + 1;
        }
        FreeEnvironmentStringsA(parent);
    }
    for (iz i = 0; i < names.len; i++) {
        copybytes(blk+n, names[i].data, names[i].len);
        n += names[i].len;
        blk[n++] = '=';
        copybytes(blk+n, vals[i].data, vals[i].len);
        n += vals[i].len;
        blk[n++] = 0;
    }
    blk[n++] = 0;
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
    line[linelen] = 0;

    u8 *env = build_env(a, names, vals);

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
        ok = CreateProcessA(0, (char *)line, 0, 0, 1, CREATE_NO_WINDOW,
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
    char exe[260];
    u32 n = GetModuleFileNameA(0, exe, sizeof(exe));
    if (!n || n >= sizeof(exe)) {
        return shell;
    }
    iz d = n;
    while (d > 0 && exe[d-1] != '\\' && exe[d-1] != '/') {
        d--;
    }
    char buf[512];
    char const *suffix[3] = {"", "bin\\", "..\\bin\\"};
    for (i32 k = 0; k < 3; k++) {
        iz len = 0;
        for (iz i = 0; i < d && len < (iz)sizeof(buf)-1; i++) buf[len++] = exe[i];
        for (char const *q = suffix[k]; *q && len < (iz)sizeof(buf)-1; q++) {
            buf[len++] = *q;
        }
        for (iz i = 0; i < shell.len && len < (iz)sizeof(buf)-1; i++) {
            buf[len++] = (char)shell.data[i];
        }
        buf[len] = 0;
        if (GetFileAttributesA(buf) != (u32)INVALID_FILE_ATTRIBUTES) {
            return clone(a, Str{(u8 *)buf, len});
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

    char *cl = GetCommandLineA();
    Str args[16];
    i32 n = 0;
    char *p = cl;
    while (*p && n < 16) {
        while (*p==' ' || *p=='\t') {
            p++;
        }
        if (!*p) {
            break;
        }
        if (*p == '"') {
            p++;
            char *s = p;
            while (*p && *p != '"') {
                p++;
            }
            args[n++] = {(u8 *)s, (iz)(p-s)};
            if (*p) p++;
        } else {
            char *s = p;
            while (*p && *p!=' ' && *p!='\t') {
                p++;
            }
            args[n++] = {(u8 *)s, (iz)(p-s)};
        }
    }

    for (i32 i = 1; i < n; i++) {
        Str t = args[i];
        if (t == "-p" && i+1 < n) {
            config.port = parse_int(args[++i], 22);
        } else if (t == "-k" && i+1 < n) {
            config.keysfile = clone(a, args[++i]);
        } else if (t == "-s" && i+1 < n) {
            config.shell = clone(a, args[++i]);
        } else if (t == "-H" && i+1 < n) {
            config.hostkeyfile = clone(a, args[++i]);
        } else if (t == "-selftest") {
            selftest_flag = 1;
        } else if (t == "-h" || t == "-?" || t == "--help") {
            usage();
            ExitProcess(0);
        }
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
