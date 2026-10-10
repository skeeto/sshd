// Win32 platform layer: no CRT, kernel32/ws2_32/advapi32/shell32 only.
// Win32 calls use the W APIs; strings are UTF-8 and converted at the boundary.
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
    CP_UTF8                    = 65001,
    CREATE_ALWAYS              = 2,
    CREATE_NO_WINDOW           = 0x08000000,
    CREATE_SUSPENDED           = 0x00000004,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CRYPT_VERIFYCONTEXT        = (i32)0xF0000000,
    FILE_ATTRIBUTE_NORMAL      = 0x80,
    FILE_SHARE_READ            = 1,
    FIONBIO                    = (i32)0x8004667e,
    GENERIC_READ               = (i32)0x80000000,
    GENERIC_WRITE              = 0x40000000,
    HANDLE_FLAG_INHERIT        = 1,
    INVALID_FILE_ATTRIBUTES    = -1,
    INFINITE                   = -1,
    MEM_COMMIT                 = 0x1000,
    MEM_RELEASE                = 0x8000,
    MEM_RESERVE                = 0x2000,
    OPEN_EXISTING              = 3,
    PAGE_READWRITE             = 4,
    PROV_RSA_FULL              = 1,
    STARTF_USESTDHANDLES       = 0x100,
    STD_ERROR_HANDLE           = -12,
    STD_INPUT_HANDLE           = -10,
    WAIT_OBJECT_0              = 0,
    AF_INET                    = 2,
    SOCK_STREAM                = 1,
    IPPROTO_TCP                = 6,
    SOL_SOCKET                 = 0xffff,
    SO_KEEPALIVE               = 8,
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
W32(b32,    AssignProcessToJobObject(uz, uz));
W32(b32,    CloseHandle(uz));
W32(u16 **, CommandLineToArgvW(u16 const *, i32 *));
W32(uz,     CreateFileW(u16 const *, u32, u32, void *, u32, u32, uz));
W32(b32,    CreatePipe(uz *, uz *, void *, u32));
W32(b32,    CreateProcessW(u16 const *, u16 *, void *, void *, b32, u32,
                           void *, u16 const *, void *, void *));
W32(uz,     CreateEventW(void *, b32, b32, u16 const *));
W32(uz,     CreateJobObjectW(void *, u16 const *));
W32(uz,     CreateThread(void *, uz, u32 (__stdcall *)(void *), void *, u32, u32 *));
W32(void,   DeleteCriticalSection(void *));
W32(void,   EnterCriticalSection(void *));
W32(void,   ExitProcess[[noreturn]](u32));
W32(b32,    FreeEnvironmentStringsW(u16 *));
W32(u16 *,  GetCommandLineW());
W32(u32,    GetEnvironmentVariableW(u16 const *, u16 *, u32));
W32(u16 *,  GetEnvironmentStringsW());
W32(b32,    GetExitCodeProcess(uz, u32 *));
W32(u32,    GetFileAttributesW(u16 const *));
W32(u32,    GetFileSize(uz, u32 *));
W32(u32,    GetLastError());
W32(u32,    GetModuleFileNameW(uz, u16 *, u32));
W32(b32,    GetConsoleMode(uz, u32 *));
W32(uz,     GetStdHandle(i32));
W32(void,   InitializeCriticalSection(void *));
W32(void,   LeaveCriticalSection(void *));
W32(uz,     LocalFree(uz));
W32(b32,    PeekNamedPipe(uz, void *, u32, u32 *, u32 *, u32 *));
W32(b32,    ReadFile(uz, void *, u32, u32 *, void *));
W32(u32,    ResumeThread(uz));
W32(b32,    SetConsoleMode(uz, u32));
W32(b32,    SetEvent(uz));
W32(b32,    SetHandleInformation(uz, u32, u32));
W32(void,   Sleep(u32));
W32(b32,    TerminateJobObject(uz, u32));
W32(b32,    TerminateProcess(uz, u32));
W32(byte *, VirtualAlloc(uz, uz, u32, u32));
W32(b32,    VirtualFree(void *, uz, u32));
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

// Decode UTF-8 to UTF-16, or only count units when dst is null. Each
// invalid byte becomes U+FFFD, which MultiByteToWideChar does not do on
// XP. Returns 0 if the result does not fit in cap.
static iz utf8_to_wide(u16 *dst, iz cap, Str s)
{
    static u32 const min[] = {0, 0x80, 0x800, 0x10000};
    iz n = 0;
    for (iz i = 0; i < s.len;) {
        u32 cp  = 0xfffd;
        iz  len = 1;
        u8  b   = s.data[i];
        if (b < 0x80) {
            cp = b;
        } else if (b>=0xc0 && b<0xf5) {
            i32 need = b>=0xf0 ? 3 : b>=0xe0 ? 2 : 1;
            u32 v    = b & (0x3fu >> need);
            iz  j    = 1;
            for (; j<=need && i+j<s.len && (s.data[i+j]&0xc0)==0x80; j++) {
                v = v<<6 | (s.data[i+j] & 0x3f);
            }
            if (j>need && v>=min[need] && v<=0x10ffff && (v<0xd800 || v>0xdfff)) {
                cp  = v;
                len = j;
            }
        }
        i += len;

        if (cp >= 0x10000) {
            if (dst && n+2<=cap) {
                dst[n+0] = (u16)(0xd7c0 + (cp >> 10));
                dst[n+1] = (u16)(0xdc00 | (cp & 0x3ff));
            }
            n += 2;
        } else {
            if (dst && n<cap) {
                dst[n] = (u16)cp;
            }
            n += 1;
        }
    }
    return dst && n>cap ? 0 : n;
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
static i32             job_warned;
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
            tv.sec  = IO_TIMEOUT_MS / 1000;
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

// Child stdin is fed from a ring buffer by a dedicated writer thread so
// the connection thread never blocks on a full pipe, which would deadlock
// against a child blocked writing its own full stdout. The SSH layer only
// returns window for drained bytes, so the ring never holds more than
// CHAN_WINDOW. The queue is shared by reference count because the writer
// may stay blocked in WriteFile after the connection ends (e.g. an orphaned
// grandchild holding the pipe open), and XP has no CancelSynchronousIo.
struct StdinQueue {
    CriticalSection lock;
    uz  event;    // auto-reset: data, eof, or stop
    uz  pipe;     // write end, owned by the writer thread
    u8 *buf;
    u32 head;     // total bytes queued
    u32 tail;     // total bytes written or discarded
    u32 drained;  // bytes written or discarded since last proc_drained()
    b32 eof;      // close the pipe once drained
    b32 dead;     // stop writing, discard everything
    i32 refs;
};

enum : u32 { STDINQ_CAP = CHAN_WINDOW };  // power of two
static_assert(!(STDINQ_CAP & (STDINQ_CAP-1)), "");

static void stdinq_release(StdinQueue *q)
{
    if (!__atomic_sub_fetch(&q->refs, 1, __ATOMIC_ACQ_REL)) {
        CloseHandle(q->event);
        DeleteCriticalSection(&q->lock);
        VirtualFree(q, 0, MEM_RELEASE);
    }
}

static u32 __stdcall stdinq_writer(void *arg)
{
    StdinQueue *q = (StdinQueue *)arg;
    for (;;) {
        EnterCriticalSection(&q->lock);
        u32 len  = q->head - q->tail;
        u32 off  = q->tail & (STDINQ_CAP - 1);
        b32 done = q->dead || (!len && q->eof);
        LeaveCriticalSection(&q->lock);
        if (done) {
            break;
        }
        if (!len) {
            WaitForSingleObject(q->event, (u32)INFINITE);
            continue;
        }

        len = len < STDINQ_CAP-off ? len : STDINQ_CAP-off;
        u32 wrote = 0;
        b32 ok = WriteFile(q->pipe, q->buf+off, len, &wrote, 0) && wrote;

        EnterCriticalSection(&q->lock);
        if (!ok) {
            q->dead = 1;  // child stopped reading
            wrote = q->head - q->tail;
        }
        q->tail    += wrote;
        q->drained += wrote;
        LeaveCriticalSection(&q->lock);
    }
    CloseHandle(q->pipe);
    stdinq_release(q);
    return 0;
}

static StdinQueue *stdinq_start(uz pipe)
{
    byte *mem = VirtualAlloc(0, sizeof(StdinQueue) + STDINQ_CAP,
                             MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        return 0;
    }
    StdinQueue *q = new (mem) StdinQueue();
    q->buf   = (u8 *)mem + sizeof(StdinQueue);
    q->pipe  = pipe;
    q->refs  = 2;
    q->event = CreateEventW(0, 0, 0, 0);
    InitializeCriticalSection(&q->lock);
    u32 tid = 0;
    uz  th  = q->event ? CreateThread(0, 0, stdinq_writer, q, 0, &tid) : 0;
    if (!th) {
        if (q->event) CloseHandle(q->event);
        DeleteCriticalSection(&q->lock);
        VirtualFree(mem, 0, MEM_RELEASE);
        return 0;
    }
    CloseHandle(th);
    return q;
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
    u16 *cwd   = config.home.len ? utf8_to_wide_alloc(a, config.home) : 0;

    SecurityAttributes sa = {sizeof(sa), 0, 1};
    uz in_r = 0, in_w = 0, out_r = 0, out_w = 0, err_r = 0, err_w = 0;

    EnterCriticalSection(&spawn_lock);
    b32 ok = CreatePipe(&in_r, &in_w, &sa, 0) &&
             CreatePipe(&out_r, &out_w, &sa, 1<<16) &&
             CreatePipe(&err_r, &err_w, &sa, 1<<16);
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
        // Start suspended so the child joins the job before it can
        // spawn anything of its own.
        ok = CreateProcessW(0, wline, 0, 0, 1,
                            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
                            CREATE_SUSPENDED,
                            env, cwd, &si, &pi);
        StdinQueue *q = ok ? stdinq_start(in_w) : 0;
        if (ok && !q) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            ok = 0;
        }
        if (ok) {
            // Fails if sshd itself runs in a job; then only the shell can
            // be killed, as before.
            uz job = CreateJobObjectW(0, 0);
            if (job && !AssignProcessToJobObject(job, pi.hProcess)) {
                CloseHandle(job);
                job = 0;
            }
            if (!job && !__atomic_exchange_n(&job_warned, 1, __ATOMIC_RELAXED)) {
                os_log("sshd: cannot use job objects, process trees will linger");
            }
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            p->hjob    = job;
            p->hproc   = pi.hProcess;
            p->stdinq  = q;
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
    StdinQueue *q = p->stdinq;
    if (!q) {
        return 0;
    }
    b32 ok = 1;
    EnterCriticalSection(&q->lock);
    if (q->dead || q->eof || (u32)len > STDINQ_CAP - (q->head - q->tail)) {
        ok = 0;  // discarded: caller returns the window itself
    } else {
        u32 off   = q->head & (STDINQ_CAP - 1);
        u32 first = (u32)len < STDINQ_CAP-off ? (u32)len : STDINQ_CAP-off;
        copybytes(q->buf+off, buf, first);
        copybytes(q->buf, buf+first, len-first);
        q->head += (u32)len;
    }
    LeaveCriticalSection(&q->lock);
    SetEvent(q->event);
    return ok;
}

static u32 proc_drained(Proc *p)
{
    StdinQueue *q = p->stdinq;
    if (!q) {
        return 0;
    }
    EnterCriticalSection(&q->lock);
    u32 n = q->drained;
    q->drained = 0;
    LeaveCriticalSection(&q->lock);
    return n;
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
    StdinQueue *q = p->stdinq;
    if (q) {
        EnterCriticalSection(&q->lock);
        q->eof = 1;
        LeaveCriticalSection(&q->lock);
        SetEvent(q->event);
    }
}

// Terminate the child and everything it started.
static void proc_kill(Proc *p)
{
    if (p->hjob) {
        TerminateJobObject(p->hjob, 1);
    } else if (p->hproc) {
        TerminateProcess(p->hproc, 1);
    }
    StdinQueue *q = p->stdinq;
    if (q) {
        EnterCriticalSection(&q->lock);
        q->dead = 1;
        LeaveCriticalSection(&q->lock);
        SetEvent(q->event);
    }
}

// Release the session's handles without killing anything, so background
// jobs outlive a shell that exited normally.
static void proc_close(Proc *p)
{
    StdinQueue *q = p->stdinq;
    if (q) {
        EnterCriticalSection(&q->lock);
        q->dead = 1;
        LeaveCriticalSection(&q->lock);
        SetEvent(q->event);
        stdinq_release(q);
        p->stdinq = 0;
    }
    if (p->hjob)    CloseHandle(p->hjob);
    if (p->hproc)   CloseHandle(p->hproc);
    if (p->hstdout) CloseHandle(p->hstdout);
    if (p->hstderr) CloseHandle(p->hstderr);
    *p = {};
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
        if (proc_alive(&c->proc)) {
            proc_kill(&c->proc);  // client went away mid-command
        }
        proc_close(&c->proc);
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
    SetHandleInformation(s, HANDLE_FLAG_INHERIT, 0);
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

    // A QuickEdit selection in the console blocks writes to it, which
    // would stall every thread at os_log while holding log_lock.
    {
        enum { QUICK_EDIT = 0x40, EXTENDED_FLAGS = 0x80 };
        uz  in   = GetStdHandle(STD_INPUT_HANDLE);
        u32 mode = 0;
        if (GetConsoleMode(in, &mode)) {
            SetConsoleMode(in, (mode & ~(u32)QUICK_EDIT) | EXTENDED_FLAGS);
        }
    }

    u8 wsa[512];
    WSAStartup(0x0202, wsa);

    ed25519_init();
    load_hostkey(&a);
    config.shell = resolve_shell(&a, config.shell);
    {
        u16 home[260];
        u32 n = GetEnvironmentVariableW((u16 const *)u"USERPROFILE", home,
                                        (u32)countof(home));
        if (n && n < countof(home)) {
            config.home = wide_to_utf8(&a, home, n);
        }
    }

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
        // Sockets are inheritable by default, and children would otherwise
        // inherit every connection's socket, including the listener.
        SetHandleInformation(s, HANDLE_FLAG_INHERIT, 0);
        i32 one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char const *)&one, sizeof(one));
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char const *)&one, sizeof(one));
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
