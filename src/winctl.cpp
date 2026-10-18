// winctl: capture and drive GUI windows from the command line
// $ cc -nostartfiles -o winctl.exe winctl.cpp -lgdi32
//
// A companion to sshd for testing GUI programs over SSH: list windows,
// capture them as PNG on standard output, wait for them, and send them
// mouse and keyboard input. Runs on Windows XP and later, imports only
// kernel32, user32, gdi32 and shell32, and looks up newer functions (DPI
// awareness, DWM frame bounds) at run time. See winctl.md.
//
// This is free and unencumbered software released into the public domain.

using u8   = unsigned char;
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

#define assert(c)   while (!(c)) __builtin_unreachable()
#define countof(a)  (iz)(sizeof(a) / sizeof(*(a)))

template<typename T>
void *operator new(uz, T *p) noexcept { return p; }

enum : i32 {
    STATUS_OK      = 0,
    STATUS_FAIL    = 1,  // bad usage, or an operation failed
    STATUS_NOMATCH = 2,  // no window matches, or more than one
    STATUS_TIMEOUT = 3,  // wait ran out of time
};

struct Arena {
    byte *beg = {};
    byte *end = {};
};

[[noreturn]] static void oom();

template<typename T>
static T *alloc(Arena *a, iz count = 1)
{
    iz size = sizeof(T);
    iz pad  = -(uz)a->beg & (alignof(T) - 1);
    if (count < 0 || count >= (a->end - a->beg - pad)/size) {
        oom();
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
        oom();
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

static Str cuthead(Str s, iz n)
{
    assert(n >= 0 && n <= s.len);
    s.data += n;
    s.len  -= n;
    return s;
}

static Str takehead(Str s, iz n)
{
    assert(n >= 0 && n <= s.len);
    s.len = n;
    return s;
}

static b32 startswith(Str s, Str prefix)
{
    return s.len>=prefix.len && takehead(s, prefix.len)==prefix;
}

struct Cut {
    Str head;
    Str tail;
    b32 ok;
};

static Cut cut(Str s, u8 c)
{
    Cut r = {};
    iz i = 0;
    for (; i<s.len && s[i]!=c; i++) {}
    r.ok   = i < s.len;
    r.head = takehead(s, i);
    r.tail = cuthead(s, i + r.ok);
    return r;
}

static u8 lower(u8 c)
{
    return c>='A' && c<='Z' ? (u8)(c + 32) : c;
}

// ASCII case-insensitive equality.
static b32 iequals(Str a, Str b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (iz i = 0; i < a.len; i++) {
        if (lower(a[i]) != lower(b[i])) {
            return 0;
        }
    }
    return 1;
}

// ASCII case-insensitive substring search.
static b32 icontains(Str s, Str pat)
{
    for (iz i = 0; i+pat.len <= s.len; i++) {
        if (iequals(Str{s.data+i, pat.len}, pat)) {
            return 1;
        }
    }
    return 0;
}

struct Int {
    i64 value;
    b32 ok;
};

// Parse a decimal integer, optionally negative, or 0x-prefixed hex.
static Int parseint(Str s)
{
    Int r   = {};
    b32 neg = s.len && s[0]=='-';
    s = cuthead(s, neg);
    if (!s.len || s.len>16) {
        return r;
    }
    if (s.len>2 && s[0]=='0' && lower(s[1])=='x') {
        for (iz i = 2; i < s.len; i++) {
            u8 c = lower(s[i]);
            i32 v = c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1;
            if (v < 0) {
                return r;
            }
            r.value = r.value<<4 | v;
        }
    } else {
        for (iz i = 0; i < s.len; i++) {
            if (s[i]<'0' || s[i]>'9') {
                return r;
            }
            r.value = r.value*10 + s[i] - '0';
        }
    }
    r.value = neg ? -r.value : r.value;
    r.ok    = 1;
    return r;
}

// Parse non-negative seconds with an optional fraction into milliseconds.
static Int parsetime(Str s)
{
    Int r = {};
    Cut c = cut(s, '.');
    Int whole = parseint(c.head);
    if (!whole.ok || whole.value<0 || whole.value>1000000) {
        return r;
    }
    i64 ms    = whole.value * 1000;
    i64 scale = 100;
    for (iz i = 0; i < c.tail.len; i++, scale /= 10) {
        u8 d = c.tail[i];
        if (d<'0' || d>'9') {
            return r;
        }
        ms += (d - '0') * scale;
    }
    r.value = ms;
    r.ok    = 1;
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
        iz extend = s.cap ? s.cap : 16;
        alloc<T>(a, extend);
        s.cap += extend;
    }
    s.data[s.len++] = v;
    return s;
}


// Win32

enum : i32 {
    CP_UTF8                   = 65001,
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
    CREATE_NEW_CONSOLE        = 0x00000010,
    CREATE_UNICODE_ENVIRONMENT= 0x00000400,
    ERROR_ACCESS_DENIED       = 5,
    FILE_ATTRIBUTE_DIRECTORY  = 0x10,
    FILE_ATTRIBUTE_REPARSE    = 0x400,
    MEM_COMMIT                = 0x1000,
    MEM_RELEASE               = 0x8000,
    MEM_RESERVE               = 0x2000,
    PAGE_READWRITE            = 4,
    PROCESS_QUERY_INFORMATION = 0x0400,
    STD_ERROR_HANDLE          = -12,
    STD_INPUT_HANDLE          = -10,
    STD_OUTPUT_HANDLE         = -11,
    SYNCHRONIZE               = 0x00100000,
    WAIT_TIMEOUT              = 258,

    CAPTUREBLT                = 0x40000000,
    SRCCOPY                   = 0x00CC0020,

    GA_ROOTOWNER              = 3,
    GW_OWNER                  = 4,
    INPUT_MOUSE               = 0,
    INPUT_KEYBOARD            = 1,
    KEYEVENTF_EXTENDEDKEY     = 0x0001,
    KEYEVENTF_KEYUP           = 0x0002,
    KEYEVENTF_UNICODE         = 0x0004,
    MOUSEEVENTF_MOVE          = 0x0001,
    MOUSEEVENTF_LEFTDOWN      = 0x0002,
    MOUSEEVENTF_LEFTUP        = 0x0004,
    MOUSEEVENTF_RIGHTDOWN     = 0x0008,
    MOUSEEVENTF_RIGHTUP       = 0x0010,
    MOUSEEVENTF_WHEEL         = 0x0800,
    MOUSEEVENTF_VIRTUALDESK   = 0x4000,
    MOUSEEVENTF_ABSOLUTE      = 0x8000,
    SM_CXDRAG                 = 68,
    SM_CYDRAG                 = 69,
    SM_XVIRTUALSCREEN         = 76,
    SM_YVIRTUALSCREEN         = 77,
    SM_CXVIRTUALSCREEN        = 78,
    SM_CYVIRTUALSCREEN        = 79,
    SW_RESTORE                = 9,
    SWP_NOSIZE                = 0x0001,
    SWP_NOZORDER              = 0x0004,
    SWP_NOACTIVATE            = 0x0010,
    WM_CLOSE                  = 0x0010,
    WM_COMMAND                = 0x0111,
    VK_TAB                    = 0x09,
    VK_RETURN                 = 0x0D,

    DWMWA_EXTENDED_FRAME_BOUNDS = 9,
    DWMWA_CLOAKED               = 14,
};

enum : uz {
    INVALID_HANDLE_VALUE = (uz)-1,
};

struct Rect {
    i32 left, top, right, bottom;
};

struct Point {
    i32 x, y;
};

struct Msg {  // MSG, only for PeekMessageW
    uz hwnd;
    u32 message;
    uz wparam;
    iz lparam;
    u32 time;
    Point pt;
    u32 priv;
};

struct Input {  // INPUT
    u32 type;
    union {
        struct {
            i32 dx, dy;
            u32 data, flags, time;
            uz  extra;
        } mi;
        struct {
            u16 vk, scan;
            u32 flags, time;
            uz  extra;
        } ki;
    };
};
static_assert(sizeof(Input) == (sizeof(uz)==4 ? 28 : 40), "");

struct BitmapInfo {  // BITMAPINFO with BITMAPINFOHEADER
    u32 size;
    i32 width, height;
    u16 planes, bitcount;
    u32 compression, sizeimage;
    i32 xppm, yppm;
    u32 clrused, clrimportant;
    u32 colors[1];
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

struct FileTime {
    u32 lo, hi;
};

struct FindData {  // WIN32_FIND_DATAW
    u32      attrs;
    FileTime ctime, atime, mtime;
    u32      sizehi, sizelo;
    u32      reserved0, reserved1;
    u16      name[260];
    u16      altname[14];
};

#define W32(r, p) extern "C" __declspec(dllimport) r __stdcall p noexcept
W32(b32,    CloseHandle(uz));
W32(b32,    CreateProcessW(u16 const *, u16 *, void *, void *, b32, u32,
                           void *, u16 const *, StartupInfo *, ProcessInfo *));
W32(void,   ExitProcess[[noreturn]](u32));
W32(b32,    FindClose(uz));
W32(uz,     FindFirstFileW(u16 const *, FindData *));
W32(b32,    FindNextFileW(uz, FindData *));
W32(u16 *,  GetCommandLineW());
W32(b32,    GetConsoleMode(uz, u32 *));
W32(u32,    GetCurrentThreadId());
W32(u32,    GetLastError());
W32(uz,     GetModuleHandleW(u16 const *));
W32(void *, GetProcAddress(uz, char const *));
W32(uz,     GetStdHandle(i32));
W32(u32,    GetTickCount());
W32(uz,     LoadLibraryW(u16 const *));
W32(uz,     LocalFree(uz));
W32(i32,    MultiByteToWideChar(u32, u32, char const *, i32, u16 *, i32));
W32(uz,     OpenProcess(u32, b32, u32));
W32(b32,    ReadFile(uz, void *, u32, u32 *, void *));
W32(void,   Sleep(u32));
W32(byte *, VirtualAlloc(uz, uz, u32, u32));
W32(b32,    VirtualFree(void *, uz, u32));
W32(i32,    WideCharToMultiByte(u32, u32, u16 const *, i32, char *, i32,
                                char const *, b32 *));
W32(b32,    WriteFile(uz, void const *, u32, u32 *, void *));
W32(u16 **, CommandLineToArgvW(u16 const *, i32 *));
W32(b32,    AttachThreadInput(u32, u32, b32));
W32(b32,    BringWindowToTop(uz));
W32(b32,    EnumWindows(i32 (__stdcall *)(uz, iz), iz));
W32(uz,     GetAncestor(uz, u32));
W32(i32,    GetClassNameW(uz, u16 *, i32));
W32(b32,    GetCursorPos(Point *));
W32(uz,     GetDC(uz));
W32(uz,     GetForegroundWindow());
W32(i32,    GetSystemMetrics(i32));
W32(uz,     GetWindow(uz, u32));
W32(b32,    GetWindowRect(uz, Rect *));
W32(i32,    GetWindowTextW(uz, u16 *, i32));
W32(u32,    GetWindowThreadProcessId(uz, u32 *));
W32(b32,    IsIconic(uz));
W32(b32,    IsWindow(uz));
W32(b32,    IsWindowVisible(uz));
W32(u32,    MapVirtualKeyW(u32, u32));
W32(b32,    PeekMessageW(Msg *, uz, u32, u32, u32));
W32(b32,    PostMessageW(uz, u32, uz, iz));
W32(i32,    ReleaseDC(uz, uz));
W32(u32,    SendInput(u32, Input *, i32));
W32(b32,    SetCursorPos(i32, i32));
W32(b32,    SetForegroundWindow(uz));
W32(b32,    SetWindowPos(uz, uz, i32, i32, i32, i32, u32));
W32(b32,    ShowWindow(uz, i32));
W32(i16,    VkKeyScanW(u16));
W32(u32,    WaitForInputIdle(uz, u32));
W32(b32,    BitBlt(uz, i32, i32, i32, i32, uz, i32, i32, u32));
W32(uz,     CreateCompatibleDC(uz));
W32(uz,     CreateDIBSection(uz, BitmapInfo *, u32, void **, uz, u32));
W32(b32,    DeleteDC(uz));
W32(b32,    DeleteObject(uz));
W32(b32,    GdiFlush());
W32(uz,     SelectObject(uz, uz));

// GCC emits calls to these even without a CRT. Defining them keeps
// msvcrt.dll out of the imports of a -nostartfiles build.
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
#endif

// Functions missing from older systems, looked up at run time.
static i32 (__stdcall *dwmgetwindowattribute)(uz, u32, void *, u32);

static void initdpi()
{
    uz user32 = GetModuleHandleW((u16 const *)u"user32.dll");
    void *ctx = GetProcAddress(user32, "SetProcessDpiAwarenessContext");
    if (ctx) {
        b32 (__stdcall *set)(iz) = (b32 (__stdcall *)(iz))ctx;
        if (set(-4) || set(-3)) {  // per-monitor v2, else v1
            return;
        }
    }
    void *old = GetProcAddress(user32, "SetProcessDPIAware");  // Vista
    if (old) {
        ((b32 (__stdcall *)())old)();
    }
}

static void initdwm()
{
    uz dwm = LoadLibraryW((u16 const *)u"dwmapi.dll");  // Vista
    if (dwm) {
        void *f = GetProcAddress(dwm, "DwmGetWindowAttribute");
        dwmgetwindowattribute = (i32 (__stdcall *)(uz, u32, void *, u32))f;
    }
}


// Output

struct Output {
    u8 *buf;
    iz  len;
    iz  cap;
    uz  handle;
    b32 err;
};

static Output *newoutput(Arena *a, i32 std, iz cap = 1<<12)
{
    Output *o = alloc<Output>(a);
    o->buf    = allocbytes(a, cap);
    o->cap    = cap;
    o->handle = GetStdHandle(std);
    return o;
}

static b32 writeall(uz h, u8 *data, iz len)
{
    while (len > 0) {
        u32 n   = len>(1<<20) ? (1<<20) : (u32)len;
        u32 got = 0;
        if (!WriteFile(h, data, n, &got, 0) || !got) {
            return 0;
        }
        data += got;
        len  -= got;
    }
    return 1;
}

static void flush(Output *o)
{
    if (!o->err && o->len) {
        o->err = !writeall(o->handle, o->buf, o->len);
    }
    o->len = 0;
}

static void print(Output *o, Str s)
{
    for (iz off = 0; !o->err && off < s.len;) {
        if (o->len == o->cap) {
            flush(o);
        }
        iz avail = o->cap - o->len;
        iz count = avail<s.len-off ? avail : s.len-off;
        copybytes(o->buf+o->len, s.data+off, count);
        off    += count;
        o->len += count;
    }
}

static void print(Output *o, i64 v)
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
    print(o, span(beg, end));
}

static void printhex(Output *o, u64 v, i32 digits)
{
    u8 tmp[18];
    tmp[0] = '0';
    tmp[1] = 'x';
    for (i32 i = 0; i < digits; i++) {
        tmp[2+digits-1-i] = (u8)"0123456789abcdef"[v>>(4*i) & 15];
    }
    print(o, Str{tmp, 2+digits});
}


// Context

struct Ctx {
    Arena   perm;
    Output *out;
    Output *err;
};

static Output *errout;  // for oom

[[noreturn]] static void quit(Ctx *c, i32 status)
{
    flush(c->out);
    flush(c->err);
    ExitProcess(c->out->err && !status ? (u32)STATUS_FAIL : (u32)status);
}

[[noreturn]] static void fail(Ctx *c, i32 status, Str msg, Str detail = {})
{
    print(c->err, "winctl: ");
    print(c->err, msg);
    if (detail.data) {
        print(c->err, " '");
        print(c->err, detail);
        print(c->err, "'");
    }
    print(c->err, "\n");
    quit(c, status);
}

[[noreturn]] static void oom()
{
    if (errout) {
        errout->len = 0;
        print(errout, "winctl: out of memory\n");
        flush(errout);
    }
    ExitProcess(STATUS_FAIL);
}

static Str fromwide(Arena *a, u16 const *s, iz len)
{
    if (!len) {
        return {allocbytes(a, 0), 0};
    }
    i32 n = WideCharToMultiByte(CP_UTF8, 0, s, (i32)len, 0, 0, 0, 0);
    u8 *buf = allocbytes(a, n);
    WideCharToMultiByte(CP_UTF8, 0, s, (i32)len, (char *)buf, n, 0, 0);
    return {buf, (iz)n};
}

struct Wide {
    u16 *data;
    iz   len;  // excluding the terminator
};

static Wide towide(Arena *a, Str s)
{
    Wide r = {};
    i32  n = 0;
    if (s.len) {
        n = MultiByteToWideChar(CP_UTF8, 0, s.cdata, (i32)s.len, 0, 0);
    }
    r.data = alloc<u16>(a, n+1);
    if (n) {
        MultiByteToWideChar(CP_UTF8, 0, s.cdata, (i32)s.len, r.data, n);
    }
    r.len = n;
    return r;
}

static iz wstrlen(u16 const *s)
{
    iz n = 0;
    for (; s[n]; n++) {}
    return n;
}


// Windows

struct Win {
    uz   hwnd;  // zero for the whole screen
    u32  pid;
    u32  tid;
    Rect rect;  // on screen, in physical pixels, as captured by shot
    Str  title;
    Str  cls;
};

// The visible frame. On Vista and later GetWindowRect includes invisible
// resize borders, so prefer the DWM frame bounds when available.
static Rect winrect(uz hwnd)
{
    Rect r = {};
    if (dwmgetwindowattribute && !IsIconic(hwnd) &&
        !dwmgetwindowattribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, &r, sizeof(r))) {
        return r;
    }
    GetWindowRect(hwnd, &r);
    return r;
}

// Visible and not cloaked: Windows 8 and later keep many invisible
// "visible" windows around, such as suspended store apps.
static b32 onscreen(uz hwnd)
{
    if (!IsWindowVisible(hwnd)) {
        return 0;
    }
    u32 cloaked = 0;
    if (dwmgetwindowattribute) {
        dwmgetwindowattribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked));
    }
    return !cloaked;
}

static Win describe(Arena *a, uz hwnd)
{
    Win r  = {};
    u16 buf[256];
    r.hwnd  = hwnd;
    r.tid   = GetWindowThreadProcessId(hwnd, &r.pid);
    r.rect  = winrect(hwnd);
    r.title = fromwide(a, buf, GetWindowTextW(hwnd, buf, countof(buf)));
    r.cls   = fromwide(a, buf, GetClassNameW(hwnd, buf, countof(buf)));
    return r;
}

static Win screenwin()
{
    Win r = {};
    r.rect.left   = GetSystemMetrics(SM_XVIRTUALSCREEN);
    r.rect.top    = GetSystemMetrics(SM_YVIRTUALSCREEN);
    r.rect.right  = r.rect.left + GetSystemMetrics(SM_CXVIRTUALSCREEN);
    r.rect.bottom = r.rect.top  + GetSystemMetrics(SM_CYVIRTUALSCREEN);
    r.title = "screen";
    return r;
}

struct Enum {
    Arena    *a;
    Slice<uz> hwnds;
};

static i32 __stdcall enumproc(uz hwnd, iz arg)
{
    Enum *e = (Enum *)arg;
    e->hwnds = push(e->a, e->hwnds, hwnd);
    return 1;
}

// Top-level windows, top of the z-order first.
static Slice<Win> windows(Arena *a, b32 all)
{
    Enum e = {};
    e.a = a;
    EnumWindows(enumproc, (iz)&e);
    Slice<Win> r = {};
    for (iz i = 0; i < e.hwnds.len; i++) {
        uz h = e.hwnds[i];
        if (all || onscreen(h)) {
            r = push(a, r, describe(a, h));
        }
    }
    return r;
}

struct Sel {
    Str title;  // substring, ASCII case-insensitive
    Str cls;    // exact, ASCII case-insensitive
    u32 pid;
    uz  hwnd;
    b32 screen;
    b32 active;
};

// A window is "screen", "active", a list of key=value criteria joined
// by commas (title=, class=, pid=, hwnd=), or else a title substring.
static Sel parsesel(Str s)
{
    Sel r = {};
    if (s == "screen") {
        r.screen = 1;
        return r;
    } else if (s == "active") {
        r.active = 1;
        return r;
    }

    Sel t  = {};
    b32 ok = s.len > 0;
    for (Str rest = s; ok && rest.len;) {
        Cut c = cut(rest, ',');
        rest = c.tail;
        Str p = c.head;
        if (startswith(p, "title=")) {
            t.title = cuthead(p, 6);
        } else if (startswith(p, "class=")) {
            t.cls = cuthead(p, 6);
        } else if (startswith(p, "pid=")) {
            Int v = parseint(cuthead(p, 4));
            ok    = v.ok && v.value>0 && v.value<=0xffffffff;
            t.pid = (u32)v.value;
        } else if (startswith(p, "hwnd=")) {
            Int v  = parseint(cuthead(p, 5));
            ok     = v.ok && v.value>0;
            t.hwnd = (uz)v.value;
        } else {
            ok = 0;
        }
    }
    if (ok) {
        return t;
    }
    r.title = s;
    return r;
}

static b32 matches(Sel *s, Win *w)
{
    return (!s->hwnd       || s->hwnd==w->hwnd) &&
           (!s->pid        || s->pid==w->pid) &&
           (!s->cls.data   || iequals(s->cls, w->cls)) &&
           (!s->title.data || icontains(w->title, s->title));
}

// Popup menus, their shadows, and tooltips are top-level windows of the
// same process, which would make most selectors ambiguous while a menu
// is open. They still appear in shots, which copy the screen.
static b32 ispopup(Win *w)
{
    return w->cls=="#32768" || w->cls=="SysShadow" ||
           w->cls=="tooltips_class32";
}

static Slice<Win> findall(Arena *a, Sel *s)
{
    Slice<Win> all = windows(a, s->hwnd != 0);
    Slice<Win> r   = {};
    for (iz i = 0; i < all.len; i++) {
        b32 skip = !s->cls.data && !s->hwnd && ispopup(&all[i]);
        if (!skip && matches(s, &all[i])) {
            r = push(a, r, all[i]);
        }
    }
    return r;
}

static void printwin(Output *o, Win *w)
{
    printhex(o, w->hwnd, 8);
    print(o, "\t");
    print(o, (i64)w->pid);
    print(o, "\t");
    print(o, (i64)w->rect.left);
    print(o, ",");
    print(o, (i64)w->rect.top);
    print(o, "\t");
    print(o, (i64)(w->rect.right - w->rect.left));
    print(o, "x");
    print(o, (i64)(w->rect.bottom - w->rect.top));
    print(o, "\t");
    print(o, w->cls);
    print(o, "\t");
    print(o, w->title);
    print(o, "\n");
}

// Exactly one window, or exit with STATUS_NOMATCH.
static Win findone(Ctx *c, Str spec)
{
    Sel s = parsesel(spec);
    if (s.screen) {
        return screenwin();
    } else if (s.active) {
        uz h = GetForegroundWindow();
        if (!h) {
            fail(c, STATUS_NOMATCH, "no active window");
        }
        return describe(&c->perm, h);
    }

    Slice<Win> m = findall(&c->perm, &s);
    if (!m.len) {
        fail(c, STATUS_NOMATCH, "no window matches", spec);
    } else if (m.len > 1) {
        print(c->err, "winctl: ");
        print(c->err, (i64)m.len);
        print(c->err, " windows match '");
        print(c->err, spec);
        print(c->err, "', narrow it down (e.g. hwnd=):\n");
        for (iz i = 0; i < m.len; i++) {
            printwin(c->err, &m[i]);
        }
        quit(c, STATUS_NOMATCH);
    }
    return m[0];
}


// Foreground and input

// Input goes to the foreground window, or to one of its owned popups
// (dialogs) when the target itself is disabled under them.
static b32 isforeground(uz hwnd)
{
    for (uz h = GetForegroundWindow(); h; h = GetWindow(h, GW_OWNER)) {
        if (h == hwnd) {
            return 1;
        }
    }
    return 0;
}

static b32 sendinput(Input *in, iz n)
{
    return (iz)SendInput((u32)n, in, sizeof(Input)) == n;
}

// SetForegroundWindow is refused to background processes, which is what
// a command run over SSH is. Attaching to the input queue of the current
// foreground thread lifts the restriction.
static b32 activate(Win *w)
{
    if (!w->hwnd) {
        return 1;  // the screen
    }
    if (IsIconic(w->hwnd)) {
        ShowWindow(w->hwnd, SW_RESTORE);
    }
    if (isforeground(w->hwnd)) {
        return 1;
    }

    Msg msg;
    PeekMessageW(&msg, 0, 0, 0, 0);  // AttachThreadInput needs a queue

    for (i32 attempt = 0; attempt < 2; attempt++) {
        if (attempt) {
            // A synthesized input event makes this process the source
            // of the last input, which also permits a foreground change.
            Input in = {};
            in.type     = INPUT_MOUSE;
            in.mi.flags = MOUSEEVENTF_MOVE;
            sendinput(&in, 1);
        }
        u32 self = GetCurrentThreadId();
        uz  fg   = GetForegroundWindow();
        u32 fgt  = fg ? GetWindowThreadProcessId(fg, 0) : 0;
        b32 a1   = fgt && fgt!=self && AttachThreadInput(self, fgt, 1);
        b32 a2   = w->tid!=self && w->tid!=fgt &&
                   AttachThreadInput(self, w->tid, 1);
        BringWindowToTop(w->hwnd);
        SetForegroundWindow(w->hwnd);
        if (a2) AttachThreadInput(self, w->tid, 0);
        if (a1) AttachThreadInput(self, fgt, 0);

        for (i32 i = 0; i < 25; i++) {
            if (isforeground(w->hwnd)) {
                Sleep(50);  // let it repaint before input or capture
                return 1;
            }
            Sleep(20);
        }
    }
    return 0;
}

static void mustactivate(Ctx *c, Win *w)
{
    if (!activate(w)) {
        fail(c, STATUS_FAIL, "cannot bring window to the foreground", w->title);
    }
    if (w->hwnd) {
        w->rect = winrect(w->hwnd);  // it may have been minimized
    }
}

static void mustsend(Ctx *c, Input *in, iz n)
{
    if (!sendinput(in, n)) {
        // Blocked by UIPI (elevated target), or a locked/secure desktop.
        fail(c, STATUS_FAIL, "SendInput failed (elevated window or locked desktop?)");
    }
}

// Move the cursor to a screen position in physical pixels.
static void moveto(Ctx *c, i32 x, i32 y)
{
    i64 vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    i64 vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    i64 vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    i64 vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    vw = vw>1 ? vw : 2;
    vh = vh>1 ? vh : 2;
    Input in = {};
    in.type     = INPUT_MOUSE;
    in.mi.dx    = (i32)(((x - vx)*65535 + (vw-1)/2) / (vw - 1));
    in.mi.dy    = (i32)(((y - vy)*65535 + (vh-1)/2) / (vh - 1));
    in.mi.flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                  MOUSEEVENTF_VIRTUALDESK;
    mustsend(c, &in, 1);
    Point p = {};
    if (GetCursorPos(&p) && (p.x!=x || p.y!=y)) {
        SetCursorPos(x, y);  // correct rounding in the normalized coordinates
    }
}

static void button(Ctx *c, u32 flags, u32 data = 0)
{
    Input in = {};
    in.type     = INPUT_MOUSE;
    in.mi.flags = flags;
    in.mi.data  = data;
    mustsend(c, &in, 1);
}

static b32 isextended(u32 vk)
{
    return (vk>=0x21 && vk<=0x28) ||  // page up/down, end, home, arrows
           vk==0x2D || vk==0x2E   ||  // insert, delete
           vk==0x5B || vk==0x5C   ||  // windows keys
           vk==0x5D || vk==0x6F   ||  // apps, numpad divide
           vk==0x90 || vk==0x2C;      // num lock, print screen
}

static Input keyinput(u32 vk, b32 up)
{
    Input in = {};
    in.type     = INPUT_KEYBOARD;
    in.ki.vk    = (u16)vk;
    in.ki.scan  = (u16)MapVirtualKeyW(vk, 0);
    in.ki.flags = (up ? KEYEVENTF_KEYUP : 0) |
                  (isextended(vk) ? KEYEVENTF_EXTENDEDKEY : 0);
    return in;
}

struct Chord {
    u32 vk[8];  // modifiers, then the key
    i32 len;
    b32 ok;
};

static Chord parsechord(Str s)
{
    static struct { Str name; u32 vk; } const names[] = {
        {"ctrl",  0x11}, {"control", 0x11}, {"alt",    0x12},
        {"shift", 0x10}, {"win",     0x5B},
        {"enter", 0x0D}, {"return",  0x0D}, {"tab",    0x09},
        {"esc",   0x1B}, {"escape",  0x1B}, {"space",  0x20},
        {"backspace", 0x08}, {"bs",  0x08},
        {"del",   0x2E}, {"delete",  0x2E}, {"ins",    0x2D},
        {"insert",0x2D}, {"home",    0x24}, {"end",    0x23},
        {"pgup",  0x21}, {"pageup",  0x21}, {"pgdn",   0x22},
        {"pagedown", 0x22},
        {"left",  0x25}, {"up",      0x26}, {"right",  0x27},
        {"down",  0x28}, {"apps",    0x5D}, {"menu",   0x5D},
        {"pause", 0x13}, {"prtsc",   0x2C}, {"plus",   0xBB},
        {"minus", 0xBD}, {"comma",   0xBC},
    };

    Chord r = {};
    for (Str rest = s; rest.len;) {
        Cut c = cut(rest, '+');
        rest  = c.tail;
        Str k = c.head;
        if (r.len==countof(r.vk) || !k.len) {
            return r;
        }

        u32 vk = 0;
        for (iz i = 0; !vk && i < countof(names); i++) {
            if (iequals(k, names[i].name)) {
                vk = names[i].vk;
            }
        }
        if (!vk && k.len>=2 && k.len<=3 && lower(k[0])=='f') {
            Int n = parseint(cuthead(k, 1));
            if (n.ok && n.value>=1 && n.value<=24) {
                vk = 0x70 + (u32)n.value - 1;
            }
        }
        if (!vk && k.len==1) {
            u8 ch = k[0];
            if (ch>='a' && ch<='z') {
                vk = ch - 'a' + 'A';
            } else if ((ch>='A' && ch<='Z') || (ch>='0' && ch<='9')) {
                vk = ch;
            } else if (ch>' ' && ch<0x7f) {
                i32 v = VkKeyScanW(ch);
                if (v == -1) {
                    return r;
                }
                vk = v & 0xff;
                if (v & 0x100) r.vk[r.len++] = 0x10;  // shift
                if (r.len == countof(r.vk)) return r;
            }
        }
        if (!vk) {
            return r;
        }
        r.vk[r.len++] = vk;
    }
    r.ok = r.len > 0;
    return r;
}

static void sendchord(Ctx *c, Chord *k)
{
    Input in[2*countof(k->vk)];
    iz n = 0;
    for (i32 i = 0; i < k->len; i++) {
        in[n++] = keyinput(k->vk[i], 0);
    }
    for (i32 i = k->len-1; i >= 0; i--) {
        in[n++] = keyinput(k->vk[i], 1);
    }
    mustsend(c, in, n);
}

// Type UTF-16 text as Unicode key events. Newlines and tabs are sent as
// the Enter and Tab keys, which edit controls handle more reliably.
static void typetext(Ctx *c, Wide w)
{
    Input in[64];
    iz n = 0;
    for (iz i = 0; i < w.len; i++) {
        u16 u = w.data[i];
        if (u == '\r') {
            if (i+1<w.len && w.data[i+1]=='\n') {
                continue;
            }
            u = '\n';
        }
        if (u=='\n' || u=='\t') {
            u32 vk = u=='\n' ? VK_RETURN : VK_TAB;
            in[n++] = keyinput(vk, 0);
            in[n++] = keyinput(vk, 1);
        } else {
            Input k = {};
            k.type     = INPUT_KEYBOARD;
            k.ki.scan  = u;
            k.ki.flags = KEYEVENTF_UNICODE;
            in[n++] = k;
            k.ki.flags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            in[n++] = k;
        }
        if (n > countof(in)-2) {
            mustsend(c, in, n);
            n = 0;
            Sleep(1);
        }
    }
    if (n) {
        mustsend(c, in, n);
    }
}


// PNG encoder: Sub/Up row filters, LZ77 deflate with fixed Huffman codes
// or stored blocks, whichever is smaller.

static u32 crc32(u32 crc, u8 *p, iz len)
{
    static u32 table[256];
    if (!table[1]) {
        for (u32 i = 0; i < 256; i++) {
            u32 c = i;
            for (i32 k = 0; k < 8; k++) {
                c = c&1 ? 0xedb88320 ^ (c>>1) : c>>1;
            }
            table[i] = c;
        }
    }
    crc = ~crc;
    for (iz i = 0; i < len; i++) {
        crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
    }
    return ~crc;
}

static u32 adler32(u8 *p, iz len)
{
    u32 a = 1, b = 0;
    while (len > 0) {
        iz n = len<5552 ? len : 5552;  // no overflow before the modulo
        for (iz i = 0; i < n; i++) {
            a += p[i];
            b += a;
        }
        a %= 65521;
        b %= 65521;
        p   += n;
        len -= n;
    }
    return b<<16 | a;
}

struct Bits {
    u8 *buf;
    iz  len;
    iz  cap;
    u64 acc;
    i32 nbits;
};

static void putbits(Bits *b, u32 v, i32 n)
{
    b->acc   |= (u64)v << b->nbits;
    b->nbits += n;
    while (b->nbits >= 8) {
        assert(b->len < b->cap);
        b->buf[b->len++] = (u8)b->acc;
        b->acc  >>= 8;
        b->nbits -= 8;
    }
}

static void flushbits(Bits *b)
{
    if (b->nbits) {
        putbits(b, 0, 8 - b->nbits);
    }
}

// Huffman codes are packed most significant bit first.
static void putcode(Bits *b, u32 code, i32 n)
{
    u32 r = 0;
    for (i32 i = 0; i < n; i++) {
        r = r<<1 | (code>>i & 1);
    }
    putbits(b, r, n);
}

static void putsym(Bits *b, i32 sym)
{
    if (sym < 144) {
        putcode(b, 0x30 + sym, 8);
    } else if (sym < 256) {
        putcode(b, 0x190 + sym - 144, 9);
    } else if (sym < 280) {
        putcode(b, sym - 256, 7);
    } else {
        putcode(b, 0xc0 + sym - 280, 8);
    }
}

static u16 const lenbase[] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static u8 const lenextra[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static u16 const distbase[] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
    513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
static u8 const distextra[] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7,
    8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

static void putmatch(Bits *b, i32 len, i32 dist)
{
    i32 l = countof(lenbase) - 1;
    for (; lenbase[l] > len; l--) {}
    putsym(b, 257 + l);
    putbits(b, (u32)(len - lenbase[l]), lenextra[l]);
    i32 d = countof(distbase) - 1;
    for (; distbase[d] > dist; d--) {}
    putcode(b, (u32)d, 5);
    putbits(b, (u32)(dist - distbase[d]), distextra[d]);
}

// Deflate into a single fixed-Huffman block. The output buffer must hold
// at least len*9/8 + 16 bytes, the worst case of all literals.
static iz deflatefixed(Arena scratch, u8 *out, iz cap, u8 *p, iz len)
{
    enum {
        WINBITS  = 15,
        WINSIZE  = 1 << WINBITS,
        HASHBITS = 15,
        MAXCHAIN = 16,
        MINMATCH = 3,
        MAXMATCH = 258,
    };
    i32 *head = alloc<i32>(&scratch, 1<<HASHBITS);  // position+1, 0 empty
    i32 *prev = alloc<i32>(&scratch, WINSIZE);

    Bits b = {};
    b.buf = out;
    b.cap = cap;
    putbits(&b, 1, 1);  // final block
    putbits(&b, 1, 2);  // fixed Huffman codes

    for (iz i = 0; i < len;) {
        i32 best = 0;
        i32 dist = 0;
        u32 h    = 0;
        if (len-i >= MINMATCH) {
            u32 key = (u32)p[i]<<16 | (u32)p[i+1]<<8 | p[i+2];
            h = key*0x9e3779b1u >> (32 - HASHBITS);
            iz maxlen = len-i<MAXMATCH ? len-i : (iz)MAXMATCH;
            iz cand   = head[h] - 1;
            for (i32 n = 0; cand>=0 && i-cand<=WINSIZE && n<MAXCHAIN; n++) {
                iz k = 0;
                for (; k<maxlen && p[cand+k]==p[i+k]; k++) {}
                if (k > best) {
                    best = (i32)k;
                    dist = (i32)(i - cand);
                    if (k == maxlen) {
                        break;
                    }
                }
                iz next = prev[cand & (WINSIZE-1)] - 1;
                if (next >= cand) {
                    break;  // overwritten slot
                }
                cand = next;
            }
            prev[i & (WINSIZE-1)] = head[h];
            head[h] = (i32)(i + 1);
        }

        if (best >= MINMATCH) {
            putmatch(&b, best, dist);
            for (iz j = i+1; j<i+best && len-j>=MINMATCH; j++) {
                u32 key = (u32)p[j]<<16 | (u32)p[j+1]<<8 | p[j+2];
                u32 hj  = key*0x9e3779b1u >> (32 - HASHBITS);
                prev[j & (WINSIZE-1)] = head[hj];
                head[hj] = (i32)(j + 1);
            }
            i += best;
        } else {
            putsym(&b, p[i]);
            i++;
        }
    }
    putsym(&b, 256);
    flushbits(&b);
    return b.len;
}

static iz storedsize(iz len)
{
    iz blocks = len ? (len + 65534)/65535 : 1;
    return len + 5*blocks;
}

static iz deflatestored(u8 *out, u8 *p, iz len)
{
    iz n = 0;
    iz i = 0;
    do {
        iz  chunk = len-i<65535 ? len-i : 65535;
        u32 c     = (u32)chunk;
        out[n++]  = i+chunk == len;  // final block flag, BTYPE 00
        out[n++]  = (u8)(c >> 0);
        out[n++]  = (u8)(c >> 8);
        out[n++]  = (u8)(~c >> 0);
        out[n++]  = (u8)(~c >> 8);
        copybytes(out+n, p+i, chunk);
        n += chunk;
        i += chunk;
    } while (i < len);
    return n;
}

static void put32be(u8 *p, u32 v)
{
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >>  8);
    p[3] = (u8)(v >>  0);
}

static i32 filtercost(u8 *row, iz len)
{
    i32 sum = 0;
    for (iz i = 0; i < len; i++) {
        i32 v = (i32)(signed char)row[i];
        sum += v<0 ? -v : v;
    }
    return sum;
}

// Encode 32-bit BGRX top-down pixels as a 24-bit RGB PNG.
static Str encodepng(Arena *a, u8 *bgrx, i32 w, i32 h)
{
    iz stride = (iz)w * 3;
    iz rawlen = (stride + 1) * h;
    u8 *raw   = allocbytes(a, rawlen);
    u8 *prior = alloc<u8>(a, stride);  // the row above, zero for the first
    u8 *cur   = allocbytes(a, stride);
    u8 *sub   = allocbytes(a, stride);
    u8 *up    = allocbytes(a, stride);

    for (i32 y = 0; y < h; y++) {
        u8 *src = bgrx + (iz)y*w*4;
        for (i32 x = 0; x < w; x++) {
            cur[x*3+0] = src[x*4+2];
            cur[x*3+1] = src[x*4+1];
            cur[x*3+2] = src[x*4+0];
        }
        for (iz i = 0; i < stride; i++) {
            sub[i] = (u8)(cur[i] - (i>=3 ? cur[i-3] : 0));
            up[i]  = (u8)(cur[i] - prior[i]);
        }
        i32 cnone = filtercost(cur, stride);
        i32 csub  = filtercost(sub, stride);
        i32 cup   = filtercost(up,  stride);
        u8 *dst   = raw + y*(stride + 1);
        if (csub<=cup && csub<cnone) {
            dst[0] = 1;
            copybytes(dst+1, sub, stride);
        } else if (cup < cnone) {
            dst[0] = 2;
            copybytes(dst+1, up, stride);
        } else {
            dst[0] = 0;
            copybytes(dst+1, cur, stride);
        }
        u8 *t = prior;
        prior = cur;
        cur   = t;
    }

    static u8 const sig[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    iz cap = 8 + 25 + 8 + 2 + rawlen + rawlen/8 + 64 + 4 + 4 + 12;
    u8 *png = allocbytes(a, cap);
    iz  n   = 0;

    copybytes(png, sig, 8);
    n += 8;
    put32be(png+n, 13);
    copybytes(png+n+4, "IHDR", 4);
    put32be(png+n+8,  (u32)w);
    put32be(png+n+12, (u32)h);
    png[n+16] = 8;  // bit depth
    png[n+17] = 2;  // truecolor
    png[n+18] = 0;  // deflate
    png[n+19] = 0;  // adaptive filtering
    png[n+20] = 0;  // no interlace
    put32be(png+n+21, crc32(0, png+n+4, 17));
    n += 25;

    iz idat = n;
    copybytes(png+n+4, "IDAT", 4);
    n += 8;
    png[n++] = 0x78;  // zlib: deflate, 32K window
    png[n++] = 0x01;
    iz z = deflatefixed(*a, png+n, cap-n, raw, rawlen);
    if (z >= storedsize(rawlen)) {
        z = deflatestored(png+n, raw, rawlen);
    }
    n += z;
    put32be(png+n, adler32(raw, rawlen));
    n += 4;
    put32be(png+idat, (u32)(n - idat - 8));
    put32be(png+n, crc32(0, png+idat+4, n-idat-4));
    n += 4;

    put32be(png+n, 0);
    copybytes(png+n+4, "IEND", 4);
    put32be(png+n+8, crc32(0, png+n+4, 4));
    n += 12;
    return {png, n};
}


// Commands

struct Args {
    Str  *v;   // UTF-8
    u16 **w;   // original UTF-16, for run
    i32   n;
    i32   i;   // next unconsumed
};

static b32 more(Args *a)
{
    return a->i < a->n;
}

static Str next(Ctx *c, Args *a, Str what)
{
    if (!more(a)) {
        fail(c, STATUS_FAIL, "missing argument:", what);
    }
    return a->v[a->i++];
}

static i32 nextint(Ctx *c, Args *a, Str what)
{
    Str s = next(c, a, what);
    Int v = parseint(s);
    if (!v.ok || v.value<-0x7fffffff || v.value>0x7fffffff) {
        fail(c, STATUS_FAIL, "invalid number", s);
    }
    return (i32)v.value;
}

static void done(Ctx *c, Args *a)
{
    if (more(a)) {
        fail(c, STATUS_FAIL, "unexpected argument", a->v[a->i]);
    }
}

static void cmdlist(Ctx *c, Args *a)
{
    b32 all = 0;
    if (more(a) && a->v[a->i]=="-a") {
        all = 1;
        a->i++;
    }
    Sel s = {};
    if (more(a)) {
        s = parsesel(next(c, a, "window"));
    }
    done(c, a);
    Slice<Win> ws = windows(&c->perm, all || s.hwnd);
    for (iz i = 0; i < ws.len; i++) {
        if (matches(&s, &ws[i])) {
            printwin(c->out, &ws[i]);
        }
    }
}

static void cmdshot(Ctx *c, Args *a)
{
    Win w = findone(c, more(a) ? next(c, a, "window") : Str("screen"));
    Rect r = w.rect;
    if (more(a)) {
        // An optional sub-rectangle in window coordinates
        i32 x  = nextint(c, a, "x");
        i32 y  = nextint(c, a, "y");
        i32 cw = nextint(c, a, "width");
        i32 ch = nextint(c, a, "height");
        r.left  += x;
        r.top   += y;
        r.right  = r.left + cw;
        r.bottom = r.top  + ch;
    }
    done(c, a);

    // Clip to the virtual screen, outside of which there is nothing.
    Rect v = screenwin().rect;
    r.left   = r.left   > v.left   ? r.left   : v.left;
    r.top    = r.top    > v.top    ? r.top    : v.top;
    r.right  = r.right  < v.right  ? r.right  : v.right;
    r.bottom = r.bottom < v.bottom ? r.bottom : v.bottom;
    i32 width  = r.right - r.left;
    i32 height = r.bottom - r.top;
    if (width<=0 || height<=0) {
        fail(c, STATUS_FAIL, "window is off screen or empty", w.title);
    }

    u32 mode = 0;
    if (GetConsoleMode(c->out->handle, &mode)) {
        fail(c, STATUS_FAIL, "refusing to write PNG to a console, redirect it");
    }

    // Copy the screen, not the window, so popups over it are included.
    uz sdc = GetDC(0);
    uz mdc = CreateCompatibleDC(sdc);
    BitmapInfo bi = {};
    bi.size     = 40;
    bi.width    = width;
    bi.height   = -height;  // top-down
    bi.planes   = 1;
    bi.bitcount = 32;
    void *bits  = 0;
    uz bmp = CreateDIBSection(sdc, &bi, 0, &bits, 0, 0);
    if (!bmp) {
        fail(c, STATUS_FAIL, "cannot create a bitmap");
    }
    uz old = SelectObject(mdc, bmp);
    b32 ok = BitBlt(mdc, 0, 0, width, height, sdc, r.left, r.top,
                    SRCCOPY | CAPTUREBLT);
    GdiFlush();
    if (!ok) {
        fail(c, STATUS_FAIL, "screen capture failed (locked desktop?)");
    }

    iz need = ((iz)width*3 + 1)*height*9/4 + ((iz)width*12) + (1<<20);
    byte *mem = VirtualAlloc(0, (uz)need, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        oom();
    }
    Arena big = {mem, mem+need};
    Str png = encodepng(&big, (u8 *)bits, width, height);

    SelectObject(mdc, old);
    DeleteObject(bmp);
    DeleteDC(mdc);
    ReleaseDC(0, sdc);

    flush(c->out);
    if (!writeall(c->out->handle, png.data, png.len)) {
        c->out->err = 1;
    }
}

static void cmdwait(Ctx *c, Args *a)
{
    enum { EXISTS, GONE, CHANGE, IDLE } mode = EXISTS;
    i64 timeout = 10000;
    while (more(a) && a->v[a->i].len && a->v[a->i][0]=='-') {
        Str o = next(c, a, "option");
        if (o == "-gone") {
            mode = GONE;
        } else if (o == "-change") {
            mode = CHANGE;
        } else if (o == "-idle") {
            mode = IDLE;
        } else if (o == "-t") {
            Str t = next(c, a, "seconds");
            Int v = parsetime(t);
            if (!v.ok) {
                fail(c, STATUS_FAIL, "invalid timeout", t);
            }
            timeout = v.value;
        } else {
            fail(c, STATUS_FAIL, "unknown option", o);
        }
    }
    Str spec = next(c, a, "window");
    done(c, a);
    Sel s = parsesel(spec);
    if (s.screen || s.active) {
        fail(c, STATUS_FAIL, "cannot wait on", spec);
    }
    u32 start = GetTickCount();

    if (mode == IDLE) {
        u32 pid = s.pid;
        if (!pid || s.title.data || s.cls.data || s.hwnd) {
            pid = findone(c, spec).pid;
        }
        uz h = OpenProcess(SYNCHRONIZE|PROCESS_QUERY_INFORMATION, 0, pid);
        if (!h) {
            fail(c, STATUS_FAIL, "cannot open process", spec);
        }
        i64 left = timeout - (i64)(GetTickCount() - start);
        u32 r = WaitForInputIdle(h, left>0 ? (u32)left : 0);
        CloseHandle(h);
        if (r == WAIT_TIMEOUT) {
            fail(c, STATUS_TIMEOUT, "timed out waiting for idle", spec);
        } else if (r) {
            fail(c, STATUS_FAIL, "cannot wait for idle (not a GUI process?)", spec);
        }
        return;
    }

    Win orig = {};
    if (mode == CHANGE) {
        orig = findone(c, spec);
    }
    for (;;) {
        Arena scratch = c->perm;
        if (mode == CHANGE) {
            if (!IsWindow(orig.hwnd)) {
                fail(c, STATUS_NOMATCH, "window closed while waiting", spec);
            }
            Win now = describe(&scratch, orig.hwnd);
            if (!(now.title == orig.title)) {
                printwin(c->out, &now);
                return;
            }
        } else {
            Slice<Win> m = findall(&scratch, &s);
            if (mode==EXISTS && m.len) {
                for (iz i = 0; i < m.len; i++) {
                    printwin(c->out, &m[i]);
                }
                return;
            } else if (mode==GONE && !m.len) {
                return;
            }
        }
        if ((i64)(GetTickCount() - start) >= timeout) {
            fail(c, STATUS_TIMEOUT, "timed out waiting for", spec);
        }
        Sleep(50);
    }
}

// A point in window coordinates.
static Point readpoint(Ctx *c, Args *a)
{
    Point p = {};
    p.x = nextint(c, a, "x");
    p.y = nextint(c, a, "y");
    return p;
}

static Point toscreen(Win *w, Point p)
{
    p.x += w->rect.left;
    p.y += w->rect.top;
    return p;
}

static void cmdclick(Ctx *c, Args *a, i32 kind)
{
    Win   w = findone(c, next(c, a, "window"));
    Point p = readpoint(c, a);
    done(c, a);
    mustactivate(c, &w);
    p = toscreen(&w, p);
    moveto(c, p.x, p.y);
    Sleep(30);
    u32 down = kind=='r' ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_LEFTDOWN;
    u32 up   = kind=='r' ? MOUSEEVENTF_RIGHTUP   : MOUSEEVENTF_LEFTUP;
    button(c, down);
    Sleep(20);
    button(c, up);
    if (kind == 'd') {
        Sleep(50);
        button(c, down);
        Sleep(20);
        button(c, up);
    }
    Sleep(50);
}

static void cmddrag(Ctx *c, Args *a)
{
    Win   w  = findone(c, next(c, a, "window"));
    Point p0 = readpoint(c, a);
    Point p1 = readpoint(c, a);
    done(c, a);
    mustactivate(c, &w);
    p0 = toscreen(&w, p0);
    p1 = toscreen(&w, p1);

    i32 dx = p1.x - p0.x;
    i32 dy = p1.y - p0.y;
    i32 d  = (dx<0 ? -dx : dx) > (dy<0 ? -dy : dy) ? (dx<0 ? -dx : dx)
                                                   : (dy<0 ? -dy : dy);
    moveto(c, p0.x, p0.y);
    Sleep(100);
    button(c, MOUSEEVENTF_LEFTDOWN);
    Sleep(100);

    // Single pixels, slowly, until past the drag threshold, so that drag
    // detection (DragDetect, OLE DoDragDrop) sees a deliberate drag.
    i32 thr = GetSystemMetrics(SM_CXDRAG);
    i32 thy = GetSystemMetrics(SM_CYDRAG);
    thr = (thr>thy ? thr : thy) * 2 + 2;
    i32 k = 1;
    for (; k<=d && k<=thr; k++) {
        moveto(c, p0.x + (i32)((i64)dx*k/d), p0.y + (i32)((i64)dy*k/d));
        Sleep(20);
    }
    // Then the rest in steps with short pauses.
    i32 steps = 20;
    for (i32 s = 1; k<=d && s <= steps; s++) {
        i32 j = k + (i32)((i64)(d - k)*s/steps);
        moveto(c, p0.x + (i32)((i64)dx*j/d), p0.y + (i32)((i64)dy*j/d));
        Sleep(25);
    }
    moveto(c, p1.x, p1.y);
    Sleep(150);  // let the drop target see the hover
    moveto(c, p1.x, p1.y);
    Sleep(100);
    button(c, MOUSEEVENTF_LEFTUP);
    Sleep(100);
}

static void cmdwheel(Ctx *c, Args *a)
{
    Win   w = findone(c, next(c, a, "window"));
    Point p = readpoint(c, a);
    i32   n = nextint(c, a, "clicks");
    done(c, a);
    mustactivate(c, &w);
    p = toscreen(&w, p);
    moveto(c, p.x, p.y);
    Sleep(30);
    button(c, MOUSEEVENTF_WHEEL, (u32)(n * 120));
    Sleep(50);
}

static void cmdkey(Ctx *c, Args *a)
{
    Win w = findone(c, next(c, a, "window"));
    if (!more(a)) {
        fail(c, STATUS_FAIL, "missing argument:", "key");
    }
    Slice<Chord> chords = {};
    while (more(a)) {
        Str   s = next(c, a, "key");
        Chord k = parsechord(s);
        if (!k.ok) {
            fail(c, STATUS_FAIL, "unknown key", s);
        }
        chords = push(&c->perm, chords, k);
    }
    mustactivate(c, &w);
    for (iz i = 0; i < chords.len; i++) {
        if (i) Sleep(50);
        sendchord(c, &chords[i]);
    }
    Sleep(50);
}

static Str readstdin(Arena *a)
{
    uz  h = GetStdHandle(STD_INPUT_HANDLE);
    Str r = {};
    r.data = allocbytes(a, 0);
    for (;;) {
        iz cap = 1<<16;
        allocbytes(a, cap);  // extends r in place
        u32 got = 0;
        if (!ReadFile(h, r.data+r.len, (u32)cap, &got, 0) || !got) {
            break;
        }
        r.len += got;
        a->beg = (byte *)(r.data + r.len);
    }
    a->beg = (byte *)(r.data + r.len);
    return r;
}

static void cmdtype(Ctx *c, Args *a)
{
    Win w = findone(c, next(c, a, "window"));
    Str text = next(c, a, "text");
    done(c, a);
    if (text == "-") {
        text = readstdin(&c->perm);
    }
    Wide wide = towide(&c->perm, text);
    mustactivate(c, &w);
    typetext(c, wide);
    Sleep(50);
}

static void cmdpost(Ctx *c, Args *a, u32 msg)
{
    Win w  = findone(c, next(c, a, "window"));
    i32 id = msg==WM_COMMAND ? nextint(c, a, "id") : 0;
    done(c, a);
    if (!w.hwnd || !PostMessageW(w.hwnd, msg, (uz)(u32)id, 0)) {
        fail(c, STATUS_FAIL, "cannot post message to", w.title);
    }
}

static void cmdraise(Ctx *c, Args *a)
{
    Win w = findone(c, next(c, a, "window"));
    done(c, a);
    mustactivate(c, &w);
}

static void cmdmove(Ctx *c, Args *a)
{
    Win w = findone(c, next(c, a, "window"));
    i32 x = nextint(c, a, "x");
    i32 y = nextint(c, a, "y");
    b32 size = more(a);
    i32 cw = size ? nextint(c, a, "width")  : 0;
    i32 ch = size ? nextint(c, a, "height") : 0;
    done(c, a);
    if (!w.hwnd) {
        fail(c, STATUS_FAIL, "cannot move the screen");
    }
    // Arguments are in the visible-frame terms of list and shot, so add
    // back any invisible borders.
    Rect o = {};
    GetWindowRect(w.hwnd, &o);
    Rect f = w.rect;
    x  -= f.left - o.left;
    y  -= f.top  - o.top;
    cw += (o.right - o.left) - (f.right - f.left);
    ch += (o.bottom - o.top) - (f.bottom - f.top);
    u32 flags = SWP_NOZORDER | SWP_NOACTIVATE | (size ? 0 : SWP_NOSIZE);
    if (!SetWindowPos(w.hwnd, 0, x, y, cw, ch, flags)) {
        fail(c, STATUS_FAIL, "cannot move window", w.title);
    }
}

// Append one argument to a command line, quoted the way CommandLineToArgvW
// and the MSVC runtime parse it.
static void appendarg(Slice<u16> *line, Arena *a, u16 *arg)
{
    if (line->len) {
        *line = push(a, *line, (u16)' ');
    }
    b32 plain = arg[0] != 0;
    for (u16 *p = arg; *p; p++) {
        plain &= *p!=' ' && *p!='\t' && *p!='"';
    }
    if (plain) {
        for (u16 *p = arg; *p; p++) {
            *line = push(a, *line, *p);
        }
        return;
    }
    *line = push(a, *line, (u16)'"');
    iz slashes = 0;
    for (u16 *p = arg;; p++) {
        if (*p == '\\') {
            slashes++;
            continue;
        }
        iz n = *p=='"' ? 2*slashes+1 : !*p ? 2*slashes : slashes;
        for (iz i = 0; i < n; i++) {
            *line = push(a, *line, (u16)'\\');
        }
        slashes = 0;
        if (!*p) {
            break;
        }
        *line = push(a, *line, *p);
    }
    *line = push(a, *line, (u16)'"');
}

static void cmdrun(Ctx *c, Args *a)
{
    if (!more(a)) {
        fail(c, STATUS_FAIL, "missing argument:", "program");
    }
    Slice<u16> line = {};
    for (; more(a); a->i++) {
        appendarg(&line, &c->perm, a->w[a->i]);
    }
    line = push(&c->perm, line, (u16)0);

    // No inherited handles, so the SSH session's pipes close when this
    // command exits, and break away from sshd's job, so the program
    // outlives the session.
    StartupInfo si = {};
    si.cb = sizeof(si);
    ProcessInfo pi = {};
    u32 flags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
    b32 ok = CreateProcessW(0, line.data, 0, 0, 0,
                            flags | CREATE_BREAKAWAY_FROM_JOB,
                            0, 0, &si, &pi);
    if (!ok && GetLastError()==ERROR_ACCESS_DENIED) {
        ok = CreateProcessW(0, line.data, 0, 0, 0, flags, 0, 0, &si, &pi);
        if (ok) {
            print(c->err, "winctl: warning: cannot leave the job, "
                          "the program may end with the session\n");
        }
    }
    if (!ok) {
        fail(c, STATUS_FAIL, "cannot start", a->v[2]);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    print(c->out, (i64)pi.dwProcessId);
    print(c->out, "\n");
}

// Recursive listing with wide APIs, as UTF-8 paths relative to the root.
// Directories end in a slash. Junctions are listed but not followed.
static void lsdir(Ctx *c, Arena scratch, Slice<u16> dir, Str rel)
{
    Slice<u16> pat = dir;
    pat.cap = pat.len;  // force a copy, leaving dir intact
    pat = push(&scratch, pat, (u16)'\\');
    pat = push(&scratch, pat, (u16)'*');
    pat = push(&scratch, pat, (u16)0);

    FindData *fd = alloc<FindData>(&scratch);
    uz h = FindFirstFileW(pat.data, fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        u16 *name = fd->name;
        if (name[0]=='.' && (!name[1] || (name[1]=='.' && !name[2]))) {
            continue;
        }
        Arena t = scratch;
        iz nlen = wstrlen(name);
        Str  u  = fromwide(&t, name, nlen);
        Str  path = {};
        path.data = allocbytes(&t, rel.len + u.len + 1);
        copybytes(path.data, rel.data, rel.len);
        copybytes(path.data+rel.len, u.data, u.len);
        path.len = rel.len + u.len;
        b32 isdir = fd->attrs & FILE_ATTRIBUTE_DIRECTORY;
        print(c->out, path);
        print(c->out, isdir ? Str("/\n") : Str("\n"));
        if (isdir && !(fd->attrs & FILE_ATTRIBUTE_REPARSE)) {
            path.data[path.len++] = '/';
            Slice<u16> sub = dir;
            sub.cap = sub.len;
            sub = push(&t, sub, (u16)'\\');
            for (iz i = 0; i < nlen; i++) {
                sub = push(&t, sub, name[i]);
            }
            lsdir(c, t, sub, path);
        }
    } while (FindNextFileW(h, fd));
    FindClose(h);
}

static void cmdls(Ctx *c, Args *a)
{
    u16 *root = more(a) ? a->w[a->i++] : (u16 *)u".";
    done(c, a);
    Slice<u16> dir = {};
    iz len = wstrlen(root);
    for (; len>1 && (root[len-1]=='\\' || root[len-1]=='/'); len--) {}
    for (iz i = 0; i < len; i++) {
        dir = push(&c->perm, dir, root[i]);
    }
    lsdir(c, c->perm, dir, Str{});
}

static void usage(Output *o)
{
    print(o,
"usage: winctl COMMAND [ARGS]\n"
"  list [-a] [WINDOW]           list visible top-level windows (-a: all)\n"
"  shot [WINDOW [X Y W H]]      PNG of the screen under WINDOW to stdout\n"
"  wait [-gone|-change|-idle] [-t SECS] WINDOW\n"
"                               wait until WINDOW exists, is gone, changes\n"
"                               title, or its process is idle (default 10s)\n"
"  click|dclick|rclick WINDOW X Y\n"
"  drag WINDOW X0 Y0 X1 Y1\n"
"  wheel WINDOW X Y CLICKS      positive scrolls up\n"
"  key WINDOW CHORD...          e.g. ctrl+s alt+f shift+tab enter f2 del\n"
"  type WINDOW TEXT             TEXT as Unicode keys, - reads stdin (UTF-8)\n"
"  raise WINDOW                 bring to the foreground\n"
"  cmd WINDOW ID                post WM_COMMAND\n"
"  close WINDOW                 post WM_CLOSE\n"
"  move WINDOW X Y [W H]        move and resize, in screen pixels\n"
"  run PROGRAM [ARGS...]        start detached from the session, print PID\n"
"  ls [DIR]                     recursive listing with Unicode names\n"
"WINDOW: title substring, or key=value[,key=value...] with keys title=,\n"
"  class=, pid=, hwnd=; or 'screen'; or 'active' (the foreground window).\n"
"Coordinates are physical pixels relative to the window, as in its shot.\n"
"Exit status: 0 ok, 1 error, 2 no or ambiguous window match, 3 timeout.\n"
    );
}

static void run(Ctx *c, Args *a)
{
    if (a->n < 2) {
        usage(c->err);
        quit(c, STATUS_FAIL);
    }
    a->i = 2;
    Str cmd = a->v[1];
    if (cmd=="-h" || cmd=="--help" || cmd=="help") {
        usage(c->out);
    } else if (cmd == "list") {
        cmdlist(c, a);
    } else if (cmd == "shot") {
        cmdshot(c, a);
    } else if (cmd == "wait") {
        cmdwait(c, a);
    } else if (cmd == "click") {
        cmdclick(c, a, 'l');
    } else if (cmd == "dclick") {
        cmdclick(c, a, 'd');
    } else if (cmd == "rclick") {
        cmdclick(c, a, 'r');
    } else if (cmd == "drag") {
        cmddrag(c, a);
    } else if (cmd == "wheel") {
        cmdwheel(c, a);
    } else if (cmd == "key") {
        cmdkey(c, a);
    } else if (cmd == "type") {
        cmdtype(c, a);
    } else if (cmd == "raise") {
        cmdraise(c, a);
    } else if (cmd == "cmd") {
        cmdpost(c, a, WM_COMMAND);
    } else if (cmd == "close") {
        cmdpost(c, a, WM_CLOSE);
    } else if (cmd == "move") {
        cmdmove(c, a);
    } else if (cmd == "run") {
        cmdrun(c, a);
    } else if (cmd == "ls") {
        cmdls(c, a);
    } else {
        fail(c, STATUS_FAIL, "unknown command", cmd);
    }
}

extern "C" __attribute((force_align_arg_pointer))
void mainCRTStartup()
{
    iz    cap = (iz)1<<24;
    byte *mem = VirtualAlloc(0, (uz)cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        ExitProcess(STATUS_FAIL);
    }
    Ctx ctx  = {};
    Ctx *c   = &ctx;
    c->perm  = {mem, mem+cap};
    c->out   = newoutput(&c->perm, STD_OUTPUT_HANDLE);
    c->err   = newoutput(&c->perm, STD_ERROR_HANDLE);
    errout   = c->err;

    initdpi();
    initdwm();

    Args a = {};
    a.w = CommandLineToArgvW(GetCommandLineW(), &a.n);
    if (!a.w) {
        fail(c, STATUS_FAIL, "cannot parse the command line");
    }
    a.v = alloc<Str>(&c->perm, a.n);
    for (i32 i = 0; i < a.n; i++) {
        a.v[i] = fromwide(&c->perm, a.w[i], wstrlen(a.w[i]));
    }

    run(c, &a);
    quit(c, STATUS_OK);
}
