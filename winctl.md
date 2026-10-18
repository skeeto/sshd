# winctl: drive GUI programs over SSH

`winctl.exe` captures and drives GUI windows on the Windows machine it
runs on. It is meant for testing GUI programs remotely through this
repository's `sshd`, which runs commands as the user logged in at the
console, so programs started over SSH appear on that desktop and
`winctl` can see and control them. It is a separate program from
`sshd.exe`, and runs on Windows XP and later.

Commands find a top-level window, act on it, and exit. A typical session
is a series of `ssh host winctl ...` commands, with screenshots written
to local PNG files and viewed in between.

## Getting it onto the target

On a machine with [w64devkit][] and this repository:

    $ make winctl.exe                              # 64-bit
    $ make -B winctl.exe CXX=i686-w64-mingw32-g++  # 32-bit, for XP

The source is one self-contained file, so the target can also build it
itself (w64devkit's `cc`, either architecture):

    $ scp src/winctl.cpp host:
    $ ssh host cc -nostartfiles -o winctl.exe winctl.cpp -lgdi32

Or copy a prebuilt binary: `scp winctl.exe host:`. An i686 build runs
everywhere. Imports are kernel32, user32, gdi32 and shell32, all present
on XP; newer functions are looked up at run time.

## The loop

    $ ssh host ./winctl.exe run notepad.exe
    4080
    $ ssh host ./winctl.exe wait pid=4080
    0x002f009c	4080	110,145	960x554	Notepad	Untitled - Notepad
    $ ssh host ./winctl.exe type pid=4080 "'hello, world'"
    $ ssh host ./winctl.exe key pid=4080 alt+e
    $ ssh host ./winctl.exe shot pid=4080 > s.png     # then view s.png
    $ ssh host ./winctl.exe key pid=4080 esc
    $ ssh host ./winctl.exe close pid=4080
    $ ssh host ./winctl.exe wait pid=4080,class=#32770 # "Save changes?"
    $ ssh host ./winctl.exe key pid=4080,class=#32770 alt+n
    $ ssh host ./winctl.exe wait -gone pid=4080

1. `run` starts the program outside the SSH session and its job object,
   so it outlives the command and the connection, and prints its PID.
2. `wait` until the window exists before anything else. It prints the
   matching windows, including the rectangle and title.
3. Act on it: `click`, `key`, `type`, `drag`, and so on. Each brings
   the window to the foreground first.
4. `shot WINDOW > file.png` and look at the image (the Read tool shows
   PNGs). The PNG goes to stdout, so nothing else may write to stdout in
   that ssh command: send other output to stderr (`>&2`) or use a
   separate command.
5. Pick coordinates for the next action from the image (see
   [Coordinates](#coordinates)), act, capture again, and repeat.
6. Clean up: close the program the way a user would, decline to save,
   `wait -gone`, and restore anything it persisted (see
   [Pitfalls](#pitfalls)).

The remote shell is usually busybox `sh`. Quote arguments for both the
local and the remote shell. On XP the home directory is
`C:/Documents and Settings/USER`, so quote paths: `"$W"`, not `$W`.

## Choosing a window

Every command except `list`, `run` and `ls` takes a WINDOW argument.

| WINDOW                      | Matches                                    |
|-----------------------------|--------------------------------------------|
| `Notepad`                   | title contains "Notepad" (ASCII case-insensitive) |
| `title=Save As`             | the same, explicitly                       |
| `class=Notepad`             | window class, exactly (case-insensitive)   |
| `pid=4080`                  | windows of that process                    |
| `hwnd=0x002f009c`           | that window handle, from `list` or `wait`  |
| `pid=4080,class=#32770`     | all criteria at once (comma-separated)     |
| `screen`                    | the whole (virtual) screen                 |
| `active`                    | the current foreground window              |

Only visible, uncloaked top-level windows are considered. A dialog is a
top-level window of its own, typically class `#32770`, so select it with
`pid=N,class=#32770` or by its title. Popup menus (`#32768`), their
shadows (`SysShadow`) and tooltips are skipped unless `class=` names
them, so `pid=N` still means the main window while a menu is open.

If nothing matches, or more than one window matches, a command fails
with exit status 2 and, for an ambiguous match, lists the candidates on
stderr in `list` format. Narrow it with more criteria or use `hwnd=`.

## Commands

    winctl list [-a] [WINDOW]

One line per window, tab-separated: handle, PID, `X,Y` of the top-left
corner on screen, `WxH`, class, title (UTF-8). Top of the z-order comes
first, which tells you what is above what. `-a` includes invisible and
cloaked windows. With WINDOW, only matching windows are listed (exit
status 0 even when none match). Minimized windows show `-32000,-32000`.

    $ ssh host ./winctl.exe list
    0x00040032	1408	0,770	1280x30	Shell_TrayWnd
    0x002f009c	4080	110,145	960x554	Notepad	Untitled - Notepad
    0x0001007a	1408	0,0	1280x800	Progman	Program Manager

---

    winctl shot [WINDOW [X Y W H]] > file.png

Captures the screen area the window occupies, as a 24-bit PNG on stdout.
It copies the screen rather than asking the window to paint, so open
menus, dialogs and tooltips over the window are included, and so is
anything else that covers it. With no WINDOW it captures the whole
screen (all monitors). `X Y W H` crops to a rectangle in window
coordinates, which keeps images small on a 4K screen. It refuses to
write to a console. It does not raise the window: `raise` it first if it
may be covered.

    $ ssh host ./winctl.exe shot pid=4080 > s.png
    $ ssh host ./winctl.exe shot pid=4080 0 0 600 200 > top.png
    $ ssh host ./winctl.exe shot > desktop.png

---

    winctl wait [-gone | -change | -idle] [-t SECONDS] WINDOW

Polls until the condition holds, or exits with status 3 after the
timeout (default 10 seconds, fractions allowed, `-t 0` checks once).

* no option: a matching window exists. Prints all matching windows.
  Several matches are fine here, though later commands need exactly one.
* `-gone`: no matching window exists.
* `-change`: the title of the (single) matching window differs from its
  title when `wait` started. Prints the window. Useful after saving or
  opening a file. Status 2 if the window closes meanwhile.
* `-idle`: the window's process is waiting for input
  (`WaitForInputIdle`). With a bare `pid=N`, no window is needed.

`wait -t 0 WINDOW` is also the way to test whether a window exists
(status 0 or 3) without failing on ambiguity.

---

    winctl click  WINDOW X Y
    winctl dclick WINDOW X Y
    winctl rclick WINDOW X Y
    winctl wheel  WINDOW X Y CLICKS
    winctl drag   WINDOW X0 Y0 X1 Y1

Mouse input at window coordinates. Each first brings the window to the
foreground (except with `screen`), moves the pointer there, and acts.
`dclick` sends two clicks within the double-click time. `wheel` scrolls
by CLICKS notches, positive up. `drag` presses the left button at the
first point, moves a pixel at a time past the system drag threshold,
then the rest of the way in steps with short pauses, hovers, and
releases at the second point. This is slow enough for `DragDetect` and
OLE `DoDragDrop`; it was verified moving selected text in WordPad on XP.

    $ ssh host ./winctl.exe click pid=4080,class=#32770 330 171
    $ ssh host ./winctl.exe drag pid=2568 32 152 168 152

---

    winctl key WINDOW CHORD...

Presses each chord in turn. A chord is keys joined by `+`: modifiers
`ctrl`, `alt`, `shift`, `win`, then a letter, digit, punctuation
character, or a named key: `enter`, `tab`, `esc`, `space`, `backspace`,
`del`, `ins`, `home`, `end`, `pgup`, `pgdn`, `left`, `up`, `right`,
`down`, `f1`-`f24`, `apps` (context menu key), `pause`, `prtsc`,
`plus`, `minus`, `comma`. Letters never imply shift: `ctrl+S` is
`ctrl+s`; write `ctrl+shift+s`.

    $ ssh host ./winctl.exe key pid=4080 ctrl+a del
    $ ssh host ./winctl.exe key pid=4080 alt+f x       # File > Exit
    $ ssh host ./winctl.exe key active shift+tab enter

---

    winctl type WINDOW TEXT
    winctl type WINDOW -

Types TEXT as Unicode characters (`KEYEVENTF_UNICODE`), independent of
the keyboard layout. Newlines become Enter and tabs become Tab. With
`-`, the text is read from stdin as UTF-8, which is the reliable way to
send non-ASCII text (see [Pitfalls](#pitfalls)):

    $ printf 'Grüße ✓\n' | ssh host ./winctl.exe type pid=4080 -

---

    winctl raise WINDOW            bring to the foreground (restores if minimized)
    winctl cmd   WINDOW ID         post WM_COMMAND with ID, e.g. a menu item
    winctl close WINDOW            post WM_CLOSE, like the title bar's X
    winctl move  WINDOW X Y [W H]  move and optionally resize

`cmd` and `close` post the message and return at once. `move` takes
screen coordinates in the same terms as `list` (the visible frame).
Many programs remember their last position, so a `move` outlives the
test unless you restore it (see [Pitfalls](#pitfalls)).

---

    winctl run PROGRAM [ARGS...]

Starts PROGRAM detached: without inheriting the session's handles, so
the ssh command returns at once, and outside sshd's job object, so the
program survives the end of the session (an SSH disconnect otherwise
kills the session's whole process tree). A console program gets its own
console window. Prints the PID. PROGRAM is found the way
`CreateProcess` finds it (current directory, system directories,
`PATH`, `.exe` appended), not via App Paths: WordPad on XP needs
`"C:/Program Files/Windows NT/Accessories/wordpad.exe"`.

---

    winctl ls [DIR]

Recursive listing of DIR (default `.`) as UTF-8 paths relative to it,
directories with a trailing `/`, junctions listed but not followed.
XP's busybox `ls` shows non-ANSI names as `?`; this does not.

## Coordinates

* Window coordinates are pixels relative to the top-left corner of the
  window's visible frame, which is exactly the top-left pixel of its
  `shot`. A pixel at (x, y) in `shot WINDOW > s.png` is clicked with
  `click WINDOW x y`. For a cropped shot `shot WINDOW X Y W H`, add X
  and Y.
* `screen` coordinates are relative to the top-left of the virtual
  screen, matching `shot screen` (on a single monitor, plain screen
  coordinates).
* All coordinates are physical pixels. winctl is per-monitor DPI aware,
  so on a 4K monitor at 150% a window that looks 1400 pixels wide is
  2100 pixels in `list`, `shot` and `click`. Don't scale anything by
  hand. (The title bar is taller and the fonts are larger, too.)
* Image viewers, including the Read tool, may show a large PNG scaled
  down. Read says so ("displayed at 2000x1047, multiply coordinates by
  1.07"): convert back to image pixels before clicking. Cropping with
  `shot WINDOW X Y W H` avoids scaling and keeps the arithmetic simple.
* Windows move. Coordinates are recomputed from the window's current
  position on every command, so window coordinates stay valid when the
  window moves; screen coordinates don't.

## Exit status

| Status | Meaning                                                    |
|--------|------------------------------------------------------------|
| 0      | success                                                    |
| 1      | usage error, or an operation failed (message on stderr)    |
| 2      | no window matches, or more than one matches                |
| 3      | `wait` timed out                                           |

Common status 1 messages: "cannot bring window to the foreground" (the
input would have gone elsewhere, so nothing was sent), "SendInput
failed" (the target runs elevated and winctl does not, or the desktop is
locked), "screen capture failed" (locked desktop).

## Pitfalls

These were learned the hard way.

* **Clicks too close together become double-clicks.** Windows turns two
  clicks at nearly the same spot within the double-click time (500 ms by
  default) into a double-click, even across separate `click` commands.
  Clicking a list item and then its checkbox, or a button twice, can do
  something else entirely. Wait (`sleep 1`) between clicks at nearby
  points, and use `dclick` when a double-click is intended. The same
  applies before a `drag` that starts where you just clicked.
* **Something else may be on top.** `click` and `drag` act at screen
  positions, so whatever is topmost there receives them: a dialog, a
  tooltip, another program, a notification. This bites at the drop
  point of a drag in particular, which may be outside the target window.
  Check with `list` (top of the z-order first) and the rectangles, or a
  `shot screen`, before a drop. `shot` shows covering windows too, which
  is a clue that one is in the way.
* **Never kill programs by image name.** No `taskkill /im notepad.exe`
  or `killall`: the user may be running the same program with unsaved
  work, on the very desktop you are driving. Close only what you
  started, by PID or handle, the way a user would (`close`, then answer
  the save prompt), and use `taskkill /pid N` only as a last resort for
  your own process.
* **Programs persist settings.** Many programs save window positions,
  recent files, options and session state when they exit, in the
  registry (`HKCU\Software\...`) or in `%APPDATA%`/`%LOCALAPPDATA%`.
  Scripted tests change them for the user. Before the test, export what
  the program uses (`reg export "HKCU\Software\Vendor\App" before.reg`,
  noting whether the key existed at all); afterward, `reg import` it, or
  `reg delete KEY /f` if the test created it. `move` is the classic
  trap: Notepad saves its window position (`HKCU\Software\Microsoft\
  Notepad`, `iWindowPos*`, in logical pixels) on exit, so a test that
  moves it changes where the user's Notepad opens. Windows 11 Notepad
  restores its tabs, including unsaved text, unless each one is closed
  with "Don't Save"; check its `LocalState\TabState` folder under
  `%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_*`.
* **DPI scaling.** Never derive coordinates from a screenshot taken by
  another tool, from logical sizes in the program's source, or from a
  different machine: scale factors differ (150% here, 100% on the XP
  laptop). Take them from a `shot` on the same machine.
* **Non-ASCII text on the command line.** On XP (and with any ANSI
  shell), the remote shell passes arguments through the ANSI code page,
  so `type W "✓"` arrives as `?`. Pipe UTF-8 to `type W -` from the
  local side instead. A `printf` run by the remote shell has the same
  problem, so run it locally: `printf ... | ssh host winctl type W -`.
  Window titles are printed as UTF-8 regardless; on XP, select windows
  with non-ASCII titles by `hwnd=`, `pid=` or `class=`.
* **Let the program catch up.** Input is queued, but a window that is
  still opening, or a menu that has not appeared yet, misses it or
  hands it to the wrong window. After `run`, `close` or an action that
  opens a dialog, `wait` for the result instead of sleeping; after
  opening a menu, a short `sleep 0.5` before `shot`.
* **The PID from `run` may not own the window.** Some programs hand off
  to another process and exit (launchers, single-instance programs that
  forward to a running copy, some Store apps). If `wait pid=N` times
  out, `wait` by class or title instead.
* **The desktop must be unlocked and awake.** With the screen locked,
  on the secure desktop (UAC prompt), or with a screen saver, input
  fails and captures are black or fail. winctl cannot unlock it.
* **Elevated windows refuse input** from a non-elevated winctl (UIPI).
  Run the program unelevated.
* **Minimized windows** report `-32000,-32000`. Every input command and
  `raise` restore them first; `shot` does not, so `raise` before `shot`.

[w64devkit]: https://github.com/skeeto/w64devkit
