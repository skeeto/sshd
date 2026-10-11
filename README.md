# sshd: a minimal SSH server for Windows

A small, dependency-free SSH server for Windows XP and later. It only
supports public-key authentication. It's meant for driving builds and
tests on a machine on a trusted local network, for example from a
w64devkit shell, and is not a general-purpose replacement for OpenSSH.

> [!WARNING]
> **Do not expose this server to the internet or any untrusted network.**
> It has not been audited, it has weak defenses against denial of
> service, and it makes no effort to resist side-channel attacks. Run it
> only on a network where every host is trusted. See [Security](#security).

## Features

* Ed25519 public-key authentication only (`ssh-ed25519`)
* Key exchange `curve25519-sha256`, host key `ssh-ed25519`, cipher
  `chacha20-poly1305@openssh.com`, with OpenSSH strict key exchange
  (the Terrapin countermeasure) and rekeying
* Remote commands with separate stdout and stderr, stdin, and exit status
* Interactive shells with basic line editing, though not a real terminal
  (see [Interactive sessions](#interactive-sessions))
* A built-in `sftp` subsystem, so `scp` and `sftp` work
* Sessions start in the user's home directory (`%USERPROFILE%`)
* A client that disconnects mid-command takes the whole process tree
  with it. Background jobs survive a normal exit.
* No C runtime dependency: kernel32, ws2_32, advapi32, and shell32 only

## Building

With [w64devkit][]:

    $ make

This builds `sshd.exe` from the sources in `src/`. To build on another
machine without the repository, generate a single-file amalgamation of
the same sources with `make sshd.cpp`, copy it over, and build it there
with a single command:

    $ cc -nostartfiles -o sshd.exe sshd.cpp -lws2_32

To build a 32-bit binary for Windows XP, use an i686 toolchain.

## Usage

    sshd [-p port] [-k authorized_keys] [-s shell] [-H hostkey] [-selftest]

| Option | Default           | Meaning                                    |
|--------|-------------------|--------------------------------------------|
| `-p`   | `22`              | TCP port to listen on                      |
| `-k`   | `authorized_keys` | Authorized public keys                     |
| `-s`   | `sh.exe`          | Shell for commands and sessions            |
| `-H`   | `hostkey`         | Host key, created on first run if missing  |

Relative paths are relative to the server's working directory. A shell
named without a directory is looked for next to `sshd.exe`, then in
`bin\` and `..\bin\` relative to it, and then on `PATH`, so placing
`sshd.exe` in a w64devkit installation finds its shell. Commands run as
`shell -c command`. PowerShell (`-s powershell.exe`) is recognized and
run as `-Command`. `-selftest` runs the built-in cryptography and UTF-8
tests and exits.

`authorized_keys` uses the OpenSSH format, but only plain `ssh-ed25519`
lines are honored. Lines with options (`from=`, `command=`,
`restrict`, ...) or other key types are skipped.

A server started inside a Windows job object, such as from a session of
another sshd, relaunches itself outside that job when the job allows it,
since XP cannot nest jobs and each session needs its own.

The Windows Firewall may block the first time `sshd.exe` listens. The
exception it grants applies to that executable path, so a binary at a
new path needs a new exception.

## Interactive sessions

Windows XP has no pseudo-terminals, so when a client requests a pty (as
plain `ssh host` does), the server provides a minimal line editor and
runs the shell interactively (`sh -i`) on pipes:

* Typed characters are echoed, and Enter sends the line to the shell.
* Backspace erases a character, Ctrl-U the line, and Ctrl-W a word.
* Ctrl-C interrupts the running command by terminating the processes
  started since the last line was entered. Its exit status is 130.
  Background jobs started earlier are left alone.
* Ctrl-D at the start of a line ends input, which exits the shell.

There is no history, cursor movement, or tab completion, and escape
sequences such as arrow keys are ignored. Programs see pipes, not a
terminal, so full-screen programs like `vi` and `less` do not work, and
programs that buffer output when it is not a terminal may appear to
hang. The window size is not passed through.

## Security

Authentication itself is sound: a client must prove possession of the
private key for one of the authorized public keys with a signature that
covers the session identifier, so signatures cannot be forged, swapped
between keys, or replayed into another session. The Ed25519 and X25519
implementations pass the RFC 8032 vectors and differential testing
against an independent implementation. Even so, keep these limitations
in mind:

* **The user name is ignored.** Any user name works with an authorized
  key, and every session runs as the account running `sshd.exe`. An
  authenticated client has full access as that user: a shell, arbitrary
  environment variables, and SFTP access to the entire file system. There
  is no sandbox.
* **Denial of service is easy.** There are 32 connection slots, and
  handshakes time out only after two minutes, so a few idle or very
  slow connections can lock out legitimate users. This does not grant
  any access.
* **No side-channel resistance.** In particular, signing with the host
  key uses scalar arithmetic that branches on secret data, so the host
  key may be vulnerable to timing attacks.
* **The host key is stored unencrypted.** The `hostkey` file holds the
  raw Ed25519 seed. Anyone who can read it can impersonate the server,
  though not log in to it.
* Pre-authentication parsing is bounds-checked and has been reviewed,
  but it has not been fuzzed.

## License

This is free and unencumbered software released into the public domain.
See [UNLICENSE](UNLICENSE).

[w64devkit]: https://github.com/skeeto/w64devkit
