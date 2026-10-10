CXXFLAGS = -O2 -fno-exceptions -fno-rtti -fno-threadsafe-statics \
  -Wall -Wextra -Wconversion -Wno-sign-conversion

LIBS = -lkernel32 -lws2_32 -ladvapi32 -lshell32 -lmemory -lchkstk
SRC  = win32.cpp base.cpp crypto.cpp ssh.cpp

AMALG_HEADER = \
  '// sshd - a minimal public-key-only SSH server for Windows' \
  '// $$ cc -nostartfiles -o sshd.exe sshd.cpp -lws2_32' \
  '// This is free and unencumbered software released into the public domain.' \
  ''

all: sshd.exe

sshd.exe: $(SRC)
	$(CXX) -nostdlib $(CXXFLAGS) -o $@ win32.cpp $(LIBS)

# Single-file amalgamation to copy to the target machine and build there.
sshd.cpp: base.cpp crypto.cpp ssh.cpp win32.cpp Makefile
	@printf '%s\n' $(AMALG_HEADER) > $@
	@cat base.cpp >> $@
	@printf '\n' >> $@
	@cat crypto.cpp >> $@
	@printf '\n' >> $@
	@cat ssh.cpp >> $@
	@printf '\n' >> $@
	@grep -vE '^#include "(base|crypto|ssh)\.cpp"$$' win32.cpp >> $@

clean:
	rm -f sshd.exe sshd.cpp