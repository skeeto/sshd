CXXFLAGS = -O2 -fno-exceptions -fno-rtti -fno-threadsafe-statics \
  -Wall -Wextra -Wconversion -Wno-sign-conversion -Wno-unused-function

LIBS = -lkernel32 -lws2_32 -ladvapi32 -lmemory -lchkstk
SRC  = win32.cpp base.cpp crypto.cpp ssh.cpp

AMALG_HEADER = \
  '// sshd - a minimal public-key-only SSH server for Windows.' \
  '// Amalgamation of base.cpp, crypto.cpp, ssh.cpp, and win32.cpp.' \
  '// This is free and unencumbered software released into the public domain.' \
  '//' \
  '// Build (32-bit Windows XP):' \
  '//   cc -nostartfiles -o sshd.exe sshd.cpp -lkernel32 -lws2_32 -ladvapi32' \
  '// Build (64-bit): use x86_64-w64-mingw32-g++ and -o sshd64.exe.'

all: sshd.exe

sshd.exe: $(SRC)
	$(CXX) -std=c++20 -nostdlib $(CXXFLAGS) -o $@ win32.cpp $(LIBS)

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