CXX32 = i686-w64-mingw32-g++
CXX64 = x86_64-w64-mingw32-g++

CXXFLAGS = -std=c++20 -O2 -nostartfiles -static-libgcc \
  -fno-exceptions -fno-rtti -fno-threadsafe-statics \
  -fno-asynchronous-unwind-tables -fno-stack-protector \
  -Wall -Wextra -Wconversion -Wno-sign-conversion \
  -Wno-unused-parameter -Wno-unused-function

LIBS = -lkernel32 -lws2_32 -ladvapi32
SRC  = win32.cpp base.cpp crypto.cpp ssh.cpp

AMALG_HEADER = \
  '// sshd - a minimal public-key-only SSH server for Windows.' \
  '// Amalgamation of base.cpp, crypto.cpp, ssh.cpp, and win32.cpp.' \
  '// This is free and unencumbered software released into the public domain.' \
  '//' \
  '// Build (32-bit Windows XP):' \
  '//   i686-w64-mingw32-g++ -std=c++20 -O2 -nostartfiles -static-libgcc -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-asynchronous-unwind-tables -fno-stack-protector -o sshd.exe sshd.cpp -lkernel32 -lws2_32 -ladvapi32' \
  '// Build (64-bit): use x86_64-w64-mingw32-g++ and -o sshd64.exe.'

all: sshd.exe sshd64.exe

sshd.exe: $(SRC)
	$(CXX32) $(CXXFLAGS) -o $@ win32.cpp $(LIBS)

sshd64.exe: $(SRC)
	$(CXX64) $(CXXFLAGS) -o $@ win32.cpp $(LIBS)

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
	rm -f sshd.exe sshd64.exe sshd.cpp