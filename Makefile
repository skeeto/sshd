CXXFLAGS = -O2 -fno-exceptions -fno-rtti -fno-threadsafe-statics \
  -Wall -Wextra -Wconversion -Wno-sign-conversion

LIBS = -lkernel32 -lws2_32 -ladvapi32 -lshell32 -lmemory -lchkstk -lgcc
SRC  = src/win32.cpp src/base.cpp src/crypto.cpp src/ssh.cpp src/sftp.cpp

AMALG_HEADER = \
  '// sshd - a minimal public-key-only SSH server for Windows' \
  '// $$ cc -nostartfiles -o sshd.exe sshd.cpp -lws2_32' \
  '// This is free and unencumbered software released into the public domain.' \
  ''

all: sshd.exe

sshd.exe: $(SRC)
	$(CXX) -nostdlib $(CXXFLAGS) -o $@ src/win32.cpp $(LIBS)

# Single-file amalgamation to copy to the target machine and build there.
sshd.cpp: $(SRC) Makefile
	@printf '%s\n' $(AMALG_HEADER) > $@
	@cat src/base.cpp >> $@
	@printf '\n' >> $@
	@cat src/crypto.cpp >> $@
	@printf '\n' >> $@
	@cat src/ssh.cpp >> $@
	@printf '\n' >> $@
	@cat src/sftp.cpp >> $@
	@printf '\n' >> $@
	@grep -vE '^#include "(base|crypto|ssh|sftp)\.cpp"$$' src/win32.cpp >> $@

clean:
	rm -f sshd.exe sshd.cpp
