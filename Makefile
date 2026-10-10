CXX32 = i686-w64-mingw32-g++
CXX64 = x86_64-w64-mingw32-g++

CXXFLAGS = -std=c++20 -O2 -nostartfiles -static-libgcc \
  -fno-exceptions -fno-rtti -fno-threadsafe-statics \
  -fno-asynchronous-unwind-tables -fno-stack-protector \
  -Wall -Wextra -Wconversion -Wno-sign-conversion \
  -Wno-unused-parameter -Wno-unused-function

LIBS = -lkernel32 -lws2_32 -ladvapi32
SRC  = win32.cpp base.cpp crypto.cpp ssh.cpp

all: sshd.exe sshd64.exe

sshd.exe: $(SRC)
	$(CXX32) $(CXXFLAGS) -o $@ win32.cpp $(LIBS)

sshd64.exe: $(SRC)
	$(CXX64) $(CXXFLAGS) -o $@ win32.cpp $(LIBS)

clean:
	rm -f sshd.exe sshd64.exe