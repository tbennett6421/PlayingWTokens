CC = x86_64-w64-mingw32-gcc
CC32 = i686-w64-mingw32-gcc
CFLAGS = -Wall
LDFLAGS = -ladvapi32 -lsecur32

SRCS = $(wildcard src/*.c)
EXES = $(patsubst src/%.c,dist/%.exe,$(SRCS))

# BOF sources live in src/bof/
BOF_SRCS = $(wildcard src/bof/*.c)
BOFS64 = $(patsubst src/bof/%.c,dist/bof/%.x64.o,$(BOF_SRCS))
BOFS32 = $(patsubst src/bof/%.c,dist/bof/%.x86.o,$(BOF_SRCS))

all: dist $(EXES) bof

bof: dist/bof $(BOFS64) $(BOFS32)

dist:
	mkdir -p dist

dist/bof:
	mkdir -p dist/bof

dist/%.exe: src/%.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

dist/bof/%.x64.o: src/bof/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

dist/bof/%.x86.o: src/bof/%.c
	$(CC32) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf dist
