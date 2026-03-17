CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall
LDFLAGS = -ladvapi32

SRCS = $(wildcard src/*.c)
EXES = $(patsubst src/%.c,dist/%.exe,$(SRCS))

all: dist $(EXES)

dist:
	mkdir -p dist

dist/%.exe: src/%.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf dist
