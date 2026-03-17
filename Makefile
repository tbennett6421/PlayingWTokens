CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall
LDFLAGS = -ladvapi32

SRCS = $(wildcard *.c)
EXES = $(addprefix dist/,$(SRCS:.c=.exe))

all: dist $(EXES)

dist:
	mkdir -p dist

dist/%.exe: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf dist
