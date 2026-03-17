CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall
LDFLAGS = -ladvapi32

SRCS = $(wildcard *.c)
EXES = $(SRCS:.c=.exe)

all: $(EXES)

%.exe: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(EXES)
