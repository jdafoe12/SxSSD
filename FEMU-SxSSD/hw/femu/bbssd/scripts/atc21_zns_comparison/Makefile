CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
LDLIBS += -laio -pthread

.PHONY: all clean

all: atc21-write

atc21-write: atc21-write.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f atc21-write
