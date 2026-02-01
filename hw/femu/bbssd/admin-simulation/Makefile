# Makefile for admin-simulation
# Builds the admin session establishment client

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../..
LDFLAGS = -lssl -lcrypto

TARGET = admin-simulation
SOURCES = admin-simulation.c
HEADERS = admin-simulation.h

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
