# SPDX-License-Identifier: GPL-2.0-or-later

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../policy -I../policy/inc
TOOL_LDFLAGS = -lssl -lcrypto

TOOLS = policyctl

.PHONY: all clean tool

all: $(TOOLS)

tool: $(TOOLS)

policyctl: policyctl.c
	$(CC) $(CFLAGS) -o $@ $< $(TOOL_LDFLAGS)

clean:
	rm -f $(TOOLS)
