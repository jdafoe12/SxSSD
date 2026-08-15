CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../policy -I../policy/inc
TOOL_LDFLAGS = -lssl -lcrypto

TOOLS = policyctl test_device_signing key-sharing-client

.PHONY: all clean tool

all: $(TOOLS)

tool: $(TOOLS)

policyctl: policyctl.c ../device-trust.h ../meta-interface-protocol.h
	$(CC) $(CFLAGS) -o $@ $< $(TOOL_LDFLAGS)

test_device_signing: test_device_signing.c ../device-trust.c ../device-trust.h
	$(CC) $(CFLAGS) -I.. -o $@ test_device_signing.c ../device-trust.c $(TOOL_LDFLAGS)

key-sharing-client: key-sharing-client.c ../policy/key-sharing.h ../device-trust.h
	$(CC) $(CFLAGS) -I.. -o $@ key-sharing-client.c $(TOOL_LDFLAGS)

clean:
	rm -f $(TOOLS)
