CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../policy -I../policy/inc
TOOL_LDFLAGS = -lssl -lcrypto

TOOLS = policyctl test_device_signing key-sharing-client

.PHONY: all clean tool

all: $(TOOLS)

tool: $(TOOLS)

policyctl: policyctl.c ../device-identity.h ../policy-attestation-format.h
	$(CC) $(CFLAGS) -o $@ $< $(TOOL_LDFLAGS)

test_device_signing: test_device_signing.c ../device-signing.c ../device-signing.h ../device-identity.h
	$(CC) $(CFLAGS) -I.. -o $@ test_device_signing.c ../device-signing.c $(TOOL_LDFLAGS)

key-sharing-client: key-sharing-client.c ../policy/key-sharing.h ../device-signing.h ../device-identity.h
	$(CC) $(CFLAGS) -I.. -o $@ key-sharing-client.c $(TOOL_LDFLAGS)

clean:
	rm -f $(TOOLS)
