# SPDX-License-Identifier: GPL-2.0-or-later

CC = gcc
CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags hogweed nettle)
CRYPTO_LIBS = $(shell pkg-config --libs hogweed nettle)
CRYPTO_SOURCES = ../policy-crypto.c
HOST_CRYPTO_SOURCES = host-crypto.c $(CRYPTO_SOURCES)

TOOLS = policyctl test_device_signing key-sharing-client
TESTS = test_sxssd_crypto

.PHONY: all check clean tool

all: $(TOOLS)

tool: $(TOOLS)

policyctl: policyctl.c host-crypto.h ../device-trust.h \
		../meta-interface-protocol.h ../policy-crypto.h $(HOST_CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -I.. -o $@ policyctl.c $(HOST_CRYPTO_SOURCES) \
		$(CRYPTO_LIBS)

test_device_signing: test_device_signing.c host-crypto.h ../device-trust.c \
		../device-trust.h ../policy-crypto.h $(HOST_CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -I.. -o $@ test_device_signing.c ../device-trust.c \
		$(HOST_CRYPTO_SOURCES) $(CRYPTO_LIBS)

key-sharing-client: key-sharing-client.c host-crypto.h \
		../policy/include/key-sharing.h ../device-trust.h ../policy-crypto.h \
		$(HOST_CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -I.. -o $@ key-sharing-client.c \
		$(HOST_CRYPTO_SOURCES) $(CRYPTO_LIBS)

test_sxssd_crypto: test_sxssd_crypto.c ../policy-crypto.h $(CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -I.. -o $@ test_sxssd_crypto.c $(CRYPTO_SOURCES) \
		$(CRYPTO_LIBS)

check: $(TESTS) test_device_signing
	./test_sxssd_crypto
	./test_device_signing

clean:
	rm -f $(TOOLS) $(TESTS)
