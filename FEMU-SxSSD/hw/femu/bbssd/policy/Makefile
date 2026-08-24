# SPDX-License-Identifier: GPL-2.0-or-later

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I. -Iinc
POLICY_LDFLAGS = -shared

POLICIES = block-interface-policy-eval.so block-interface-policy-baseline.so block-interface-policy-flashguard.so block-interface-flashguard-policy.so zns-policy.so

.PHONY: all clean
.PHONY: tool

all: $(POLICIES)

tool: $(POLICIES)

BLOCK_POLICY_DEPS = block-interface-policy.h block-interface-policy-state.h femu_policy.h inc/pqueue.h inc/qtailq.h lib/pqueue.c

block-interface-policy-eval.so: block-interface-policy-eval.c $(BLOCK_POLICY_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ block-interface-policy-eval.c lib/pqueue.c

block-interface-policy-baseline.so: block-interface-policy-baseline.c $(BLOCK_POLICY_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ block-interface-policy-baseline.c lib/pqueue.c

block-interface-policy-flashguard.so: block-interface-policy-flashguard.c $(BLOCK_POLICY_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ block-interface-policy-flashguard.c lib/pqueue.c

block-interface-flashguard-policy.so: block-interface-flashguard-policy.c $(BLOCK_POLICY_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ block-interface-flashguard-policy.c lib/pqueue.c

zns-policy.so: zns-policy.c zns-policy.h femu_policy.h
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ zns-policy.c

clean:
	rm -f $(POLICIES)
