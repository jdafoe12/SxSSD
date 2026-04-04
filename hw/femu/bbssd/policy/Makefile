CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I. -Iinc
POLICY_LDFLAGS = -shared

POLICIES = block-interface-policy.so block-interface-policy-buffered.so simple-log-policy.so zns-policy.so

.PHONY: all clean
.PHONY: tool

all: $(POLICIES)

tool: $(POLICIES)

block-interface-policy.so: block-interface-policy.c block-interface-policy-state.h femu_policy.h inc/pqueue.h inc/qtailq.h lib/pqueue.c
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ block-interface-policy.c lib/pqueue.c

block-interface-policy-buffered.so: block-interface-policy-buffered.c block-interface-policy-buffered.h block-interface-policy-buffered-state.h femu_policy.h inc/pqueue.h inc/qtailq.h lib/pqueue.c
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ block-interface-policy-buffered.c lib/pqueue.c

simple-log-policy.so: simple-log-policy.c femu_policy.h
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ simple-log-policy.c

zns-policy.so: zns-policy.c zns-policy.h femu_policy.h
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ zns-policy.c

clean:
	rm -f $(POLICIES)
