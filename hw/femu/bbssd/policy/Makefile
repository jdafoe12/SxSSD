CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I. -Iinc
POLICY_LDFLAGS = -shared
TOOL_LDFLAGS = -lssl -lcrypto

POLICIES = block-interface-policy.so
TOOLS = policyctl

.PHONY: all clean
.PHONY: tool

all: $(POLICIES) $(TOOLS)

tool: policyctl

block-interface-policy.so: block-interface-policy.c block-interface-policy-state.h femu_policy.h inc/pqueue.h inc/qtailq.h lib/pqueue.c
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ block-interface-policy.c lib/pqueue.c

policyctl: policyctl.c
	$(CC) -Wall -Wextra -O2 -o $@ policyctl.c $(TOOL_LDFLAGS)

clean:
	rm -f $(POLICIES) $(TOOLS)
