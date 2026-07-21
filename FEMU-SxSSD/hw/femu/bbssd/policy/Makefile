CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I. -Iinc
POLICY_LDFLAGS = -shared

POLICIES = block-interface-policy-eval.so block-interface-policy-baseline.so block-interface-policy-flashguard.so block-interface-flashguard-policy.so zns-policy.so signing-test-policy.so key-sharing-policy.so tee-ftl-v1-policy.so

.PHONY: all clean
.PHONY: tool
.PHONY: test test-tee-v1

all: $(POLICIES)

tool: $(POLICIES)

BLOCK_POLICY_DEPS = block-interface-policy.h block-interface-policy-state.h femu_policy.h inc/pqueue.h inc/qtailq.h lib/pqueue.c
TEE_V1_SRCS = tee/tee-v1-segment.c tee/tee-v1-bitmap.c tee/tee-v1-guard.c
TEE_V1_DEPS = tee/tee-v1-segment.h tee/tee-v1-bitmap.h tee/tee-v1-guard.h $(TEE_V1_SRCS)

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

signing-test-policy.so: signing-test-policy.c femu_policy.h
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ signing-test-policy.c

key-sharing-policy.so: key-sharing-policy.c key-sharing.h femu_policy.h
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ key-sharing-policy.c

tee-ftl-v1-policy.so: tee-ftl-v1-policy.c $(BLOCK_POLICY_DEPS) $(TEE_V1_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ tee-ftl-v1-policy.c lib/pqueue.c $(TEE_V1_SRCS)

test_tee_v1_segment: tests/test_tee_v1_segment.c tee/tee-v1-segment.c tee/tee-v1-segment.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v1_segment.c tee/tee-v1-segment.c

test_tee_v1_bitmap: tests/test_tee_v1_bitmap.c tee/tee-v1-bitmap.c tee/tee-v1-bitmap.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v1_bitmap.c tee/tee-v1-bitmap.c

test_tee_v1_guard: tests/test_tee_v1_guard.c $(TEE_V1_DEPS) femu_policy.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v1_guard.c $(TEE_V1_SRCS)

test_tee_v1_flow: tests/test_tee_v1_flow.c $(TEE_V1_DEPS) femu_policy.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v1_flow.c $(TEE_V1_SRCS)

test-tee-v1: test_tee_v1_segment test_tee_v1_bitmap test_tee_v1_guard test_tee_v1_flow
	./test_tee_v1_segment
	./test_tee_v1_bitmap
	./test_tee_v1_guard
	./test_tee_v1_flow

test: test-tee-v1

clean:
	rm -f $(POLICIES) test_tee_v1_segment test_tee_v1_bitmap test_tee_v1_guard test_tee_v1_flow
