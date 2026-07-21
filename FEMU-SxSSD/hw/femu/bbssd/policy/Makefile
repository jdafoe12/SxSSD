CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I. -Iinc
POLICY_LDFLAGS = -shared

POLICIES = block-interface-policy-eval.so block-interface-policy-baseline.so block-interface-policy-flashguard.so block-interface-flashguard-policy.so zns-policy.so signing-test-policy.so key-sharing-policy.so tee-ftl-v1-policy.so tee-ftl-v2-policy.so

.PHONY: all clean
.PHONY: tool
.PHONY: test test-tee-v1 test-tee-v2

all: $(POLICIES)

tool: $(POLICIES)

BLOCK_POLICY_DEPS = block-interface-policy.h block-interface-policy-state.h femu_policy.h inc/pqueue.h inc/qtailq.h lib/pqueue.c
TEE_V1_SRCS = tee/tee-v1-segment.c tee/tee-v1-bitmap.c tee/tee-v1-guard.c
TEE_V1_DEPS = tee/tee-v1-segment.h tee/tee-v1-bitmap.h tee/tee-v1-guard.h $(TEE_V1_SRCS)
TEE_V2_SRCS = tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-hmac-group.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c tee/tee-v2-write.c tee/tee-v2-relocation.c
TEE_V2_DEPS = tee-ftl-v2-policy.h tee/tee-v2-format.h tee/tee-v2-active-metadata.h tee/tee-v2-hmac-group.h tee/tee-v2-passive-metadata.h tee/tee-v2-cache.h tee/tee-v2-write.h tee/tee-v2-relocation.h $(TEE_V2_SRCS)

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

tee-ftl-v2-policy.so: tee-ftl-v2-policy.c tee-ftl-v1-policy.c $(BLOCK_POLICY_DEPS) $(TEE_V1_DEPS) $(TEE_V2_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ tee-ftl-v2-policy.c lib/pqueue.c $(TEE_V1_SRCS) $(TEE_V2_SRCS)

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

test_tee_v2_format: tests/test_tee_v2_format.c tee/tee-v2-format.c tee/tee-v2-format.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_format.c tee/tee-v2-format.c

test_tee_v2_active_metadata: tests/test_tee_v2_active_metadata.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_active_metadata.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c

test_tee_v2_hmac_group: tests/test_tee_v2_hmac_group.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-hmac-group.c
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_hmac_group.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-hmac-group.c

test_tee_v2_passive_metadata: tests/test_tee_v2_passive_metadata.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-passive-metadata.c
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_passive_metadata.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-passive-metadata.c

test_tee_v2_cache: tests/test_tee_v2_cache.c $(TEE_V1_SRCS) tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_cache.c tee/tee-v1-bitmap.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c

test_tee_v2_write: tests/test_tee_v2_write.c $(TEE_V1_SRCS) $(TEE_V2_SRCS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_write.c tee/tee-v1-bitmap.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-hmac-group.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c tee/tee-v2-write.c

test_tee_v2_relocation: tests/test_tee_v2_relocation.c $(TEE_V1_SRCS) $(TEE_V2_SRCS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_relocation.c tee/tee-v1-bitmap.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c tee/tee-v2-relocation.c

test_tee_v2_flow: tests/test_tee_v2_flow.c $(TEE_V1_DEPS) $(TEE_V2_DEPS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_flow.c $(TEE_V1_SRCS) $(TEE_V2_SRCS)

test-tee-v2: test_tee_v2_format test_tee_v2_active_metadata test_tee_v2_hmac_group test_tee_v2_passive_metadata test_tee_v2_cache test_tee_v2_write test_tee_v2_relocation test_tee_v2_flow
	./test_tee_v2_format
	./test_tee_v2_active_metadata
	./test_tee_v2_hmac_group
	./test_tee_v2_passive_metadata
	./test_tee_v2_cache
	./test_tee_v2_write
	./test_tee_v2_relocation
	./test_tee_v2_flow

test: test-tee-v1 test-tee-v2

clean:
	rm -f $(POLICIES) test_tee_v1_segment test_tee_v1_bitmap test_tee_v1_guard test_tee_v1_flow test_tee_v2_format test_tee_v2_active_metadata test_tee_v2_hmac_group test_tee_v2_passive_metadata test_tee_v2_cache test_tee_v2_write test_tee_v2_relocation test_tee_v2_flow
