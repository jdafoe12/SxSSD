CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I. -Iinc
POLICY_LDFLAGS = -shared

POLICIES = block-interface-policy-eval.so block-interface-policy-baseline.so block-interface-policy-flashguard.so block-interface-flashguard-policy.so zns-policy.so signing-test-policy.so key-sharing-policy.so tee-ftl-v1-policy.so tee-ftl-v2-policy.so tee-ftl-v3-policy.so tee-ftl-v4-policy.so

.PHONY: all clean
.PHONY: tool
.PHONY: test test-tee-v1 test-tee-v2 test-tee-v3 test-tee-v3-storage test-tee-v3-read test-tee-v3-proof-timeout test-tee-v4 test-tee-v4-admin-format test-tee-v4-admin-response test-tee-v4-writeback test-tee-v4-admin test-tee-v4-policy-flow test-tee-v4-metadata-intake test-tee-v5 test-tee-v5-status test-tee-v5-admin-format test-tee-v5-admin test-tee-v5-proof test-tee-v5-delete test-tee-v5-policy-flow

all: $(POLICIES)

tool: $(POLICIES)

BLOCK_POLICY_DEPS = block-interface-policy.h block-interface-policy-state.h femu_policy.h inc/pqueue.h inc/qtailq.h lib/pqueue.c
TEE_V1_SRCS = tee/tee-v1-segment.c tee/tee-v1-bitmap.c tee/tee-v1-guard.c
TEE_V1_DEPS = tee/tee-v1-segment.h tee/tee-v1-bitmap.h tee/tee-v1-guard.h $(TEE_V1_SRCS)
TEE_V2_SRCS = tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-hmac-group.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c tee/tee-v2-write.c tee/tee-v2-relocation.c
TEE_V2_DEPS = tee-ftl-v2-policy.h tee/tee-v2-format.h tee/tee-v2-active-metadata.h tee/tee-v2-hmac-group.h tee/tee-v2-passive-metadata.h tee/tee-v2-cache.h tee/tee-v2-write.h tee/tee-v2-relocation.h $(TEE_V2_SRCS)
TEE_V3_SRCS = tee/tee-v3-storage.c tee/tee-v3-read.c tee/tee-v3-proof.c tee/tee-v3-policy.c
TEE_V3_DEPS = tee-ftl-v3-policy.h tee/tee-v3-storage.h tee/tee-v3-read.h tee/tee-v3-proof.h tee/tee-v3-policy.h $(TEE_V3_SRCS)
TEE_V4_SRCS = tee/tee-v4-admin-format.c tee/tee-v4-admin-response.c tee/tee-v4-writeback.c tee/tee-v4-admin.c
TEE_V4_DEPS = tee-ftl-v4-policy.h tee/tee-v4-admin-format.h tee/tee-v4-admin-response.h tee/tee-v4-writeback.h tee/tee-v4-admin.h $(TEE_V4_SRCS)
TEE_V5_STATUS_SRCS = tee/tee-v5-status.c
TEE_V5_PROOF_SRCS = tee/tee-v5-proof.c

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

tee-ftl-v3-policy.so: tee-ftl-v3-policy.c tee-ftl-v1-policy.c $(BLOCK_POLICY_DEPS) $(TEE_V1_DEPS) $(TEE_V2_DEPS) $(TEE_V3_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ tee-ftl-v3-policy.c lib/pqueue.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) $(TEE_V3_SRCS)

tee-ftl-v4-policy.so: tee-ftl-v4-policy.c tee-ftl-v3-policy.c tee-ftl-v1-policy.c $(BLOCK_POLICY_DEPS) $(TEE_V1_DEPS) $(TEE_V2_DEPS) $(TEE_V3_DEPS) $(TEE_V4_DEPS)
	$(CC) $(CFLAGS) $(POLICY_LDFLAGS) -o $@ tee-ftl-v4-policy.c lib/pqueue.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) $(TEE_V3_SRCS) $(TEE_V4_SRCS)

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

test_tee_v2_media_status: tests/test_tee_v2_media_status.c ../ftl-write-status.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v2_media_status.c

test-tee-v2: test_tee_v2_format test_tee_v2_active_metadata test_tee_v2_hmac_group test_tee_v2_passive_metadata test_tee_v2_cache test_tee_v2_write test_tee_v2_relocation test_tee_v2_flow test_tee_v2_media_status
	./test_tee_v2_format
	./test_tee_v2_active_metadata
	./test_tee_v2_hmac_group
	./test_tee_v2_passive_metadata
	./test_tee_v2_cache
	./test_tee_v2_write
	./test_tee_v2_relocation
	./test_tee_v2_flow
	./test_tee_v2_media_status

test: test-tee-v1 test-tee-v2 test-tee-v3 test-tee-v4 test-tee-v5

test_tee_v3_storage: tests/test_tee_v3_storage.c tee/tee-v3-storage.c tee/tee-v3-storage.h $(TEE_V1_SRCS) tee/tee-v2-passive-metadata.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v3_storage.c tee/tee-v1-segment.c tee/tee-v1-bitmap.c tee/tee-v3-storage.c

test-tee-v3-storage: test_tee_v3_storage
	./test_tee_v3_storage

test_tee_v3_read: tests/test_tee_v3_read.c tee/tee-v3-read.c tee/tee-v3-read.h tee/tee-v2-passive-metadata.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v3_read.c tee/tee-v3-read.c

test-tee-v3-read: test_tee_v3_read
	./test_tee_v3_read

test_tee_v3_proof_timeout: tests/test_tee_v3_proof_timeout.c tee/tee-v3-proof.c tee/tee-v3-proof.h $(TEE_V1_SRCS) $(TEE_V2_SRCS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v3_proof_timeout.c tee/tee-v1-bitmap.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c tee/tee-v2-write.c tee/tee-v2-hmac-group.c tee/tee-v3-proof.c

test-tee-v3-proof-timeout: test_tee_v3_proof_timeout
	./test_tee_v3_proof_timeout

test_tee_v3_flow: tests/test_tee_v3_flow.c tee/tee-v3-policy.c tee/tee-v3-policy.h $(TEE_V1_SRCS) $(TEE_V2_SRCS) tee/tee-v3-storage.c tee/tee-v3-read.c tee/tee-v3-proof.c
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v3_flow.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) tee/tee-v3-storage.c tee/tee-v3-read.c tee/tee-v3-proof.c tee/tee-v3-policy.c

test-tee-v3: test-tee-v3-storage test-tee-v3-read test-tee-v3-proof-timeout test_tee_v3_flow
	./test_tee_v3_flow

test_tee_v4_admin_format: tests/test_tee_v4_admin_format.c $(TEE_V4_DEPS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v4_admin_format.c tee/tee-v4-admin-format.c

test-tee-v4-admin-format: test_tee_v4_admin_format
	./test_tee_v4_admin_format

test_tee_v4_admin_response: tests/test_tee_v4_admin_response.c $(TEE_V4_DEPS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v4_admin_response.c tee/tee-v4-admin-format.c tee/tee-v4-admin-response.c

test-tee-v4-admin-response: test_tee_v4_admin_response
	./test_tee_v4_admin_response

test_tee_v4_writeback: tests/test_tee_v4_writeback.c tee/tee-v4-writeback.c tee/tee-v4-writeback.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v4_writeback.c tee/tee-v4-writeback.c

test-tee-v4-writeback: test_tee_v4_writeback
	./test_tee_v4_writeback

test_tee_v4_admin: tests/test_tee_v4_admin.c $(TEE_V1_DEPS) $(TEE_V2_DEPS) $(TEE_V3_DEPS) $(TEE_V4_DEPS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v4_admin.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) $(TEE_V3_SRCS) tee/tee-v4-admin-format.c tee/tee-v4-admin-response.c tee/tee-v4-writeback.c tee/tee-v4-admin.c

test-tee-v4-admin: test_tee_v4_admin
	./test_tee_v4_admin

test_tee_v4_policy_flow: tests/test_tee_v4_policy_flow.c tee-ftl-v4-policy.c tee-ftl-v1-policy.c $(BLOCK_POLICY_DEPS) $(TEE_V1_DEPS) $(TEE_V2_DEPS) $(TEE_V3_DEPS) $(TEE_V4_DEPS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v4_policy_flow.c lib/pqueue.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) $(TEE_V3_SRCS) $(TEE_V4_SRCS)

test-tee-v4-policy-flow: test_tee_v4_policy_flow
	./test_tee_v4_policy_flow

test_tee_v4_metadata_intake: tests/test_tee_v4_metadata_intake.c $(TEE_V1_DEPS) $(TEE_V2_DEPS) $(TEE_V3_DEPS) $(TEE_V4_DEPS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v4_metadata_intake.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) $(TEE_V3_SRCS) $(TEE_V4_SRCS)

test-tee-v4-metadata-intake: test_tee_v4_metadata_intake
	./test_tee_v4_metadata_intake

test-tee-v4: test-tee-v4-admin-format test-tee-v4-admin-response test-tee-v4-writeback test-tee-v4-admin test-tee-v4-policy-flow test-tee-v4-metadata-intake

test_tee_v5_status: tests/test_tee_v5_status.c tee/tee-v5-status.h $(TEE_V5_STATUS_SRCS) femu_policy.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v5_status.c $(TEE_V5_STATUS_SRCS)

test-tee-v5-status: test_tee_v5_status
	./test_tee_v5_status

test_tee_v5_admin_format: tests/test_tee_v5_admin_format.c tee/tee-v5-admin-format.h tee/tee-v4-admin-format.h
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v5_admin_format.c tee/tee-v5-admin-format.c tee/tee-v4-admin-format.c

test-tee-v5-admin-format: test_tee_v5_admin_format
	./test_tee_v5_admin_format

test_tee_v5_admin: tests/test_tee_v5_admin.c tee/tee-v5-admin.h tee/tee-v5-admin.c tee/tee-v5-admin-format.h tee/tee-v5-status.h $(TEE_V1_DEPS) $(TEE_V2_DEPS) $(TEE_V3_DEPS) $(TEE_V4_DEPS) $(TEE_V5_STATUS_SRCS) $(TEE_V5_PROOF_SRCS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v5_admin.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) $(TEE_V3_SRCS) $(TEE_V4_SRCS) $(TEE_V5_STATUS_SRCS) $(TEE_V5_PROOF_SRCS) tee/tee-v5-admin-format.c tee/tee-v5-admin.c

test-tee-v5-admin: test_tee_v5_admin
	./test_tee_v5_admin

test_tee_v5_proof: tests/test_tee_v5_proof.c tee/tee-v5-proof.h $(TEE_V5_PROOF_SRCS) tee/tee-v3-proof.h tee/tee-v3-proof.c $(TEE_V1_SRCS) $(TEE_V2_SRCS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v5_proof.c $(TEE_V5_PROOF_SRCS) tee/tee-v3-proof.c tee/tee-v1-bitmap.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-hmac-group.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c tee/tee-v2-write.c

test-tee-v5-proof: test_tee_v5_proof
	./test_tee_v5_proof

test_tee_v5_delete: tests/test_tee_v5_delete.c tee/tee-v5-delete.h tee/tee-v5-delete.c $(TEE_V1_DEPS) $(TEE_V2_DEPS)
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v5_delete.c tee/tee-v1-bitmap.c tee/tee-v2-format.c tee/tee-v2-active-metadata.c tee/tee-v2-passive-metadata.c tee/tee-v2-cache.c tee/tee-v5-delete.c

test-tee-v5-delete: test_tee_v5_delete
	./test_tee_v5_delete

test_tee_v5_policy_flow: tests/test_tee_v5_policy_flow.c tee-ftl-v5-policy.c tee-ftl-v4-policy.c tee-ftl-v1-policy.c $(BLOCK_POLICY_DEPS) $(TEE_V1_DEPS) $(TEE_V2_DEPS) $(TEE_V3_DEPS) $(TEE_V4_DEPS) tee/tee-v5-status.c tee/tee-v5-admin-format.c tee/tee-v5-admin.c tee/tee-v5-proof.c tee/tee-v5-delete.c
	$(CC) $(CFLAGS) -o $@ tests/test_tee_v5_policy_flow.c lib/pqueue.c $(TEE_V1_SRCS) $(TEE_V2_SRCS) $(TEE_V3_SRCS) $(TEE_V4_SRCS) tee/tee-v5-status.c tee/tee-v5-admin-format.c tee/tee-v5-admin.c tee/tee-v5-proof.c tee/tee-v5-delete.c

test-tee-v5-policy-flow: test_tee_v5_policy_flow
	./test_tee_v5_policy_flow

test-tee-v5: test-tee-v5-status test-tee-v5-admin-format test-tee-v5-admin test-tee-v5-proof test-tee-v5-delete test-tee-v5-policy-flow

clean:
	rm -f $(POLICIES) test_tee_v1_segment test_tee_v1_bitmap test_tee_v1_guard test_tee_v1_flow test_tee_v2_format test_tee_v2_active_metadata test_tee_v2_hmac_group test_tee_v2_passive_metadata test_tee_v2_cache test_tee_v2_write test_tee_v2_relocation test_tee_v2_flow test_tee_v2_media_status test_tee_v3_storage test_tee_v3_read test_tee_v3_proof_timeout test_tee_v3_flow test_tee_v4_admin_format test_tee_v4_admin_response test_tee_v4_writeback test_tee_v4_admin test_tee_v4_policy_flow test_tee_v4_metadata_intake test_tee_v5_status test_tee_v5_admin_format test_tee_v5_admin test_tee_v5_proof test_tee_v5_delete test_tee_v5_policy_flow
