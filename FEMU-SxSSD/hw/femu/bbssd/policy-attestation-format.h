#ifndef SXS_POLICY_ATTESTATION_FORMAT_H
#define SXS_POLICY_ATTESTATION_FORMAT_H

/* All integers are little-endian. Multi-byte structs are serialized explicitly.
 *
 * Request (19 bytes): version:u8, report_type:u8, history_mode:u8, nonce[16].
 * Delta appends base_sequence:u64, for a total of 27 bytes.
 *
 * Response header (76 bytes): version:u8, report_type:u8, history_mode:u8,
 * policy_count:u8, snapshot_sequence:u64, boot_epoch[16], nonce[16],
 * history_head[32]. It is followed by policy entries, returned history records,
 * and an Ed25519 signature[64] over every preceding response byte.
 *
 * Security entry (9 bytes): policy_id:u32, generation:u32, active:u8.
 * Consistency entry (41 bytes): security entry, policy_sha256[32].
 * History record (9 bytes): operation:u8, policy_id:u32, generation:u32.
 * Its sequence is its one-based position in the complete per-boot history.
 */
#define POLICY_ATTESTATION_FORMAT_VERSION 1

#define POLICY_ATTESTATION_REPORT_SECURITY     1
#define POLICY_ATTESTATION_REPORT_CONSISTENCY  2

#define POLICY_ATTESTATION_HISTORY_CHECKPOINT  1
#define POLICY_ATTESTATION_HISTORY_DELTA       2
#define POLICY_ATTESTATION_HISTORY_FULL        3

#define POLICY_HISTORY_OP_INSTALL     1
#define POLICY_HISTORY_OP_UPDATE      2
#define POLICY_HISTORY_OP_ACTIVATE    3
#define POLICY_HISTORY_OP_DEACTIVATE  4
#define POLICY_HISTORY_OP_REMOVE      5

#define POLICY_ATTESTATION_NONCE_SIZE             16
#define POLICY_ATTESTATION_BOOT_EPOCH_SIZE        16
#define POLICY_ATTESTATION_HASH_SIZE              32
#define POLICY_ATTESTATION_SIGNATURE_SIZE         64
#define POLICY_ATTESTATION_REQUEST_SIZE           19
#define POLICY_ATTESTATION_DELTA_REQUEST_SIZE     27
#define POLICY_ATTESTATION_RESPONSE_HEADER_SIZE   76
#define POLICY_ATTESTATION_SECURITY_ENTRY_SIZE     9
#define POLICY_ATTESTATION_CONSISTENCY_ENTRY_SIZE 41
#define POLICY_ATTESTATION_HISTORY_RECORD_SIZE     9

#define POLICY_ATTESTATION_MAX_POLICIES 16

#endif /* SXS_POLICY_ATTESTATION_FORMAT_H */
