#ifndef META_INTERFACE_POLICY_H
#define META_INTERFACE_POLICY_H

/* Host-visible vendor commands owned by the built-in meta-interface policy. */
#define SXS_NVME_ADMIN_INIT_SESSION_SUBMIT 0x93U
#define SXS_NVME_ADMIN_INIT_SESSION_FETCH 0x94U
#define SXS_NVME_ADMIN_INSTALL_POLICY 0x95U
#define SXS_NVME_ADMIN_DEACTIVATE_POLICY 0x97U
#define SXS_NVME_ADMIN_REMOVE_POLICY 0x99U
#define SXS_NVME_ADMIN_ATTESTATION_FETCH 0x9aU
#define SXS_NVME_ADMIN_ACTIVATE_POLICY 0x9bU
#define SXS_NVME_ADMIN_UPDATE_POLICY 0x9dU
#define SXS_NVME_ADMIN_ATTESTATION_SUBMIT 0x9fU

#define SXS_SESSION_MODE_NORMAL 0U
#define SXS_SESSION_MODE_CONFIDENTIAL 1U

#define SXS_INIT_SESSION_REQUEST_SIZE 105U
#define SXS_INIT_SESSION_RESPONSE_SIZE 104U

#define SXS_META_INTERFACE_POLICY_ID 0xffff0001U
#define SXS_META_INTERFACE_POLICY_VERSION 1U

#if !defined(__wasm__)
#include <stddef.h>
#include <stdint.h>

/* Generated in the build directory from meta-interface-policy.wasm. */
extern const uint8_t pe_meta_interface_policy_wasm[];
extern const size_t pe_meta_interface_policy_wasm_size;
#endif

#endif /* META_INTERFACE_POLICY_H */
