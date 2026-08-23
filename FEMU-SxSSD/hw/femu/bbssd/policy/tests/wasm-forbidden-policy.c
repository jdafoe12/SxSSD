/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-wasm-abi.h"

/* This symbol is deliberately absent from the sxs_v1 import allowlist. */
extern sxs_u64 pe_test_forbidden_host_function(void);

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{ return (sxs_s32)pe_test_forbidden_host_function(); }
SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    return sxs_context_get(&context) == 0 && context.pair_id == pair_id;
}
SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{ (void)pair_id; return SXS_WASM_ACTION_ERROR; }
