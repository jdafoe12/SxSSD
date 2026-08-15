# SxSSD implementation structure

The SxSSD implementation is divided into three conceptual parts: the policy
engine, the flash subsystem, and the built-in meta-interface policy. The
`struct ssd` object connects them, but it does not define an additional FTL
layer.

## Policy engine

- `policy-engine.c` and `policy-engine.h` own policy lifecycle, subscriptions,
  event dispatch, activation transactions, and per-execution context.
- `policy-wamr.c` and `policy-wamr.h` are the policy engine's private
  WebAssembly mechanism. They own WAMR initialization, module instances,
  execution, host-import adapters, and the explicit `NativeSymbol` tables.
- `policy-crypto.c` and `device-trust.c` provide focused services used by the
  policy engine and Policy API. Each policy keeps its mutable runtime state in
  its own WebAssembly linear memory.

WAMR is not part of the flash subsystem. A policy call crosses WAMR because
the policy runs in isolated WebAssembly memory. For example:

```text
policy calls sxs_geometry_get
  -> WAMR resolves "sxs_geometry_get" in the explicit NativeSymbol table
  -> import_geometry_get validates WASM memory
  -> policy_api_geometry_get reads the BBM geometry
  -> import_geometry_get copies the result into WASM memory
```

The declarations in `policy/policy-wasm-abi.h` are explicit. The WAMR wrappers
and `NativeSymbol` entries in `policy-wamr.c` are also explicit.
`policy/policy-imports.def` remains a compact ABI manifest for linker
allowlists and compile-time declaration checks; it does not generate the host
wrappers or runtime registration tables.

Each policy declares its own fixed linear-memory size when it is linked. The
policy engine accepts declarations up to 256 MiB and does not interpret or
copy policy-owned memory between calls. That memory lasts for the lifetime of
the WAMR instance and is discarded when the policy is deactivated. Policies
that require persistence across activation or power loss must define their own
on-flash representation and recovery behavior.

## Flash subsystem

The flash subsystem has the three layers described by the SxSSD design.

1. `policy-api.c` and `policy-api.h` are the top mechanism layer. They own the
   native implementation of policy operations, eSWD configuration and layout,
   request-buffer access, and the shared `struct ssd` state used to compose the
   subsystem.
2. `bbm.c` and `bbm.h` own pseudo-physical addressing, overprovisioned block
   mappings, policy-storage reservations, and translation to physical
   addresses.
3. `raw-flash.c` and `raw-flash.h` own physical media bytes, OOB bytes, page
   validity, erase counts, pSWD state, geometry, and NAND timing.

Calls move downward one layer at a time:

```text
policy_api_page_read
  -> native_read_physical_page
  -> native_read_page_buffer
  -> bbm_read
  -> raw_flash_read
```

Completed flash operations move upward through `BbmEventNotify`. BBM has no
policy-engine pointer and does not include `policy-engine.h`. Device setup in
`bb.c` connects the callback to `pe_dispatch_flash_event`. pSWD transitions
use a separate typed callback directly from raw flash because raw flash owns
that state machine.

`bb.c` owns controller construction and the request worker. This keeps device
composition out of the Policy API while retaining FEMU's existing broad
`struct ssd` object.

## Meta-interface policy

The meta-interface policy remains a privileged built-in WebAssembly policy.
It is fundamental device behavior, but it uses the same policy engine and
isolation boundary as installed policies. Its privileged import namespace is
registered explicitly in `policy-wamr.c`.

`meta-interface-protocol.h` is the shared wire contract used by the built-in
policy and host-side `policyctl`. It contains vendor command identifiers,
session constants, and the serialized attestation format. `device-trust.c`
and `device-trust.h` form one support component containing the simulator's
device identity and the narrowly scoped signing operations that use it.

## Evaluation-only changes

The final branch intentionally excludes evaluation counters and measurement
hooks from the runtime design. In particular, `enum sxs_stats_counter`, stats
imports, GC counters, timing-only policy calls, and evaluation-only policy
variants belong on the `evaluation` branch. They are observations of the
design, not requirements for correct SSD behavior.

Benchmark and workload scripts may remain shared when they do not change the
runtime ABI or device behavior. When updating the evaluation branch after this
refactor, add instrumentation at the new owner boundary:

- policy execution timing belongs in `policy-engine.c` or `policy-wamr.c`;
- Policy API operation counters belong in `policy-api.c`;
- BBM translation or operation counters belong in `bbm.c`;
- physical read, write, erase, and pSWD counters belong in `raw-flash.c`.

Do not reintroduce an `ftl.c` instrumentation layer. Keep evaluation imports
explicit in both the policy ABI declarations and the `NativeSymbol` tables,
and keep the production branch free of those imports.
