# Modified for SxSSD by Josh Dafoe.
# SxSSD modifications: 2025-12-04 through 2026-08-23.

# SxSSD uses Nettle directly for its GPLv2-compatible cryptographic primitives.
sxssd_nettle = dependency('nettle', version: '>= 3.6', required: true)
sxssd_hogweed = dependency('hogweed', version: '>= 3.6', required: true)

# Policy isolation uses the pinned WAMR Fast JIT runtime. Policies are
# freestanding Core Wasm modules and receive host functions only through the
# explicit common and privileged import namespaces. WAMR's Fast JIT requires
# its classic interpreter infrastructure for loading and module representation,
# but every policy instance executes exclusively in Fast JIT mode.
cmake_mod = import('cmake')
wamr_options = cmake_mod.subproject_options()
wamr_options.add_cmake_defines({
  'WAMR_BUILD_INTERP': '1',
  'WAMR_BUILD_FAST_INTERP': '0',
  'WAMR_BUILD_AOT': '0',
  'WAMR_BUILD_JIT': '0',
  'WAMR_BUILD_FAST_JIT': '1',
  'WAMR_BUILD_LIBC_BUILTIN': '0',
  'WAMR_BUILD_LIBC_WASI': '0',
  'WAMR_BUILD_MULTI_MODULE': '0',
  'WAMR_BUILD_LIB_PTHREAD': '0',
  'WAMR_BUILD_LIB_WASI_THREADS': '0',
  'WAMR_BUILD_SIMD': '0',
  'WAMR_BUILD_REF_TYPES': '0',
  'WAMR_BUILD_INSTRUCTION_METERING': '0',
  # FEMU requires explicit bounds checks below.  WAMR otherwise
  # prefers Linux hardware-trap bounds checking and forcibly reports the
  # configurable software checks as disabled.
  'WAMR_DISABLE_HW_BOUND_CHECK': '1',
  # WAMR otherwise writes the Wasm linear-memory base into x86 GS on every
  # interpreted call.  WAMR is an embedded library here, so it must not leave
  # process/thread CPU state changed when returning to FEMU/QEMU.
  'WAMR_DISABLE_WRITE_GS_BASE': '1',
  'WAMR_CONFIGURABLE_BOUNDS_CHECKS': '1',
  'WAMR_BUILD_SHRUNK_MEMORY': '0',
})
wamr_project = cmake_mod.subproject('wamr', options: wamr_options)
wamr = wamr_project.dependency('vmlib')
wamr_for_femu = wamr.partial_dependency(
  compile_args: false,
  includes: true,
  link_args: true,
  links: true,
)

meta_interface_wasm = custom_target(
  'meta-interface-policy-wasm',
  input: files('bbssd/meta-interface-policy.c'),
  output: 'meta-interface-policy.wasm',
  command: [
    files('bbssd/policy/build-meta-interface-wasm.sh'),
    '@OUTPUT@',
    '@INPUT@',
    files('bbssd/policy/privileged-wasm-imports.allow'),
  ],
  depend_files: files(
    'bbssd/meta-interface-protocol.h',
    'bbssd/policy/check-wasm-policy.sh',
    'bbssd/policy/generate-policy-import-allowlists.sh',
    'bbssd/policy/include/policy-imports.def',
    'bbssd/policy/include/policy-wasm-abi.h',
    'bbssd/policy/include/policy-privileged-wasm-abi.h',
  ),
)

meta_interface_embedded = custom_target(
  'meta-interface-policy-embedded',
  input: meta_interface_wasm,
  output: 'meta-interface-policy-embedded.c',
  command: [
    files('bbssd/policy/wasm-to-c.sh'),
    '@INPUT@',
    '@OUTPUT@',
    'pe_meta_interface_policy_wasm',
  ],
)

femu_ss = ss.source_set()
femu_ss.add(files('dma.c', 'intr.c', 'nvme-util.c', 'nvme-admin.c', 'nvme-io.c', 'femu.c', 'nossd/nop.c', 'nand/nand.c', 'timing-model/timing.c', 'ocssd/oc12.c', 'ocssd/oc20.c', 'zns/zns.c', 'zns/zftl.c', 'bbssd/bb.c', 'bbssd/bbm.c', 'bbssd/raw-flash.c', 'bbssd/device-trust.c', 'bbssd/policy-crypto.c', 'bbssd/policy-api.c', 'bbssd/policy-wamr.c', 'bbssd/policy-engine.c', 'lib/pqueue.c', 'lib/rte_ring.c', 'backend/dram.c'), meta_interface_embedded)
femu_ss.add(when: sxssd_nettle, if_true: sxssd_nettle)
femu_ss.add(when: sxssd_hogweed, if_true: sxssd_hogweed)
femu_ss.add(when: wamr_for_femu, if_true: wamr_for_femu)

system_ss.add_all(when: 'CONFIG_FEMU_PCI', if_true: femu_ss)
