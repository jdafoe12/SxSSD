# OpenSSL dependency for meta-interface-policy crypto operations
openssl = dependency('openssl', version: '>= 1.1.1', required: true)

# Ordinary policy isolation uses the pinned userspace uBPF interpreter. Keep
# optional uBPF extras disabled; safe-profile selection is enforced by the
# policy VM wrapper at runtime.
cmake_mod = import('cmake')
ubpf_options = cmake_mod.subproject_options()
ubpf_options.add_cmake_defines({
  'UBPF_ENABLE_TESTS': 'OFF',
  'UBPF_ENABLE_INSTALL': 'OFF',
  'UBPF_ENABLE_PACKAGE': 'OFF',
  'UBPF_SKIP_EXTERNAL': 'ON',
})
ubpf_project = cmake_mod.subproject('ubpf', options: ubpf_options)
ubpf = ubpf_project.dependency('ubpf')
ubpf_for_femu = ubpf.partial_dependency(
  compile_args: false,
  includes: true,
  link_args: true,
  links: true,
)

femu_ss = ss.source_set()
femu_ss.add(files('dma.c', 'intr.c', 'nvme-util.c', 'nvme-admin.c', 'nvme-io.c', 'femu.c', 'nossd/nop.c', 'nand/nand.c', 'timing-model/timing.c', 'ocssd/oc12.c', 'ocssd/oc20.c', 'zns/zns.c', 'zns/zftl.c','bbssd/bb.c', 'bbssd/bbm.c', 'bbssd/eswd-config.c', 'bbssd/eswd-layout.c', 'bbssd/ftl.c', 'bbssd/device-signing.c', 'bbssd/policy-crypto.c', 'bbssd/policy-bpf-state.c', 'bbssd/policy-bpf-helpers.c', 'bbssd/policy-bpf-vm.c', 'bbssd/policy-engine.c', 'bbssd/meta-interface-policy.c', 'lib/pqueue.c', 'lib/rte_ring.c', 'backend/dram.c', 'backend/ftl-backend.c'))
femu_ss.add(when: openssl, if_true: openssl)
femu_ss.add(when: ubpf_for_femu, if_true: ubpf_for_femu)

system_ss.add_all(when: 'CONFIG_FEMU_PCI', if_true: femu_ss)
