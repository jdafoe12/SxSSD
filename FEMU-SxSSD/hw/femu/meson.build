# OpenSSL dependency for meta-interface-policy crypto operations
openssl = dependency('openssl', version: '>= 1.1.1', required: true)
dl = cc.find_library('dl', required: false)

femu_ss = ss.source_set()
femu_ss.add(files('dma.c', 'intr.c', 'nvme-util.c', 'nvme-admin.c', 'nvme-io.c', 'femu.c', 'nossd/nop.c', 'nand/nand.c', 'timing-model/timing.c', 'ocssd/oc12.c', 'ocssd/oc20.c', 'zns/zns.c', 'zns/zftl.c','bbssd/bb.c', 'bbssd/bbm.c', 'bbssd/eswd-config.c', 'bbssd/eswd-layout.c', 'bbssd/ftl.c', 'bbssd/policy-engine.c', 'bbssd/meta-interface-policy.c', 'lib/pqueue.c', 'lib/rte_ring.c', 'backend/dram.c', 'backend/ftl-backend.c'))
femu_ss.add(when: openssl, if_true: openssl)
femu_ss.add(when: dl, if_true: dl)

system_ss.add_all(when: 'CONFIG_FEMU_PCI', if_true: femu_ss)
