# Upstream lineage

SxSSD is an independent research fork of
[FEMU](https://github.com/MoatLab/FEMU), the Fast, Accurate, and Extensible
NVMe SSD Emulator. FEMU is itself based on [QEMU](https://www.qemu.org/).
SxSSD is not affiliated with or endorsed by the FEMU or QEMU maintainers.

## Canonical FEMU snapshot

The canonical FEMU snapshot incorporated into this repository is:

```text
commit:  b3272c0130faa5fd04826303541a831731a8dfb2
describe: femu-v9.0.1-23-gb3272c013
date:    2025-11-23
subject: Implement zone reset with erase latency (#178)
```

That snapshot includes FEMU's update to QEMU 10.1. The commit identifier,
rather than a version label, is the authoritative reference for reproducing
the upstream source used by SxSSD.

The repository preserves the underlying Git histories. In particular:

* `c382cef7e5ff46a244dc16e2376e72d2d053f6fe` relocated the upstream FEMU
  divergence snapshot into the combined research repository.
* `76e90d00fff8003dcccff4739f36a52df649cc4e` merged the preserved FEMU and
  earlier SxSSD development lineages into the canonical SxSSD history.

Consequently, SxSSD is a genuine Git derivative of FEMU even though the
GitHub repository may be hosted as a standalone project rather than being
attached to GitHub's formal FEMU fork network.

## What SxSSD changes

SxSSD retains FEMU/QEMU as the full-system NVMe emulation foundation and
substantially extends FEMU's BlackBox SSD mode. The principal SxSSD work is
under `FEMU-SxSSD/hw/femu/bbssd/` and includes:

* a layered raw-flash, bad-block-management, pSWD, and eSWD subsystem;
* an event-driven policy engine and policy-facing storage API;
* isolated WebAssembly policies executed with WAMR Fast JIT;
* block, stream, ZNS, and FlashGuard policy implementations;
* a privileged meta-interface policy for policy lifecycle management;
* authenticated management sessions, policy storage, and attestation; and
* host-side policy management and evaluation utilities.

The rest of `FEMU-SxSSD/` remains largely upstream FEMU/QEMU code, subject to
the modifications needed to compose and build SxSSD. Individual file history
is the final authority when a more precise provenance determination is
required.

## Policy-runtime lineage

The earlier uBPF policy-isolation prototype remains available in repository
history at commit `2f80b4559a79b264f5bac16d11fe6d30cbdb14a9`. Commit
`b4bc492f3` replaced that runtime with WAMR, and the canonical implementation
now uses WAMR Fast JIT. The historical development commits remain ancestors of
`main` even though their temporary branch names are not retained.

## BBSSD source reorganization

The upstream FEMU files `hw/femu/bbssd/ftl.c` and
`hw/femu/bbssd/ftl.h` no longer exist as standalone files in SxSSD. Their
functionality and portions of their implementation were reorganized into:

* `FEMU-SxSSD/hw/femu/bbssd/bb.c`;
* `FEMU-SxSSD/hw/femu/bbssd/policy-api.c` and `policy-api.h`;
* `FEMU-SxSSD/hw/femu/bbssd/raw-flash.c` and `raw-flash.h`; and
* the BBM geometry and address-management implementation in `bbm.c` and
  `bbm.h`.

An intermediate SxSSD layer, `hw/femu/backend/ftl-backend.c` and
`ftl-backend.h`, was introduced on 2025-12-04 and was renamed and refactored
into `hw/femu/bbssd/raw-flash.c` and `raw-flash.h` on 2026-08-14. The current
destination files carry notices recording this provenance. Other renamed or
consolidated SxSSD-authored files retain their lineage in Git and carry
`GPL-2.0-or-later` SPDX identifiers.

## WAMR dependency

SxSSD embeds the
[WebAssembly Micro Runtime](https://github.com/bytecodealliance/wasm-micro-runtime)
as a pinned Git submodule:

```text
path:    FEMU-SxSSD/subprojects/wamr
commit:  6ab10571e7ca204a5dd958297de79f75d1ed6369
version: WAMR-2.4.5-1-g6ab10571
subject: Fix configurable bounds checks during dispatch setup
```

This post-2.4.5 commit is intentional: SxSSD requires its configurable
bounds-check correction. WAMR retains its own history and its
`Apache-2.0 WITH LLVM-exception` license.

## Upstream maintenance

SxSSD is maintained as a research system rather than as a patch queue that is
expected to merge directly into FEMU. Upstream FEMU fixes should be evaluated
and imported deliberately against the canonical snapshot. Generally useful
FEMU or QEMU fixes should be proposed to their respective upstream projects
separately when practical.

Maintainers may configure a local upstream remote with:

```bash
git remote add femu-upstream https://github.com/MoatLab/FEMU.git
git fetch femu-upstream
```

Git remotes are local configuration and are not inherited by repository
clones; the snapshot recorded above remains the public provenance reference.

## Attribution and citation

Publications and artifacts using this repository should cite both SxSSD and
the FEMU paper on which its emulation environment is based:

```bibtex
@inproceedings{Li2018FEMU,
  author    = {Huaicheng Li and Mingzhe Hao and Michael Hao Tong and
               Swaminathan Sundararaman and Matias Bj{\o}rling and
               Haryadi S. Gunawi},
  title     = {The CASE of FEMU: Cheap, Accurate, Scalable and Extensible
               Flash Emulator},
  booktitle = {16th USENIX Conference on File and Storage Technologies
               (FAST 18)},
  year      = {2018}
}
```

The SxSSD citation will be added when a public archival publication record is
available.

## Licensing

Copyright (C) 2025-2026 Josh Dafoe.

SxSSD-authored files and modifications are licensed under the GNU General
Public License, version 2 or (at your option) any later version:

    SPDX-License-Identifier: GPL-2.0-or-later

The combined QEMU/FEMU/SxSSD emulator is distributed as a whole under GNU GPL
version 2. The root `LICENSE` contains the complete, unmodified GNU GPL
version 2 text. This does not relicense third-party work:

* FEMU and QEMU retain their upstream licenses and per-file notices. See
  `FEMU-SxSSD/LICENSE`, `FEMU-SxSSD/COPYING`, and
  `FEMU-SxSSD/COPYING.LIB`.
* WAMR retains its `Apache-2.0 WITH LLVM-exception` license. See
  `FEMU-SxSSD/subprojects/wamr/LICENSE`.
* SxSSD links the external Nettle and Hogweed libraries under their GNU
  GPL version 2 or later licensing alternative. They are not vendored in this
  repository; see <https://www.lysator.liu.se/~nisse/nettle/>.
* Other bundled firmware, headers, libraries, tests, and subprojects retain
  the licenses identified by their own files and notices.

When distributing source or binaries, preserve the applicable notices and
comply with the terms for every included component.
