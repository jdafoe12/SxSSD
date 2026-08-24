# Upstream and licensing

SxSSD is a fork of [FEMU](https://github.com/MoatLab/FEMU), which is
based on [QEMU](https://www.qemu.org/).

SxSSD is based on FEMU commit:

```text
b3272c0130faa5fd04826303541a831731a8dfb2
```

The upstream Git history is preserved in this repository. SxSSD is hosted as
a standalone GitHub repository rather than through GitHub's fork network.

Most SxSSD-specific code is under `FEMU-SxSSD/hw/femu/bbssd/`. Some upstream
FEMU BlackBox SSD code, including the former `ftl.c` and `ftl.h`, was split
and reorganized there. Git history and file notices record that lineage.

## Dependencies

- [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) is included
  as a Git submodule at commit
  `6ab10571e7ca204a5dd958297de79f75d1ed6369` and retains its own license.
- Nettle and Hogweed are external build dependencies and are not included in
  this repository.
- Other bundled components retain their own license files and notices.

## Licensing

SxSSD-authored files and modifications are licensed under
`GPL-2.0-or-later`. The combined QEMU/FEMU/SxSSD emulator is distributed under
GNU GPL version 2. The complete license text is in `LICENSE`.

FEMU, QEMU, WAMR, and all other third-party components retain their original
licenses and copyright notices. Those notices must be preserved when the
project is redistributed.
