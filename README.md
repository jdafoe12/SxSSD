# SxSSD

SxSSD is a research prototype of a secure and extensible solid state drive. It is
built on [FEMU](https://github.com/MoatLab/FEMU) and uses WebAssembly Micro
Runtime (WAMR) to execute device-side policies with JIT compilation.

## Repository layout

- `FEMU-SxSSD/` contains the FEMU/QEMU source tree used by SxSSD.
- `FEMU-SxSSD/hw/femu/bbssd/` contains the main SxSSD implementation.
- `FEMU-SxSSD/hw/femu/bbssd/policy/` contains the policy code.
- `FEMU-SxSSD/hw/femu/bbssd/scripts/` contains policy-management tools and
  tests.
- `FEMU-SxSSD/subprojects/wamr/` is the WAMR Git submodule.

The fixed keys under the BBSSD simulation directories are intentionally public
test fixtures. They are not secret or production credentials.

See [`UPSTREAM.md`](UPSTREAM.md) for FEMU/QEMU
lineage and third-party dependency provenance.

## Getting the source

Clone the repository with its submodules:

```bash
git clone --recurse-submodules <SxSSD repository URL>
cd SxSSD
```

For an existing clone:

```bash
git submodule update --init --recursive
```

## Building

The build and execution instructions are available in
[`FEMU-SxSSD/README.md`](FEMU-SxSSD/README.md).

## License

Copyright (C) 2025-2026 Josh Dafoe.

SxSSD-authored files and modifications are licensed under
`GPL-2.0-or-later`. FEMU, QEMU, WAMR, and other third-party components retain
their upstream licenses. See [`LICENSE`](LICENSE) and
[`UPSTREAM.md`](UPSTREAM.md).

SxSSD is distributed without any warranty; see `LICENSE` for details.
