# SxSSD: A Secure and eXtensible Software-defined Solid State Drive

This branch contains the standalone SxSSD implementation. The source tree is
under [`FEMU-SxSSD/`](FEMU-SxSSD/), with the main SxSSD-specific code under
`FEMU-SxSSD/hw/femu/bbssd/`.

The repository's `evaluation` branch adds the comparison FEMU implementation,
measurement instrumentation, workload drivers, and figure-generation tools
used to collect evaluation data. Those components are intentionally excluded
from `main`.

## Build

The build should run on Ubuntu 20.04 LTS or newer.

```bash
cd FEMU-SxSSD
mkdir -p build-femu
cd build-femu
cp ../femu-scripts/femu-copy-scripts.sh .
./femu-copy-scripts.sh .
./femu-compile.sh
```

See [`FEMU-SxSSD/README.md`](FEMU-SxSSD/README.md) for FEMU's detailed build,
configuration, and usage documentation.

## SxSSD components

- `FEMU-SxSSD/hw/femu/bbssd/`: SxSSD storage and extensibility implementation
- `FEMU-SxSSD/hw/femu/bbssd/policy/`: implemented storage policies
- `FEMU-SxSSD/hw/femu/bbssd/scripts/`: policy and meta-interface utilities

## License

See [`LICENSE`](LICENSE) and the licensing files within `FEMU-SxSSD/`.
