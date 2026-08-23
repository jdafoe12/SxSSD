#!/bin/bash
# Modified for SxSSD by Josh Dafoe.
# SxSSD modifications: 2026-07-18 through 2026-08-23.

# Huaicheng <huaicheng@cs.uchicago.edu>
# Please run this script as root.

SYSTEM=`uname -s`

if [[ -f /etc/debian_version ]]; then
	# Includes Ubuntu, Debian
    apt-get install -y gcc pkg-config git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libdw-dev
    apt-get install -y libaio-dev libslirp-dev

	# Additional dependencies
	apt-get install -y libnuma-dev
    # WAMR policy runtime and freestanding wasm32 policy toolchain.
    apt-get install -y clang lld llvm cmake ninja-build nettle-dev
else
    echo "pkgdep: unsupported system type ($SYSTEM), please install QEMU depencies manually"
	exit 1
fi

echo "===> Dependency installation ... Done!"
