#!/bin/bash

NRCPUS="$(cat /proc/cpuinfo | grep "vendor_id" | wc -l)"

make clean
# Keep newer compiler warnings from turning an otherwise valid FEMU build
# into a hard failure (for example, bundled DTC with GCC 16).
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-werror
make -j $NRCPUS

echo ""
echo "===> FEMU compilation done ..."
echo ""
exit
