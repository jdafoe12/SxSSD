#!/bin/bash

usage() {
    cat <<EOF
Usage: $0 [--eval]

  --eval    Build FEMU with the evaluation statistics interface enabled.
EOF
}

extra_cflags=""

case "${1:-}" in
    "")
        ;;
    --eval)
        extra_cflags="-DFEMU_EVAL"
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac

NRCPUS="$(cat /proc/cpuinfo | grep "vendor_id" | wc -l)"
configure_args=(
    --enable-kvm
    --target-list=x86_64-softmmu
    --enable-slirp
    --disable-werror
)

if [[ -n "$extra_cflags" ]]; then
    configure_args+=("--extra-cflags=$extra_cflags")
fi

make clean
# Keep newer compiler warnings from turning an otherwise valid FEMU build
# into a hard failure (for example, bundled DTC with GCC 16).
../configure "${configure_args[@]}"
make -j $NRCPUS

echo ""
echo "===> FEMU compilation done ..."
echo ""
exit
