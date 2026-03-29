#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
POLICY_ID="${2:-1}"
POLICY_VERSION="${3:-1}"

if [ ! -f ./block-interface-policy.so ]; then
    echo "Missing ./block-interface-policy.so. Build it on the host before copying this folder into the guest." >&2
    exit 1
fi

echo "Building guest-local policyctl..."
make tool

./policyctl install "$DEVICE" ./block-interface-policy.so "$POLICY_ID" "$POLICY_VERSION"
./policyctl activate "$DEVICE" "$POLICY_ID"

echo "Installed and activated block-interface-policy.so on $DEVICE"
