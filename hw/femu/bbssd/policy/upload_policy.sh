#!/bin/bash

# Simple script to upload policy to FEMU
# Usage: ./upload_policy.sh <policy.so> <device>

if [ $# -ne 2 ]; then
    echo "Usage: $0 <policy.so> <device>"
    echo "Example: $0 test-policy.so /dev/nvme0n1"
    exit 1
fi

POLICY_SO="$1"
DEVICE="$2"

# LPN addresses (from your FEMU config: tt_pgs_log = 3145728)
METADATA_LPN=3913728      # offset 0
INIT_TRIGGER_LPN=3913729  # offset 1
POLICY_START_LPN=3913744  # offset 16

echo "Step 1: Creating metadata..."
./create_metadata "$POLICY_SO" 1 test_policy metadata.bin

echo ""
echo "Step 2: Writing metadata..."
sudo dd if=metadata.bin of="$DEVICE" bs=4096 seek=$METADATA_LPN count=1

echo ""
echo "Step 3: Writing policy .so file..."
POLICY_SIZE=$(stat -c%s "$POLICY_SO")
POLICY_PAGES=$(( (POLICY_SIZE + 4095) / 4096 ))
sudo dd if="$POLICY_SO" of="$DEVICE" bs=4096 seek=$POLICY_START_LPN count=$POLICY_PAGES

echo ""
echo "Step 4: Triggering initialization..."
sudo dd if=/dev/zero of="$DEVICE" bs=4096 seek=$INIT_TRIGGER_LPN count=1

echo ""
echo "Done! Policy should be loaded."

