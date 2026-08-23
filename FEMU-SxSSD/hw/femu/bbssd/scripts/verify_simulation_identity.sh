#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BBSSD_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

"$SCRIPT_DIR/test_device_signing" \
    "$BBSSD_DIR/ssd-keys/ssd_private.hex" \
    "$BBSSD_DIR/ssd-keys/ssd_public.hex" \
    "$BBSSD_DIR/manufacturer-simulation/manufacturer_private.hex" \
    "$BBSSD_DIR/manufacturer-simulation/manufacturer_public.hex" \
    "$BBSSD_DIR/manufacturer-simulation/ssd_pubkey.bin" \
    "$BBSSD_DIR/manufacturer-simulation/ssd_cert_sig.bin" \
    "$BBSSD_DIR/admin-simulation/admin_private.hex" \
    "$BBSSD_DIR/admin-simulation/admin_public.hex" \
    "$BBSSD_DIR/manufacturer-simulation/admin_pubkey.bin" \
    "$BBSSD_DIR/manufacturer-simulation/admin_cert_sig.bin"
echo "simulation identity verification passed"
