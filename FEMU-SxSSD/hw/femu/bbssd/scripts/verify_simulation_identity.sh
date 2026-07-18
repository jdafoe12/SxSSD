#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BBSSD_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

openssl pkey -in "$BBSSD_DIR/ssd-keys/ssd_private.pem" \
    -pubout -outform DER -out "$TMP_DIR/ssd-derived.der"
openssl pkey -pubin -in "$BBSSD_DIR/ssd-keys/ssd_public.pem" \
    -outform DER -out "$TMP_DIR/ssd-public.der"
cmp "$TMP_DIR/ssd-derived.der" "$TMP_DIR/ssd-public.der"
tail -c 32 "$TMP_DIR/ssd-public.der" > "$TMP_DIR/ssd-public.bin"
cmp "$TMP_DIR/ssd-public.bin" \
    "$BBSSD_DIR/manufacturer-simulation/ssd_pubkey.bin"

openssl pkey -in "$BBSSD_DIR/admin-simulation/admin_private.pem" \
    -pubout -outform DER -out "$TMP_DIR/admin-derived.der"
openssl pkey -pubin -in "$BBSSD_DIR/admin-simulation/admin_public.pem" \
    -outform DER -out "$TMP_DIR/admin-public.der"
cmp "$TMP_DIR/admin-derived.der" "$TMP_DIR/admin-public.der"
tail -c 32 "$TMP_DIR/admin-public.der" > "$TMP_DIR/admin-public.bin"
cmp "$TMP_DIR/admin-public.bin" \
    "$BBSSD_DIR/manufacturer-simulation/admin_pubkey.bin"

"$SCRIPT_DIR/test_device_signing" \
    "$BBSSD_DIR/manufacturer-simulation/ssd_pubkey.bin" \
    "$BBSSD_DIR/manufacturer-simulation/manufacturer_public.pem" \
    "$BBSSD_DIR/manufacturer-simulation/ssd_cert_sig.bin" \
    "$BBSSD_DIR/manufacturer-simulation/admin_pubkey.bin" \
    "$BBSSD_DIR/manufacturer-simulation/admin_cert_sig.bin"
echo "simulation identity verification passed"
