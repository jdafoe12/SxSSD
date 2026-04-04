#!/bin/bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-}"
XNVME_DIR="${XNVME_DIR:-}"

fail() {
    echo "[install-xnvme] ERROR: $*" >&2
    exit 1
}

note() {
    echo "[install-xnvme] $*"
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

SUDO_USER_NAME="${SUDO_USER:-}"
[ -n "$SUDO_USER_NAME" ] || fail "SUDO_USER is not set"
USER_HOME="$(getent passwd "$SUDO_USER_NAME" | cut -d: -f6)"
[ -n "$USER_HOME" ] || fail "Failed to determine home for $SUDO_USER_NAME"

if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="$USER_HOME/tools"
fi
if [ -z "$XNVME_DIR" ]; then
    XNVME_DIR="$INSTALL_DIR/xnvme"
fi

if [[ "$INSTALL_DIR" == \$HOME/* ]]; then
    INSTALL_DIR="${USER_HOME}${INSTALL_DIR#\$HOME}"
fi
if [[ "$XNVME_DIR" == \$HOME/* ]]; then
    XNVME_DIR="${USER_HOME}${XNVME_DIR#\$HOME}"
fi

note "Installing xNVMe build dependencies via apt"
apt update
apt install -y git python3 python3-pip python3-venv meson ninja-build build-essential \
    liburing-dev libaio-dev pkg-config libnuma-dev uuid-dev libssl-dev

mkdir -p "$INSTALL_DIR"
chown "$SUDO_USER_NAME":"$SUDO_USER_NAME" "$INSTALL_DIR"

if [ ! -d "$XNVME_DIR/.git" ]; then
    note "Cloning xNVMe into $XNVME_DIR"
    sudo -u "$SUDO_USER_NAME" git clone https://github.com/xnvme/xnvme.git "$XNVME_DIR"
else
    note "Updating existing xNVMe checkout in $XNVME_DIR"
    sudo -u "$SUDO_USER_NAME" git -C "$XNVME_DIR" pull --ff-only
fi

note "Building xNVMe"
sudo -u "$SUDO_USER_NAME" rm -rf "$XNVME_DIR/builddir"
sudo -u "$SUDO_USER_NAME" meson setup "$XNVME_DIR/builddir" "$XNVME_DIR"
sudo -u "$SUDO_USER_NAME" meson compile -C "$XNVME_DIR/builddir"

note "Installing xNVMe"
meson install -C "$XNVME_DIR/builddir"

note "Installed xNVMe"
xnvme --help >/dev/null 2>&1 || fail "xnvme command is not available after install"
note "xnvme is available"
