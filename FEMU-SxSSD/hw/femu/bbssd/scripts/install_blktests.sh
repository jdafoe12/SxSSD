#!/bin/bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-}"
BLKTESTS_DIR="${BLKTESTS_DIR:-}"

fail() {
    echo "[install-blktests] ERROR: $*" >&2
    exit 1
}

note() {
    echo "[install-blktests] $*"
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
if [ -z "$BLKTESTS_DIR" ]; then
    BLKTESTS_DIR="$INSTALL_DIR/blktests"
fi

if [[ "$INSTALL_DIR" == \$HOME/* ]]; then
    INSTALL_DIR="${USER_HOME}${INSTALL_DIR#\$HOME}"
fi
if [[ "$BLKTESTS_DIR" == \$HOME/* ]]; then
    BLKTESTS_DIR="${USER_HOME}${BLKTESTS_DIR#\$HOME}"
fi

note "Installing blktests dependencies via apt"
apt update
apt install -y git fio nvme-cli uuid-runtime libaio-dev

mkdir -p "$INSTALL_DIR"
chown "$SUDO_USER_NAME":"$SUDO_USER_NAME" "$INSTALL_DIR"

if [ ! -d "$BLKTESTS_DIR/.git" ]; then
    note "Cloning blktests into $BLKTESTS_DIR"
    sudo -u "$SUDO_USER_NAME" git clone https://github.com/osandov/blktests.git "$BLKTESTS_DIR"
else
    note "Updating existing blktests checkout in $BLKTESTS_DIR"
    sudo -u "$SUDO_USER_NAME" git -C "$BLKTESTS_DIR" pull --ff-only
fi

note "Installed blktests source tree"
note "Run tests from: $BLKTESTS_DIR"
note "Example:"
note "  cd $BLKTESTS_DIR"
note "  cat > config <<'EOF'"
note "  TEST_DEVS=(/dev/nvme0n1)"
note "  RUN_ZONED_TESTS=1"
note "  QUICK_RUN=1"
note "  TIMEOUT=30"
note "  DEVICE_ONLY=1"
note "  EOF"
note "  sudo ./check block zbd"
