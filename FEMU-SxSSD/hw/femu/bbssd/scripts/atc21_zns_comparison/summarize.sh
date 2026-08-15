#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_ROOT="${RESULTS_ROOT:-$HOME/atc21-zns-results}"

exec python3 "$SCRIPT_DIR/summarize.py" "$RESULTS_ROOT"
