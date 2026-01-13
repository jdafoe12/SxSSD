#!/bin/bash

# Simple compilation script for policies
# Usage: ./compile.sh <policy.c>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <policy.c>"
    echo "Example: $0 test-policy.c"
    exit 1
fi

POLICY_C="$1"
POLICY_SO="${POLICY_C%.c}.so"

echo "Compiling $POLICY_C -> $POLICY_SO"
gcc -shared -fPIC -o "$POLICY_SO" "$POLICY_C" -I.

if [ $? -eq 0 ]; then
    echo "Success! Created $POLICY_SO"
else
    echo "Compilation failed!"
    exit 1
fi

