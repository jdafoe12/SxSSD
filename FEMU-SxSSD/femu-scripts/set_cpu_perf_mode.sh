#!/usr/bin/env bash
# Modified for SxSSD by Josh Dafoe.
# SxSSD modifications: 2026-04-29 through 2026-07-11.

set -u

echo "Placing all CPUs in performance mode..."

updated=0
skipped=0
failed=0

driver=""
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver ]]; then
    driver="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver)"
fi

# On many modern Intel systems with intel_pstate active, the preferred control
# path is power-profiles-daemon or the EPP interface rather than writing the
# governor sysfs file directly.
if [[ "$driver" == "intel_pstate" ]] && command -v powerprofilesctl >/dev/null 2>&1; then
    if sudo powerprofilesctl set performance; then
        echo "Set system power profile to performance via powerprofilesctl"
        exit 0
    fi
    echo "powerprofilesctl failed; falling back to sysfs writes" >&2
fi

epp_paths=(/sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference)
if [[ -e "${epp_paths[0]}" ]]; then
    for epp in "${epp_paths[@]}"; do
        if [[ ! -e "$epp" ]]; then
            skipped=$((skipped + 1))
            continue
        fi

        if echo performance | sudo tee "$epp" >/dev/null; then
            updated=$((updated + 1))
        else
            echo "Failed to set energy performance preference for $epp" >&2
            failed=$((failed + 1))
        fi
    done

    echo "Updated EPP: $updated, skipped: $skipped, failed: $failed"
    if [[ $failed -ne 0 ]]; then
        exit 1
    fi
    exit 0
fi

for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [[ ! -e "$governor" ]]; then
        skipped=$((skipped + 1))
        continue
    fi

    if echo performance | sudo tee "$governor" >/dev/null; then
        updated=$((updated + 1))
    else
        echo "Failed to set governor for $governor" >&2
        failed=$((failed + 1))
    fi
done

echo "Updated: $updated, skipped: $skipped, failed: $failed"

if [[ $failed -ne 0 ]]; then
    exit 1
fi
