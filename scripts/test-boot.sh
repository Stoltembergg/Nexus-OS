#!/usr/bin/env bash
# Nexus OS - Phase 2 Automated Bare-Metal UEFI Boot & Process Execution Test (Bash)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
OVMF_PATH="${OVMF_PATH:-/usr/share/ovmf/OVMF.fd}"
TIMEOUT_SEC="${TIMEOUT_SEC:-15}"

echo "============================================================"
echo "    Nexus OS - Phase 2 Real Process Execution & VMM Test    "
echo "============================================================"

# 1. Build UEFI Bootloader and Kernel
echo "[1/4] Compiling nexus-boot for x86_64-unknown-uefi..."
cargo build -p nexus-boot --target x86_64-unknown-uefi

EFI_SOURCE="${WORKSPACE_ROOT}/target/x86_64-unknown-uefi/debug/bootx64.efi"
if [[ ! -f "${EFI_SOURCE}" ]]; then
    echo "Error: bootx64.efi not found at ${EFI_SOURCE}" >&2
    exit 1
fi

# 2. Stage EFI System Partition (ESP)
echo "[2/4] Staging ESP directory structure..."
BUILD_DIR="${WORKSPACE_ROOT}/build"
ESP_DIR="${BUILD_DIR}/esp"
BOOT_DIR="${ESP_DIR}/EFI/BOOT"
mkdir -p "${BOOT_DIR}"
cp "${EFI_SOURCE}" "${BOOT_DIR}/BOOTX64.EFI"

# Stage startup.nsh
printf "FS0:\r\n\\EFI\\BOOT\\BOOTX64.EFI\r\n" > "${ESP_DIR}/startup.nsh"

LOG_FILE="${BUILD_DIR}/boot_serial.log"
rm -f "${LOG_FILE}"

# 3. Launch QEMU
echo "[3/4] Launching QEMU with OVMF UEFI firmware..."
timeout "${TIMEOUT_SEC}s" "${QEMU_BIN}" \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_PATH}" \
    -drive "file=fat:rw:${ESP_DIR},format=raw" \
    -vga std \
    -display none \
    -serial stdio \
    -no-reboot > "${LOG_FILE}" 2>&1 || true

# 4. Verify Boot Output
echo "[4/4] Validating Serial Boot Logs..."
cat "${LOG_FILE}"

if grep -q "NEXUS_PHASE2_SUCCESS" "${LOG_FILE}" && \
   grep -q "MILESTONE 1 VERIFIED" "${LOG_FILE}" && \
   grep -q "MILESTONE 2 VERIFIED" "${LOG_FILE}" && \
   grep -q "PMM & VMM Active" "${LOG_FILE}"; then
    echo -e "\033[0;32m[+] REAL PROCESS EXECUTION & VMM TEST PASSED: All Phase 2 milestones verified.\033[0m"
    exit 0
else
    echo -e "\033[0;31m[!] Test Failed: Expected Phase 2 boot milestones missing from log.\033[0m" >&2
    exit 1
fi
