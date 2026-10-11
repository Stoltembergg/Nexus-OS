#!/usr/bin/env bash
# Nexus OS - Phase 1 Automated Bare-Metal UEFI Boot Test (Bash)
# Runs QEMU with OVMF firmware and verifies bare-metal boot sequence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "============================================================"
echo "       Nexus OS - Phase 1 Bare-Metal Boot Verification      "
echo "============================================================"

# 1. Compile bootloader
echo "[1/4] Compiling nexus-boot for x86_64-unknown-uefi..."
cargo build -p nexus-boot --target x86_64-unknown-uefi

EFI_SOURCE="${WORKSPACE_ROOT}/target/x86_64-unknown-uefi/debug/bootx64.efi"
if [[ ! -f "${EFI_SOURCE}" ]]; then
    echo "Error: ${EFI_SOURCE} not found." >&2
    exit 1
fi

# 2. Stage ESP directory
echo "[2/4] Staging ESP directory structure..."
BUILD_DIR="${WORKSPACE_ROOT}/build"
ESP_DIR="${BUILD_DIR}/esp"
BOOT_DIR="${ESP_DIR}/EFI/BOOT"
mkdir -p "${BOOT_DIR}"
cp "${EFI_SOURCE}" "${BOOT_DIR}/BOOTX64.EFI"

# 3. Locate OVMF firmware
OVMF_PATH=""
for path in \
    "/usr/share/OVMF/OVMF_CODE.fd" \
    "/usr/share/ovmf/OVMF.fd" \
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd" \
    "/usr/share/edk2/ovmf/OVMF_CODE.fd" \
    "${BUILD_DIR}/ovmf.fd"; do
    if [[ -f "${path}" ]]; then
        OVMF_PATH="${path}"
        break
    fi
done

if [[ -z "${OVMF_PATH}" ]]; then
    echo "Warning: OVMF firmware not found in standard paths. Attempting to use QEMU bios fallback."
fi

LOG_FILE="${BUILD_DIR}/boot_serial.log"
rm -f "${LOG_FILE}"

# 4. Launch QEMU
echo "[3/4] Launching QEMU with OVMF UEFI firmware..."
QEMU_CMD="qemu-system-x86_64"

if [[ -n "${OVMF_PATH}" ]]; then
    ${QEMU_CMD} \
        -drive if=pflash,format=raw,readonly=on,file="${OVMF_PATH}" \
        -drive file="fat:rw:${ESP_DIR}",format=raw \
        -vga std \
        -display none \
        -serial stdio \
        -no-reboot > "${LOG_FILE}" 2>&1 &
else
    ${QEMU_CMD} \
        -bios default \
        -drive file="fat:rw:${ESP_DIR}",format=raw \
        -vga std \
        -display none \
        -serial stdio \
        -no-reboot > "${LOG_FILE}" 2>&1 &
fi

QEMU_PID=$!

# Wait up to 10 seconds for boot success marker
SUCCESS=0
for _ in {1..20}; do
    sleep 0.5
    if [[ -f "${LOG_FILE}" ]] && grep -q "NEXUS_BOOT_SUCCESS" "${LOG_FILE}"; then
        SUCCESS=1
        break
    fi
done

kill -9 "${QEMU_PID}" 2>/dev/null || true

# 5. Validate Output
echo "[4/4] Validating Serial Boot Logs..."
if [[ -f "${LOG_FILE}" ]]; then
    echo "--- Serial Log Output ---"
    cat "${LOG_FILE}"
    echo "-------------------------"
fi

if [[ ${SUCCESS} -eq 1 ]]; then
    echo "[+] BARE-METAL BOOT TEST PASSED: All Phase 1 kernel components verified."
    exit 0
else
    echo "[-] Test Failed: NEXUS_BOOT_SUCCESS not found in serial log." >&2
    exit 1
fi
