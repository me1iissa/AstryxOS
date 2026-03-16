#!/usr/bin/env bash
#
# AstryxOS Automated GUI Test Runner
#
# Builds the kernel in gui-test mode, launches QEMU with the ISA debug-exit
# device, and runs the Python pixel analyser on the serial output.
#
# Novel test approach:
#   1. The kernel renders the full desktop compositor for 60 timer ticks.
#   2. It then samples key pixels directly from its own backbuffer and emits
#      them via serial as "[GUITEST] pixel X Y NAME #RRGGBB" lines.
#   3. This script captures those lines, optionally takes a QMP screendump
#      for visual archiving, then runs analyze-gui.py to validate the pixels.
#
# Usage:
#   ./scripts/run-gui-test.sh            # Build + run
#   ./scripts/run-gui-test.sh --no-build # Skip rebuild
#   ./scripts/run-gui-test.sh --window   # Show QEMU display window
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
SERIAL_LOG="${BUILD_DIR}/gui-test-serial.log"
SCREENSHOT="${BUILD_DIR}/gui-test-screenshot.ppm"
QMP_SOCK="/tmp/astryx-gui-qmp-$$.sock"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}======================================"
echo "  AstryxOS — GUI Test Runner"
echo -e "======================================${NC}"

# ── Step 1: Build in gui-test mode ───────────────────────────────────────────
NO_BUILD=0
SHOW_WINDOW=0
for arg in "$@"; do
    [[ "$arg" == "--no-build" ]] && NO_BUILD=1
    [[ "$arg" == "--window"   ]] && SHOW_WINDOW=1
done

if [[ $NO_BUILD -eq 0 ]]; then
    echo -e "${YELLOW}[GUITEST] Building kernel with gui-test feature...${NC}"

    BOOT_TARGET="x86_64-unknown-uefi"
    KERNEL_TARGET_JSON="${ROOT_DIR}/kernel/x86_64-astryx.json"

    cargo +nightly build \
        --package astryx-boot \
        --target "${BOOT_TARGET}" \
        --profile release

    cargo +nightly build \
        --package astryx-kernel \
        --target "${KERNEL_TARGET_JSON}" \
        --profile release \
        --features gui-test \
        -Zbuild-std=core,alloc \
        -Zbuild-std-features=compiler-builtins-mem \
        -Zjson-target-spec

    mkdir -p "${BUILD_DIR}/esp/EFI/BOOT" "${BUILD_DIR}/esp/EFI/astryx"

    BOOT_BIN="${ROOT_DIR}/target/${BOOT_TARGET}/release/astryx-boot.efi"
    KERNEL_BIN="${ROOT_DIR}/target/x86_64-astryx/release/astryx-kernel"

    cp "${BOOT_BIN}" "${BUILD_DIR}/esp/EFI/BOOT/BOOTX64.EFI"

    OBJCOPY=$(find "$(rustc +nightly --print sysroot)" -name "llvm-objcopy" | head -1)
    [[ -z "${OBJCOPY}" ]] && OBJCOPY="llvm-objcopy"
    "${OBJCOPY}" -O binary "${KERNEL_BIN}" "${BUILD_DIR}/esp/EFI/astryx/kernel.bin"

    echo -e "${GREEN}[GUITEST] Build complete.${NC}"
else
    echo -e "${YELLOW}[GUITEST] Skipping build (--no-build).${NC}"
fi

# ── Step 2: OVMF ─────────────────────────────────────────────────────────────
if [[ ! -f "${OVMF_CODE}" ]]; then
    OVMF_CODE="/usr/share/ovmf/OVMF.fd"
    [[ ! -f "${OVMF_CODE}" ]] && { echo -e "${RED}ERROR: OVMF not found.${NC}"; exit 1; }
    OVMF_VARS=""
fi

OVMF_VARS_COPY=""
if [[ -n "${OVMF_VARS:-}" ]]; then
    OVMF_VARS_COPY="${BUILD_DIR}/OVMF_VARS_GUITEST.fd"
    cp "${OVMF_VARS}" "${OVMF_VARS_COPY}"
fi

# ── Step 3: QEMU command ─────────────────────────────────────────────────────
: > "${SERIAL_LOG}"   # truncate

QEMU_CMD=(
    qemu-system-x86_64
    -machine pc
    -cpu qemu64,+rdtscp
    -m 1G
    -smp 2
    -serial "file:${SERIAL_LOG}"
    -no-reboot
    -no-shutdown
    -monitor none

    # ISA debug-exit: writing 0 to port 0xf4 → QEMU exit(1) = pass
    -device isa-debug-exit,iobase=0xf4,iosize=0x04

    # QMP monitor for optional screendump
    -qmp "unix:${QMP_SOCK},server=on,wait=off"
)

# Display
if [[ $SHOW_WINDOW -eq 1 ]]; then
    QEMU_CMD+=(-vga vmware)
else
    # Even headless, -vga vmware lets QMP screendump read SVGA VRAM.
    QEMU_CMD+=(-vga vmware -display none)
fi

# UEFI firmware
if [[ -n "${OVMF_VARS_COPY:-}" ]]; then
    QEMU_CMD+=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    )
else
    QEMU_CMD+=(-bios "${OVMF_CODE}")
fi

# Boot disk
QEMU_CMD+=(-drive "format=raw,file=fat:rw:${BUILD_DIR}/esp")

# Data disk
DATA_IMG="${BUILD_DIR}/data.img"
if [[ -f "${DATA_IMG}" ]]; then
    QEMU_CMD+=(
        -drive "file=${DATA_IMG},format=raw,if=none,id=data0,snapshot=on"
        -device "ide-hd,drive=data0,bus=ide.1"
    )
fi

# KVM
[[ -r /dev/kvm ]] && QEMU_CMD+=(-enable-kvm)

# Network (needed for kernel init phases)
QEMU_CMD+=(
    -device e1000,netdev=net0
    -netdev user,id=net0
)

# ── Step 4: Run QEMU ─────────────────────────────────────────────────────────
echo -e "${CYAN}[GUITEST] Launching QEMU (gui-test mode)...${NC}"
echo ""

set +e
timeout 120 "${QEMU_CMD[@]}" &
QEMU_PID=$!

# Stream serial log in real-time
tail -f "${SERIAL_LOG}" --pid=${QEMU_PID} 2>/dev/null &
TAIL_PID=$!

# Background: watch for [GUITEST] DONE, then take a QMP screendump
(
    for _ in $(seq 1 600); do
        sleep 0.2
        if grep -q '\[GUITEST\] DONE' "${SERIAL_LOG}" 2>/dev/null; then
            # Try QMP screendump — kernel waits ~1 s before debug-exit
            if command -v python3 &>/dev/null && [[ -S "${QMP_SOCK}" ]]; then
                python3 - "${QMP_SOCK}" "${SCREENSHOT}" <<'PYEOF' 2>/dev/null || true
import socket, json, sys, time
sock_path, out_path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sock_path)
    s.settimeout(5)
    # Read greeting
    data = b""
    while b"\n" not in data:
        data += s.recv(4096)
    # Negotiate capabilities
    s.sendall(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n")
    time.sleep(0.2)
    s.recv(4096)
    # Take screenshot
    cmd = {"execute": "screendump", "arguments": {"filename": out_path}}
    s.sendall(json.dumps(cmd).encode() + b"\n")
    time.sleep(1)
    s.recv(4096)
    print(f"[GUITEST] Screenshot saved to {out_path}")
finally:
    s.close()
PYEOF
            fi
            break
        fi
    done
) &
SCREENSHOT_PID=$!

wait ${QEMU_PID}
EXIT_CODE=$?
sleep 0.3
kill ${TAIL_PID}     2>/dev/null; wait ${TAIL_PID}     2>/dev/null || true
kill ${SCREENSHOT_PID} 2>/dev/null; wait ${SCREENSHOT_PID} 2>/dev/null || true
# Clean up QMP socket
rm -f "${QMP_SOCK}"
set -e

echo ""
echo -e "${CYAN}[GUITEST] QEMU exited with code ${EXIT_CODE}${NC}"

# Exit code 1 = debug-exit value 0 = pass signal from kernel
if [[ ${EXIT_CODE} -ne 1 && ${EXIT_CODE} -ne 0 ]]; then
    echo -e "${RED}[GUITEST] QEMU did not exit cleanly (code ${EXIT_CODE})${NC}"
    echo ""
    echo -e "${YELLOW}[GUITEST] Serial output:${NC}"
    cat "${SERIAL_LOG}"
    exit "${EXIT_CODE}"
fi

# ── Step 5: Pixel analysis ────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}[GUITEST] Running pixel analyser...${NC}"
echo ""

ANALYZE="${ROOT_DIR}/scripts/analyze-gui.py"

if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}[GUITEST] python3 not found — skipping pixel analysis${NC}"
    echo -e "${GREEN}[GUITEST] Serial telemetry (raw):${NC}"
    grep '\[GUITEST\]' "${SERIAL_LOG}" || true
    exit 0
fi

SCREENSHOT_ARG=""
[[ -f "${SCREENSHOT}" ]] && SCREENSHOT_ARG="${SCREENSHOT}"

if python3 "${ANALYZE}" "${SERIAL_LOG}" ${SCREENSHOT_ARG}; then
    echo ""
    echo -e "${GREEN}${BOLD}======================================"
    echo "  ✓ GUI TEST PASSED"
    echo -e "======================================${NC}"
    echo -e "${CYAN}[GUITEST] Serial log:    ${SERIAL_LOG}${NC}"
    [[ -f "${SCREENSHOT}" ]] && echo -e "${CYAN}[GUITEST] Screenshot:    ${SCREENSHOT}${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}${BOLD}======================================"
    echo "  ✗ GUI TEST FAILED"
    echo -e "======================================${NC}"
    echo ""
    echo -e "${YELLOW}[GUITEST] Full serial log:${NC}"
    cat "${SERIAL_LOG}"
    exit 1
fi
