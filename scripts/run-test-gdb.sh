#!/usr/bin/env bash
#
# AstryxOS Test Build + Run Script (GDB Debug Mode)
#
# Same as run-test.sh but exposes a GDB stub on TCP port 1234.
# QEMU starts running immediately (no -S freeze).
#
# Usage:
#   ./scripts/run-test-gdb.sh              # Build + run, GDB port 1234
#   ./scripts/run-test-gdb.sh --no-build   # Skip build
#   ./scripts/run-test-gdb.sh --freeze     # Freeze at boot, wait for GDB connect
#
# Attach with:
#   gdb -x scripts/kernel.gdb
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
GDB_PORT=1234

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}======================================"
echo "  AstryxOS — Test Runner (GDB Mode)"
echo -e "======================================${NC}"
echo -e "${CYAN}GDB stub will be available on port ${GDB_PORT}${NC}"

# ── Step 1: Build ─────────────────────────────────────────────────────────────

if [[ "${1:-}" != "--no-build" ]] && [[ "${2:-}" != "--no-build" ]]; then
    echo -e "${YELLOW}[TEST] Building kernel with debug symbols + test-mode...${NC}"

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
        --features test-mode \
        -Zbuild-std=core,alloc \
        -Zbuild-std-features=compiler-builtins-mem \
        -Zjson-target-spec

    mkdir -p "${BUILD_DIR}/esp/EFI/BOOT"
    mkdir -p "${BUILD_DIR}/esp/EFI/astryx"

    BOOT_BIN="${ROOT_DIR}/target/${BOOT_TARGET}/release/astryx-boot.efi"
    KERNEL_BIN="${ROOT_DIR}/target/x86_64-astryx/release/astryx-kernel"

    cp "${BOOT_BIN}" "${BUILD_DIR}/esp/EFI/BOOT/BOOTX64.EFI"

    OBJCOPY=$(find "$(rustc +nightly --print sysroot)" -name "llvm-objcopy" | head -1)
    [ -z "${OBJCOPY}" ] && OBJCOPY="llvm-objcopy"
    "${OBJCOPY}" -O binary "${KERNEL_BIN}" "${BUILD_DIR}/esp/EFI/astryx/kernel.bin"

    echo -e "${GREEN}[TEST] Build complete.${NC}"
else
    echo -e "${YELLOW}[TEST] Skipping build.${NC}"
fi

# ── Step 2: OVMF ──────────────────────────────────────────────────────────────

if [ ! -f "${OVMF_CODE}" ]; then
    OVMF_CODE="/usr/share/ovmf/OVMF.fd"
    [ ! -f "${OVMF_CODE}" ] && { echo -e "${RED}ERROR: OVMF not found.${NC}"; exit 1; }
    OVMF_VARS=""
fi

if [ -n "${OVMF_VARS:-}" ]; then
    OVMF_VARS_COPY="${BUILD_DIR}/OVMF_VARS_TEST.fd"
    cp "${OVMF_VARS}" "${OVMF_VARS_COPY}"
fi

# ── Step 3: Build QEMU command ────────────────────────────────────────────────

SERIAL_LOG="${BUILD_DIR}/test-serial.log"
: > "${SERIAL_LOG}"

QEMU_CMD=(
    qemu-system-x86_64
    -machine pc
    -cpu qemu64
    -m 1G
    -smp 2
    -serial "file:${SERIAL_LOG}"
    -no-reboot
    -no-shutdown
    -monitor none
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
    -display none

    # GDB stub — QEMU acts as a gdbserver
    -gdb "tcp::${GDB_PORT}"
)

# --freeze: pause at first instruction, wait for GDB to connect and `continue`
if [[ "${1:-}" == "--freeze" ]] || [[ "${2:-}" == "--freeze" ]]; then
    QEMU_CMD+=(-S)
    echo -e "${YELLOW}[GDB] QEMU is frozen at boot. Attach GDB and run 'continue'.${NC}"
else
    echo -e "${CYAN}[GDB] QEMU running freely. Attach GDB any time before the hang.${NC}"
fi

if [ -n "${OVMF_VARS:-}" ]; then
    QEMU_CMD+=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    )
else
    QEMU_CMD+=(-bios "${OVMF_CODE}")
fi

QEMU_CMD+=(-drive "format=raw,file=fat:rw:${BUILD_DIR}/esp")

DATA_IMG="${BUILD_DIR}/data.img"
if [ -f "${DATA_IMG}" ]; then
    QEMU_CMD+=(
        -drive "file=${DATA_IMG},format=raw,if=none,id=data0,snapshot=on"
        -device "ide-hd,drive=data0,bus=ide.1"
    )
fi

[ -r /dev/kvm ] && QEMU_CMD+=(-enable-kvm)

QEMU_CMD+=(
    -device e1000,netdev=net0
    -netdev user,id=net0
)

# ── Step 4: Launch ────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}[GDB] QEMU PID will be printed below.${NC}"
echo -e "${CYAN}[GDB] Serial log: ${SERIAL_LOG}${NC}"
echo -e "${CYAN}[GDB] To attach GDB in another terminal:${NC}"
echo -e "${BOLD}        gdb -x scripts/kernel.gdb${NC}"
echo ""

set +e
"${QEMU_CMD[@]}" &
QEMU_PID=$!
echo -e "${GREEN}[GDB] QEMU PID: ${QEMU_PID}${NC}"
echo "${QEMU_PID}" > "${BUILD_DIR}/qemu.pid"

# Stream serial log to terminal
tail -f "${SERIAL_LOG}" --pid=${QEMU_PID} 2>/dev/null &
TAIL_PID=$!

wait ${QEMU_PID}
EXIT_CODE=$?

sleep 0.2
kill ${TAIL_PID} 2>/dev/null
wait ${TAIL_PID} 2>/dev/null
rm -f "${BUILD_DIR}/qemu.pid"
set -e

echo ""
echo -e "${CYAN}======================================${NC}"
case ${EXIT_CODE} in
    1)  echo -e "${GREEN}${BOLD}  ✓ ALL TESTS PASSED${NC}" ; exit 0 ;;
    3)  echo -e "${RED}${BOLD}  ✗ SOME TESTS FAILED${NC}"
        echo -e "${YELLOW}[TEST] Full serial log:${NC}"; cat "${SERIAL_LOG}"
        exit 1 ;;
    124) echo -e "${RED}${BOLD}  ✗ TIMEOUT${NC}"
         cat "${SERIAL_LOG}"; exit 1 ;;
    *)  echo -e "${YELLOW}  ? QEMU exited with code ${EXIT_CODE}${NC}"
        cat "${SERIAL_LOG}"; exit ${EXIT_CODE} ;;
esac
