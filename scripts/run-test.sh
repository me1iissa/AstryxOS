#!/usr/bin/env bash
#
# AstryxOS Test Build + Run Script
#
# Builds the kernel in test-mode, launches QEMU with the ISA debug-exit device,
# and reports pass/fail based on the QEMU exit code. All kernel test output
# goes to the serial port (stdout).
#
# Usage:
#   ./scripts/run-test.sh             # Build + run tests, show serial output
#   ./scripts/run-test.sh --headless  # Same but no QEMU window
#   ./scripts/run-test.sh --no-build  # Run without rebuilding
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}======================================"
echo "  AstryxOS — Test Runner"
echo -e "======================================${NC}"

# ── Step 1: Build in test mode ───────────────────────────────────────────────

if [[ "${1:-}" != "--no-build" ]]; then
    echo -e "${YELLOW}[TEST] Building kernel with test-mode feature...${NC}"

    BOOT_TARGET="x86_64-unknown-uefi"
    KERNEL_TARGET_JSON="${ROOT_DIR}/kernel/x86_64-astryx.json"

    # Build bootloader (same as normal)
    cargo +nightly build \
        --package astryx-boot \
        --target "${BOOT_TARGET}" \
        --profile release

    # Build kernel WITH test-mode feature
    cargo +nightly build \
        --package astryx-kernel \
        --target "${KERNEL_TARGET_JSON}" \
        --profile release \
        --features test-mode \
        -Zbuild-std=core,alloc \
        -Zbuild-std-features=compiler-builtins-mem \
        -Zjson-target-spec

    # Prepare ESP
    mkdir -p "${BUILD_DIR}/esp/EFI/BOOT"
    mkdir -p "${BUILD_DIR}/esp/EFI/astryx"

    BOOT_BIN="${ROOT_DIR}/target/${BOOT_TARGET}/release/astryx-boot.efi"
    KERNEL_BIN="${ROOT_DIR}/target/x86_64-astryx/release/astryx-kernel"

    cp "${BOOT_BIN}" "${BUILD_DIR}/esp/EFI/BOOT/BOOTX64.EFI"

    OBJCOPY=$(find "$(rustc +nightly --print sysroot)" -name "llvm-objcopy" | head -1)
    if [ -z "${OBJCOPY}" ]; then
        OBJCOPY="llvm-objcopy"
    fi
    "${OBJCOPY}" -O binary "${KERNEL_BIN}" "${BUILD_DIR}/esp/EFI/astryx/kernel.bin"

    echo -e "${GREEN}[TEST] Build complete.${NC}"
else
    echo -e "${YELLOW}[TEST] Skipping build (--no-build).${NC}"
fi

# ── Step 2: Check for OVMF ──────────────────────────────────────────────────

if [ ! -f "${OVMF_CODE}" ]; then
    OVMF_CODE="/usr/share/ovmf/OVMF.fd"
    if [ ! -f "${OVMF_CODE}" ]; then
        echo -e "${RED}ERROR: OVMF firmware not found.${NC}"
        exit 1
    fi
    OVMF_VARS=""
fi

if [ -n "${OVMF_VARS:-}" ]; then
    OVMF_VARS_COPY="${BUILD_DIR}/OVMF_VARS_TEST.fd"
    cp "${OVMF_VARS}" "${OVMF_VARS_COPY}"
fi

# ── Step 3: Launch QEMU with ISA debug-exit ──────────────────────────────────

echo -e "${CYAN}[TEST] Launching QEMU (test mode)...${NC}"
echo ""

SERIAL_LOG="${BUILD_DIR}/test-serial.log"
: > "${SERIAL_LOG}"   # truncate

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

    # ISA debug-exit: writing to port 0xf4 terminates QEMU.
    # Exit code = (value * 2) + 1.  Kernel uses 0 → exit(1)=pass, 1 → exit(3)=fail.
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
)

# Display
if [[ "${1:-}" == "--headless" ]] || [[ "${2:-}" == "--headless" ]]; then
    QEMU_CMD+=(-display none)
else
    QEMU_CMD+=(-vga vmware)
fi

# UEFI firmware
if [ -n "${OVMF_VARS:-}" ]; then
    QEMU_CMD+=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    )
else
    QEMU_CMD+=(
        -bios "${OVMF_CODE}"
    )
fi

# Boot disk
QEMU_CMD+=(
    -drive "format=raw,file=fat:rw:${BUILD_DIR}/esp"
)

# Data disk — persistent FAT32 drive (secondary IDE)
DATA_IMG="${BUILD_DIR}/data.img"
if [ ! -f "${DATA_IMG}" ]; then
    "${ROOT_DIR}/scripts/create-data-disk.sh" 2>/dev/null || true
fi
if [ -f "${DATA_IMG}" ]; then
    QEMU_CMD+=(
        -drive "file=${DATA_IMG},format=raw,if=none,id=data0,snapshot=on"
        -device "ide-hd,drive=data0,bus=ide.1"
    )
fi

# KVM if available
if [ -r /dev/kvm ]; then
    QEMU_CMD+=(-enable-kvm)
fi

# Network — e1000 with QEMU user-mode NAT (SLIRP)
# Uses the host's network stack directly — no TAP, bridge, or sudo needed.
# Guest gets 10.0.2.15, gateway 10.0.2.2 — SLIRP proxies ICMP/TCP/UDP.
QEMU_CMD+=(
    -device e1000,netdev=net0
    -netdev user,id=net0
)
echo -e "${CYAN}[TEST] Network: e1000 user-mode NAT (IPv4+IPv6 via host network)${NC}"

# SLIRP needs unprivileged ICMP sockets to forward ping to external hosts.
# If ping_group_range is empty (e.g. "1 0"), SLIRP silently drops outbound ICMP.
# Fix: expand the range to include all groups. This is NOT TAP/bridge — just
# a kernel sysctl that lets QEMU open ICMP sockets without root.
PING_RANGE=$(cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo "1 0")
PING_MIN=$(echo "$PING_RANGE" | awk '{print $1}')
PING_MAX=$(echo "$PING_RANGE" | awk '{print $2}')
if [ "$PING_MIN" -gt "$PING_MAX" ] 2>/dev/null; then
    echo -e "${YELLOW}[TEST] ICMP sockets disabled (ping_group_range=$PING_RANGE)${NC}"
    echo -e "${YELLOW}[TEST] Enabling unprivileged ICMP sockets for SLIRP...${NC}"
    # Try to set it (sysctl -qw returns 0 even on permission denied, so verify)
    sysctl -qw net.ipv4.ping_group_range="0 2147483647" 2>/dev/null || true
    # Verify the change actually took effect
    PING_RANGE_AFTER=$(cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo "1 0")
    PING_MIN_AFTER=$(echo "$PING_RANGE_AFTER" | awk '{print $1}')
    PING_MAX_AFTER=$(echo "$PING_RANGE_AFTER" | awk '{print $2}')
    if [ "$PING_MIN_AFTER" -le "$PING_MAX_AFTER" ] 2>/dev/null; then
        echo -e "${GREEN}[TEST] ICMP sockets enabled${NC}"
    else
        echo -e "${YELLOW}[TEST] Could not set sysctl (needs root or CAP_NET_ADMIN) — external pings may fail${NC}"
        echo -e "${YELLOW}[TEST] Fix: run 'sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"' once${NC}"
    fi
fi

# Run QEMU — capture exit code
# Timeout after 600 seconds to allow all 56 tests to complete
# Use serial file output + tail to stream log reliably
set +e
timeout 600 "${QEMU_CMD[@]}" &
QEMU_PID=$!

# Stream the serial log in real-time (background tail)
tail -f "${SERIAL_LOG}" --pid=${QEMU_PID} 2>/dev/null &
TAIL_PID=$!

# Wait for QEMU to finish
wait ${QEMU_PID}
EXIT_CODE=$?

# Give tail a moment to flush, then clean up
sleep 0.2
kill ${TAIL_PID} 2>/dev/null
wait ${TAIL_PID} 2>/dev/null
set -e

echo ""
echo -e "${CYAN}======================================${NC}"

# Interpret exit code:
#   1 = test suite passed  (kernel wrote 0 to debug-exit → (0*2)+1 = 1)
#   3 = test suite failed  (kernel wrote 1 to debug-exit → (1*2)+1 = 3)
#   124 = timeout
#   other = QEMU error
case ${EXIT_CODE} in
    1)
        echo -e "${GREEN}${BOLD}  ✓ ALL TESTS PASSED${NC}"
        echo -e "${CYAN}======================================${NC}"
        echo -e "${CYAN}[TEST] Full serial log: ${SERIAL_LOG}${NC}"
        exit 0
        ;;
    3)
        echo -e "${RED}${BOLD}  ✗ SOME TESTS FAILED${NC}"
        echo ""
        echo -e "${YELLOW}[TEST] Full serial log:${NC}"
        cat "${SERIAL_LOG}"
        echo -e "${CYAN}======================================${NC}"
        exit 1
        ;;
    124)
        echo -e "${RED}${BOLD}  ✗ TIMEOUT — tests did not complete in 600s${NC}"
        echo ""
        echo -e "${YELLOW}[TEST] Serial output captured so far:${NC}"
        cat "${SERIAL_LOG}"
        echo -e "${CYAN}======================================${NC}"
        exit 1
        ;;
    *)
        echo -e "${YELLOW}  ? QEMU exited with code ${EXIT_CODE}${NC}"
        echo ""
        echo -e "${YELLOW}[TEST] Serial output:${NC}"
        cat "${SERIAL_LOG}"
        echo -e "${CYAN}======================================${NC}"
        exit ${EXIT_CODE}
        ;;
esac
