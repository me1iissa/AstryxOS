#!/usr/bin/env bash
#
# Run AstryxOS in QEMU with OVMF UEFI firmware.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"

# Check for OVMF
if [ ! -f "${OVMF_CODE}" ]; then
    # Try alternative paths
    OVMF_CODE="/usr/share/ovmf/OVMF.fd"
    if [ ! -f "${OVMF_CODE}" ]; then
        echo "ERROR: OVMF firmware not found. Install with: sudo apt install ovmf"
        exit 1
    fi
    OVMF_VARS=""
fi

# Create a working copy of OVMF_VARS (it gets modified at runtime)
if [ -n "${OVMF_VARS}" ]; then
    OVMF_VARS_COPY="${BUILD_DIR}/OVMF_VARS.fd"
    cp "${OVMF_VARS}" "${OVMF_VARS_COPY}"
fi

# Build non-test-mode kernel (skip with --no-build)
if [ "${1:-}" != "--no-build" ] && [ "${2:-}" != "--no-build" ]; then
    echo "[QEMU] Building non-test-mode kernel..."
    KERNEL_TARGET_JSON="${ROOT_DIR}/kernel/x86_64-astryx.json"
    BOOT_TARGET="x86_64-unknown-uefi"
    cd "${ROOT_DIR}"
    cargo +nightly build \
        --package astryx-boot \
        --target "${BOOT_TARGET}" \
        --profile release
    cargo +nightly build \
        --package astryx-kernel \
        --target "${KERNEL_TARGET_JSON}" \
        --profile release \
        -Zbuild-std=core,alloc \
        -Zbuild-std-features=compiler-builtins-mem \
        -Zjson-target-spec
    # Install binaries to ESP
    BOOT_BIN="${ROOT_DIR}/target/${BOOT_TARGET}/release/astryx-boot.efi"
    KERNEL_BIN="${ROOT_DIR}/target/x86_64-astryx/release/astryx-kernel"
    OBJCOPY=$(find "$(rustc +nightly --print sysroot)" -name "llvm-objcopy" | head -1)
    [ -z "${OBJCOPY}" ] && OBJCOPY="llvm-objcopy"
    mkdir -p "${BUILD_DIR}/esp/EFI/BOOT"
    mkdir -p "${BUILD_DIR}/esp/EFI/astryx"
    cp "${BOOT_BIN}" "${BUILD_DIR}/esp/EFI/BOOT/BOOTX64.EFI"
    "${OBJCOPY}" -O binary "${KERNEL_BIN}" "${BUILD_DIR}/esp/EFI/astryx/kernel.bin"
    echo "[QEMU] Build complete."
fi

echo "======================================"
echo "  AstryxOS — QEMU Launcher"
echo "======================================"

# Build QEMU command
QEMU_CMD=(
    qemu-system-x86_64
    -machine pc
    -cpu host
    -m 4G
    -smp 4
    -serial stdio
    -no-reboot
    -no-shutdown
)

# Display mode
if [ "${1:-}" = "--headless" ] || [ "${2:-}" = "--headless" ]; then
    QEMU_CMD+=(-display none)
    echo "[QEMU] Headless mode (serial only)"
else
    # VMware SVGA II virtual GPU (required by kernel driver).
    QEMU_CMD+=(-vga vmware)

    # Display backend selection.
    # On WSL2, GTK uses the native Wayland protocol (WSLg) which lacks the
    # relative-pointer-v1 extension QEMU needs for PS/2 mouse grab — this
    # breaks mouse input and causes crashes on fullscreen.  SDL uses
    # XWayland (X11) instead and works correctly on WSL2.
    # Prefer SDL → GTK → default.
    DISPLAY_HELP=$(qemu-system-x86_64 -display help 2>&1)
    if echo "${DISPLAY_HELP}" | grep -q 'sdl'; then
        QEMU_CMD+=(-display sdl)
        echo "[QEMU] Display: SDL (click window to capture PS/2 mouse)"
    elif echo "${DISPLAY_HELP}" | grep -q 'gtk'; then
        QEMU_CMD+=(-display gtk,grab-on-hover=on)
        echo "[QEMU] Display: GTK (hover to capture mouse; fullscreen may crash on WSL2)"
    else
        echo "[QEMU] NOTE: Click inside the QEMU window to capture PS/2 mouse input"
    fi
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

# Boot disk — use vvfat to directly serve the ESP directory
# This avoids needing mtools/mkfs.fat
QEMU_CMD+=(
    -drive "format=raw,file=fat:rw:${BUILD_DIR}/esp"
)

# Data disk — persistent FAT32 drive (secondary IDE)
# Created by scripts/create-data-disk.sh
DATA_IMG="${BUILD_DIR}/data.img"
if [ ! -f "${DATA_IMG}" ]; then
    echo "[QEMU] Creating data disk..."
    "${ROOT_DIR}/scripts/create-data-disk.sh"
fi
if [ -f "${DATA_IMG}" ]; then
    QEMU_CMD+=(
        -drive "file=${DATA_IMG},format=raw,if=none,id=data0"
        -device "ide-hd,drive=data0,bus=ide.1"
    )
    echo "[QEMU] Data disk: ${DATA_IMG} (secondary IDE)"
fi

# Debug options
if [ "${1:-}" = "--debug" ]; then
    echo "[QEMU] Debug mode: GDB server on port 1234"
    QEMU_CMD+=(-s -S)
fi

# KVM acceleration if available
if [ -r /dev/kvm ]; then
    QEMU_CMD+=(-enable-kvm)
    echo "[QEMU] KVM acceleration enabled"
fi

# Network — Intel e1000 NIC with QEMU user-mode NAT (SLIRP).
# Uses the host's network stack directly — no TAP, bridge, or sudo needed.
# Guest gets 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3.
# SLIRP forwards ICMP/TCP/UDP through the host transparently.
QEMU_CMD+=(
    -device e1000,netdev=net0
    -netdev user,id=net0
)
echo "[QEMU] Network: e1000 NIC with user-mode NAT (SLIRP)"

# SLIRP needs unprivileged ICMP sockets to forward ping to external hosts.
# If ping_group_range is empty (e.g. "1 0"), SLIRP silently drops outbound ICMP.
PING_RANGE=$(cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo "1 0")
PING_MIN=$(echo "$PING_RANGE" | awk '{print $1}')
PING_MAX=$(echo "$PING_RANGE" | awk '{print $2}')
if [ "$PING_MIN" -gt "$PING_MAX" ] 2>/dev/null; then
    echo "[QEMU] ICMP sockets disabled — enabling for SLIRP..."
    # Try to set it (sysctl -qw returns 0 even on permission denied, so verify)
    sysctl -qw net.ipv4.ping_group_range="0 2147483647" 2>/dev/null || true
    PING_RANGE_AFTER=$(cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo "1 0")
    PING_MIN_AFTER=$(echo "$PING_RANGE_AFTER" | awk '{print $1}')
    PING_MAX_AFTER=$(echo "$PING_RANGE_AFTER" | awk '{print $2}')
    if [ "$PING_MIN_AFTER" -le "$PING_MAX_AFTER" ] 2>/dev/null; then
        echo "[QEMU] ICMP sockets enabled"
    else
        echo "[QEMU] Could not set sysctl (needs root or CAP_NET_ADMIN) — external pings may fail"
        echo "[QEMU] Fix: run 'sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"' once"
    fi
fi

echo "[QEMU] Starting AstryxOS..."
echo "[QEMU] Serial output on this terminal"
echo "[QEMU] Press Ctrl+A then X to exit QEMU"
echo ""

exec "${QEMU_CMD[@]}"
