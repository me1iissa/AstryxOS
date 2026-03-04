#!/usr/bin/env bash
#
# AstryxOS Build Script
# Builds the bootloader (UEFI) and kernel, then creates a bootable ISO/disk image.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
BOOT_TARGET="x86_64-unknown-uefi"
KERNEL_TARGET_JSON="${ROOT_DIR}/kernel/x86_64-astryx.json"
PROFILE="${1:-release}"

echo "======================================"
echo "  AstryxOS Build System"
echo "  Profile: ${PROFILE}"
echo "======================================"

# Step 1: Build the bootloader (UEFI application)
echo "[BUILD] Building AstryxBoot (UEFI bootloader)..."
cargo +nightly build \
    --package astryx-boot \
    --target "${BOOT_TARGET}" \
    --profile "${PROFILE}"

# Step 2: Build the kernel
echo "[BUILD] Building Aether Kernel..."
cargo +nightly build \
    --package astryx-kernel \
    --target "${KERNEL_TARGET_JSON}" \
    --profile "${PROFILE}" \
    -Zbuild-std=core,alloc \
    -Zbuild-std-features=compiler-builtins-mem \
    -Zjson-target-spec

# Step 3: Create the ESP (EFI System Partition) directory structure
echo "[BUILD] Creating disk image..."
mkdir -p "${BUILD_DIR}/esp/EFI/BOOT"
mkdir -p "${BUILD_DIR}/esp/EFI/astryx"

# Copy bootloader EFI binary
if [ "${PROFILE}" = "dev" ] || [ "${PROFILE}" = "debug" ]; then
    BOOT_BIN="${ROOT_DIR}/target/${BOOT_TARGET}/debug/astryx-boot.efi"
    KERNEL_BIN="${ROOT_DIR}/target/x86_64-astryx/debug/astryx-kernel"
else
    BOOT_BIN="${ROOT_DIR}/target/${BOOT_TARGET}/release/astryx-boot.efi"
    KERNEL_BIN="${ROOT_DIR}/target/x86_64-astryx/release/astryx-kernel"
fi

cp "${BOOT_BIN}" "${BUILD_DIR}/esp/EFI/BOOT/BOOTX64.EFI"

# Copy kernel as flat binary
# Use objcopy to convert ELF to flat binary
OBJCOPY=$(find "$(rustc +nightly --print sysroot)" -name "llvm-objcopy" | head -1)
if [ -z "${OBJCOPY}" ]; then
    OBJCOPY="llvm-objcopy"
fi

"${OBJCOPY}" -O binary "${KERNEL_BIN}" "${BUILD_DIR}/esp/EFI/astryx/kernel.bin"

echo "[BUILD] Bootloader: ${BUILD_DIR}/esp/EFI/BOOT/BOOTX64.EFI"
echo "[BUILD] Kernel:     ${BUILD_DIR}/esp/EFI/astryx/kernel.bin"

# Step 4: Create a FAT32 disk image
ESP_IMG="${BUILD_DIR}/astryx-os.img"
ESP_SIZE_MB=64

echo "[BUILD] Creating FAT32 disk image (${ESP_SIZE_MB} MiB)..."
dd if=/dev/zero of="${ESP_IMG}" bs=1M count="${ESP_SIZE_MB}" status=none

# Create GPT partition table with EFI System Partition
# Using sgdisk if available, otherwise fall back to manual FAT32 formatting
if command -v mkfs.fat &>/dev/null; then
    mkfs.fat -F 32 "${ESP_IMG}" >/dev/null
    # Copy files into FAT32 image using mtools
    if command -v mcopy &>/dev/null; then
        export MTOOLS_SKIP_CHECK=1
        mcopy -i "${ESP_IMG}" -s "${BUILD_DIR}/esp/EFI" "::EFI"
    else
        echo "[WARN] mtools not found — using alternative method"
        # Create a temporary mount or use QEMU's vvfat
        echo "[BUILD] Files prepared in ${BUILD_DIR}/esp/ — will use QEMU vvfat"
    fi
else
    echo "[WARN] mkfs.fat not found — will use QEMU vvfat directly"
fi

# Step 5: Create ISO image (for distribution)
if command -v xorriso &>/dev/null; then
    echo "[BUILD] Creating bootable ISO..."
    ISO_DIR="${BUILD_DIR}/iso"
    mkdir -p "${ISO_DIR}"
    cp -r "${BUILD_DIR}/esp/"* "${ISO_DIR}/"

    xorriso -as mkisofs \
        -o "${BUILD_DIR}/astryx-os.iso" \
        -e "EFI/BOOT/BOOTX64.EFI" \
        -no-emul-boot \
        "${ISO_DIR}" 2>/dev/null || echo "[WARN] ISO creation failed — disk image still available"
else
    echo "[INFO] xorriso not found — skipping ISO creation. Use disk image instead."
fi

echo ""
echo "======================================"
echo "  Build complete!"
echo "  Disk image: ${BUILD_DIR}/astryx-os.img"
if [ -f "${BUILD_DIR}/astryx-os.iso" ]; then
    echo "  ISO image:  ${BUILD_DIR}/astryx-os.iso"
fi
echo ""
echo "  Run with: ./scripts/run-qemu.sh"
echo "======================================"
