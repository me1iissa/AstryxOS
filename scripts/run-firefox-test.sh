#!/usr/bin/env bash
#
# AstryxOS Firefox Launch Test
#
# Builds the kernel in firefox-test mode, launches QEMU headlessly, and
# captures the serial log to show what happens when Firefox starts.
#
# Usage:
#   ./scripts/run-firefox-test.sh            # Build + run
#   ./scripts/run-firefox-test.sh --no-build # Skip rebuild
#   ./scripts/run-firefox-test.sh --window   # Show QEMU display window
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
SERIAL_LOG="${BUILD_DIR}/firefox-test-serial.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}======================================"
echo "  AstryxOS — Firefox Launch Test"
echo -e "======================================${NC}"

NO_BUILD=0
SHOW_WINDOW=0
for arg in "$@"; do
    [[ "$arg" == "--no-build" ]] && NO_BUILD=1
    [[ "$arg" == "--window"   ]] && SHOW_WINDOW=1
done

# ── Step 1: Build ────────────────────────────────────────────────────────────
if [[ $NO_BUILD -eq 0 ]]; then
    echo -e "${YELLOW}[FFTEST] Building kernel with firefox-test feature...${NC}"

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
        --features firefox-test \
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

    echo -e "${GREEN}[FFTEST] Build complete.${NC}"
else
    echo -e "${YELLOW}[FFTEST] Skipping build (--no-build).${NC}"
fi

# ── Step 2: OVMF ─────────────────────────────────────────────────────────────
if [[ ! -f "${OVMF_CODE}" ]]; then
    OVMF_CODE="/usr/share/ovmf/OVMF.fd"
    [[ ! -f "${OVMF_CODE}" ]] && { echo -e "${RED}ERROR: OVMF not found.${NC}"; exit 1; }
    OVMF_VARS=""
fi

OVMF_VARS_COPY="${BUILD_DIR}/OVMF_VARS_FFTEST.fd"
if [[ -n "${OVMF_VARS:-}" ]]; then
    cp "${OVMF_VARS}" "${OVMF_VARS_COPY}"
else
    # Fallback: combined OVMF.fd — use a copy as writable NVRAM.
    cp "${OVMF_CODE}" "${OVMF_VARS_COPY}"
fi

# ── Step 3: QEMU command ─────────────────────────────────────────────────────
: > "${SERIAL_LOG}"

DATA_IMG="${BUILD_DIR}/data.img"
if [[ ! -f "${DATA_IMG}" ]]; then
    echo -e "${RED}ERROR: No data disk at ${DATA_IMG} — Firefox won't be found.${NC}"
    exit 1
fi

WINDOW_FLAG=()
[[ $SHOW_WINDOW -eq 1 ]] && WINDOW_FLAG+=("--window")

KVM_FLAG=(--no-kvm)
[[ -r /dev/kvm ]] && KVM_FLAG=(--kvm)

# Canonical QEMU argv — one source of truth in scripts/astryx_qemu.py.
# The `firefox-test` mode bakes in the 2 GiB memory and `-cpu host`
# that Firefox needs. Previously this script had its own inline argv
# which drifted from the test / gui-test builders (audit MED-2/3/5);
# the canonical builder kills that drift. Data disk bus is now
# virtio-blk-pci (was ide-hd here) — tests against the recently
# regression-hunted virtio path (commit f0e1835).
readarray -t QEMU_CMD < <(python3 "${ROOT_DIR}/scripts/astryx_qemu.py" build \
    --mode firefox-test \
    --serial-path "${SERIAL_LOG}" \
    --data-img    "${DATA_IMG}" \
    --ovmf-code   "${OVMF_CODE}" \
    --ovmf-vars   "${OVMF_VARS_COPY}" \
    --esp-dir     "${BUILD_DIR}/esp" \
    "${WINDOW_FLAG[@]}" \
    "${KVM_FLAG[@]}")

# ── Step 4: Run QEMU ─────────────────────────────────────────────────────────
echo -e "${CYAN}[FFTEST] Launching QEMU (firefox-test mode)...${NC}"
echo ""

set +e
# Timeout: 10 minutes (Firefox startup with demand-paging 194MB libxul can be slow)
timeout 600 "${QEMU_CMD[@]}" &
QEMU_PID=$!

# Stream serial log in real-time
tail -f "${SERIAL_LOG}" --pid=${QEMU_PID} 2>/dev/null &
TAIL_PID=$!

wait ${QEMU_PID}
EXIT_CODE=$?
sleep 0.3
kill ${TAIL_PID} 2>/dev/null; wait ${TAIL_PID} 2>/dev/null || true
set -e

echo ""
echo -e "${CYAN}[FFTEST] QEMU exited with code ${EXIT_CODE}${NC}"

# ── Step 5: Analyse serial log ────────────────────────────────────────────────
echo ""
echo "======================================"
echo "  Firefox Test Serial Analysis"
echo "======================================"

PASSED=0
FAILED=0

check() {
    local name="$1"
    local desc="$2"
    local pattern="$3"
    if grep -q "${pattern}" "${SERIAL_LOG}" 2>/dev/null; then
        echo -e "  [${GREEN}PASS${NC}] ${name}: ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  [${RED}FAIL${NC}] ${name}: ${desc}"
        FAILED=$((FAILED + 1))
    fi
}

check "kernel_init"   "X11 server ready"               "\[FFTEST\] X11 server ready"
check "desktop_ready" "Desktop launched"               "\[WM\] Created window.*Terminal"
check "ff_launched"   "Firefox launch initiated"       "Launching /disk/opt/firefox/firefox-bin"
check "ff_done"       "FFTEST DONE marker received"    "\[FFTEST\] DONE"

# Look for common crash/error patterns
echo ""
echo "  Notable events:"
grep -E "\[FFTEST\]|\[LINUX-SYS\] unimplemented|PANIC|FAULT|ERROR|firefox" \
    "${SERIAL_LOG}" 2>/dev/null | grep -v "^$" | tail -50 || true

echo ""
echo "======================================"
TOTAL=$((PASSED + FAILED))
echo "  Results: ${PASSED}/${TOTAL} checks passed"

if [[ ${FAILED} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  OVERALL: PASS${NC}"
    echo "======================================"
    echo -e "${CYAN}[FFTEST] Full serial log: ${SERIAL_LOG}${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}  OVERALL: FAIL${NC}"
    echo "======================================"
    echo ""
    echo -e "${YELLOW}[FFTEST] Tail of serial log:${NC}"
    tail -100 "${SERIAL_LOG}" || true
    exit 1
fi
