#!/usr/bin/env bash
#
# Host-side smoke test for the create-data-disk.sh write-safety guard
# (incident 2026-07-16: a --force regen wrote THROUGH a worktree symlink and
# rewrote the canonical build/data.img in place while running QEMU sessions
# held it open as snapshot=on backing).
#
# One-shot, non-interactive, no QEMU: it drives create-data-disk.sh in an
# isolated throwaway tree (only the script is present, so every install-*.sh
# staging step is skipped) and asserts the three guards:
#
#   (a) atomic replace   — regen builds to a temp file and renames(2) over the
#                          target: the target inode CHANGES, and a process that
#                          held the OLD image open keeps reading the old bytes.
#   (b) refuse-while-open — a held-open target is refused (exit 3) unless
#                          --force-inuse is passed.
#   (c) foreign symlink  — a data.img symlinked to a target outside the tree is
#                          refused (exit 3) with no override; the foreign file
#                          is left untouched.  A within-tree symlink is allowed
#                          and its resolved target is replaced atomically.
#
# Exit 0 = all checks passed (or cleanly skipped for a missing tool); non-zero
# = a guard regressed.  Refs: rename(2), fuser(1), lsof(8), mke2fs(8).
set -uo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
CDD="${SELF_DIR}/create-data-disk.sh"
SIZE_MB=128   # >= inode-table floor for the script's hardcoded -N 200000

PASS=0
FAIL=0
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

if [ ! -f "${CDD}" ]; then
    echo "SKIP: create-data-disk.sh not found at ${CDD}"
    exit 0
fi
if ! command -v mke2fs >/dev/null 2>&1; then
    echo "SKIP: mke2fs (e2fsprogs) not installed — cannot build test images"
    exit 0
fi
HAVE_INUSE_TOOL=false
if command -v fuser >/dev/null 2>&1 || command -v lsof >/dev/null 2>&1; then
    HAVE_INUSE_TOOL=true
fi

WORK="$(mktemp -d)"
cleanup() { rm -rf "${WORK}" 2>/dev/null || true; }
trap cleanup EXIT

# Isolated fake-root: only create-data-disk.sh present, so ROOT_DIR resolves
# here and every `[ -f "${ROOT_DIR}/scripts/install-*.sh" ]` guard is false —
# no glibc/Firefox staging runs and the build is ~0.3s.
mkroot() {
    local r="$1"
    mkdir -p "${r}/scripts" "${r}/build/disk"
    cp "${CDD}" "${r}/scripts/create-data-disk.sh"
    printf 'VERSION=1\n' > "${r}/build/disk/marker.txt"
}
run_cdd() {  # run_cdd <root> <output-or-empty> <extra-args...>
    local r="$1"; shift
    local out="$1"; shift
    local args=(--build-dir="${r}/build" --force "${SIZE_MB}")
    [ -n "${out}" ] && args=(--output="${out}" "${args[@]}")
    bash "${r}/scripts/create-data-disk.sh" "${args[@]}" "$@" \
        > "${r}/last.log" 2>&1
}

echo "== create-data-disk safety smoke (work=${WORK}) =="

# ── (a) atomic replace + old-reader isolation ────────────────────────────────
echo "[a] atomic replace via temp+rename"
A="${WORK}/a"; mkroot "${A}"; IMG="${A}/build/data.img"
if run_cdd "${A}" "${IMG}"; then
    if dumpe2fs -h "${IMG}" >/dev/null 2>&1; then
        pass "v1 build produced a valid ext2 image"
    else
        fail "v1 image is not a valid ext2 filesystem"
    fi
    grep -q 'via temp+rename' "${A}/last.log" \
        && pass "build logged the temp+rename path" \
        || fail "build did not use temp+rename"
    I1="$(stat -c %i "${IMG}")"
    MODE="$(stat -c %a "${IMG}")"
    [ "${MODE}" = "644" ] && pass "image mode is 0644" \
        || fail "image mode is ${MODE}, expected 644"
    cp "${IMG}" "${WORK}/ref_v1.img"
    # Hold the OLD inode open, then regen (needs --force-inuse since it's held).
    sleep 30 < "${IMG}" &
    HP=$!
    sleep 0.3
    printf 'VERSION=2\n' > "${A}/build/disk/marker.txt"
    run_cdd "${A}" "${IMG}" --force-inuse
    RC=$?
    [ "${RC}" -eq 0 ] && pass "held-open regen with --force-inuse succeeded" \
        || fail "held-open regen with --force-inuse rc=${RC} (expected 0)"
    I2="$(stat -c %i "${IMG}")"
    [ "${I1}" != "${I2}" ] && pass "target inode changed (${I1} -> ${I2})" \
        || fail "target inode unchanged (${I1}); rename did not happen"
    if cmp -s "/proc/${HP}/fd/0" "${WORK}/ref_v1.img"; then
        pass "old held-open fd still reads the v1 image (readers untouched)"
    else
        fail "old held-open fd content diverged from v1 image"
    fi
    if cmp -s "${IMG}" "${WORK}/ref_v1.img"; then
        fail "new target is byte-identical to v1 (regen produced no change)"
    else
        pass "new target differs from v1 (fresh content landed)"
    fi
    kill "${HP}" 2>/dev/null; wait "${HP}" 2>/dev/null
else
    fail "v1 build failed (rc=$?); $(tail -1 "${A}/last.log")"
fi

# ── (b) refuse-while-open ────────────────────────────────────────────────────
echo "[b] refuse-while-open (+ --force-inuse override)"
if [ "${HAVE_INUSE_TOOL}" != true ]; then
    echo "  SKIP: neither fuser nor lsof present — cannot test in-use detection"
else
    B="${WORK}/b"; mkroot "${B}"; IMG="${B}/build/data.img"
    run_cdd "${B}" "${IMG}" || { fail "b: initial build failed"; }
    IB="$(stat -c %i "${IMG}")"
    sleep 30 < "${IMG}" &
    HP=$!
    sleep 0.3
    run_cdd "${B}" "${IMG}"
    RC=$?
    [ "${RC}" -eq 3 ] && pass "held-open regen refused (exit 3)" \
        || fail "held-open regen rc=${RC} (expected 3)"
    grep -q 'REFUSED:.*held open' "${B}/last.log" \
        && pass "refusal names the open-file reason" \
        || fail "refusal message missing 'held open'"
    grep -q 'force-inuse' "${B}/last.log" \
        && pass "refusal names the --force-inuse override" \
        || fail "refusal message omits the override flag"
    [ "${IB}" = "$(stat -c %i "${IMG}")" ] \
        && pass "target left untouched on refusal" \
        || fail "target inode changed despite refusal"
    run_cdd "${B}" "${IMG}" --force-inuse
    RC=$?
    [ "${RC}" -eq 0 ] && pass "--force-inuse overrides the refusal" \
        || fail "--force-inuse regen rc=${RC} (expected 0)"
    kill "${HP}" 2>/dev/null; wait "${HP}" 2>/dev/null
fi

# ── (c) symlink handling ─────────────────────────────────────────────────────
echo "[c] symlink: refuse foreign target, allow within-tree"
C="${WORK}/c"; mkroot "${C}"
FOREIGN_DIR="${WORK}/foreign"; mkdir -p "${FOREIGN_DIR}"
# Seed a real foreign image.
run_cdd "${C}" "${C}/build/real.img" >/dev/null 2>&1 || true
cp "${C}/build/real.img" "${FOREIGN_DIR}/canonical.img"
cp "${FOREIGN_DIR}/canonical.img" "${WORK}/ref_foreign.img"
FI="$(stat -c %i "${FOREIGN_DIR}/canonical.img")"
rm -f "${C}/build/data.img"
ln -s "${FOREIGN_DIR}/canonical.img" "${C}/build/data.img"
# Foreign symlink: must refuse even with --force-inuse.
run_cdd "${C}" "" --force-inuse
RC=$?
[ "${RC}" -eq 3 ] && pass "foreign-symlink regen refused (exit 3, override ignored)" \
    || fail "foreign-symlink regen rc=${RC} (expected 3)"
grep -q 'REFUSED:.*OUTSIDE this tree' "${C}/last.log" \
    && pass "refusal names the out-of-tree symlink reason" \
    || fail "refusal message missing 'OUTSIDE this tree'"
[ -L "${C}/build/data.img" ] && pass "symlink left intact" \
    || fail "symlink was replaced"
[ "${FI}" = "$(stat -c %i "${FOREIGN_DIR}/canonical.img")" ] \
    && pass "foreign target inode untouched" \
    || fail "foreign target inode changed"
cmp -s "${FOREIGN_DIR}/canonical.img" "${WORK}/ref_foreign.img" \
    && pass "foreign target content untouched" \
    || fail "foreign target content changed"

# Within-tree symlink: allowed; resolved target replaced atomically, link kept.
rm -f "${C}/build/data.img"
cp "${FOREIGN_DIR}/canonical.img" "${C}/build/local-real.img"
RIB="$(stat -c %i "${C}/build/local-real.img")"
ln -s "${C}/build/local-real.img" "${C}/build/data.img"
printf 'VERSION=3\n' > "${C}/build/disk/marker.txt"
run_cdd "${C}" "${C}/build/data.img"
RC=$?
[ "${RC}" -eq 0 ] && pass "within-tree symlink regen succeeded" \
    || fail "within-tree symlink regen rc=${RC} (expected 0)"
[ -L "${C}/build/data.img" ] && pass "within-tree symlink preserved" \
    || fail "within-tree symlink was replaced by a regular file"
[ "${RIB}" != "$(stat -c %i "${C}/build/local-real.img")" ] \
    && pass "resolved within-tree target replaced atomically (inode changed)" \
    || fail "resolved within-tree target inode unchanged"

# ── summary ──────────────────────────────────────────────────────────────────
echo "== summary: ${PASS} passed, ${FAIL} failed =="
[ "${FAIL}" -eq 0 ] || exit 1
echo "OK: create-data-disk write-safety guards intact"
exit 0
