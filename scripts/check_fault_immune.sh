#!/usr/bin/env bash
#
# check_fault_immune.sh — guard the fault-immunity contract for the
# kernel bugcheck banner printer.
#
# Background
# ----------
# `kernel/src/ke/bugcheck.rs` and `kernel/src/util/no_alloc_fmt.rs` are
# the only two files in the kernel that may execute while the heap is
# corrupt, the serial mutex is held by another CPU, or the page tables
# are partially shot.  PR #127 hardened them so every byte of output
# goes through a hand-rolled, allocator-free, lock-free path.  Any
# regression that re-introduces an allocating call (`format!`,
# `String::from`, `Box::new`, `Vec::new()`, `vec![]`, …) or a path
# through the standard serial macro (`serial_println!`) silently
# defeats the contract — the bugcheck banner becomes the very thing
# that re-faults instead of capturing the original cause.
#
# This script is intentionally simple: a `grep -nE` pass over the two
# files for the forbidden tokens.  It is meant to run from:
#   * a developer's shell  (`./scripts/check_fault_immune.sh`)
#   * the `cargo-check` CI job (one step that invokes this script)
#
# Exit status
# -----------
#   0  no forbidden tokens found.
#   1  forbidden token found (printed with `file:line` for grep-jump).
#   2  one of the watched files is missing (refactor without updating
#      this script).
#
# Notes on the regex
# ------------------
# We deliberately avoid checking for `panic!` here because the macro
# expansion of `panic!` in `no_std` resolves to the in-tree panic
# handler at `kernel/src/panic.rs`, which itself routes to
# `ke::bugcheck`.  A recursive `panic!` inside the printer would
# defeat the guard; therefore `panic!` is in the forbidden set even
# though the rest of the kernel uses it routinely.
#
# `Vec::new()` is matched literally (with the parens) to avoid
# false-positives on the word "vector" or on `&[T]::new()` constructors
# that happen to be called on slices.  `vec!` is matched as a token
# (`\bvec!`).
#
# Comments are ignored heuristically: any line whose leading non-space
# is `//` or `*` (block-comment continuation) is exempt, which means
# we can talk freely about `format!`/`String`/etc. in the doc comments
# at the top of each file.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILES=(
    "${REPO_ROOT}/kernel/src/ke/bugcheck.rs"
    "${REPO_ROOT}/kernel/src/util/no_alloc_fmt.rs"
)

for f in "${FILES[@]}"; do
    if [ ! -e "$f" ]; then
        echo "check_fault_immune: missing file $f" >&2
        exit 2
    fi
done

# Strip comment-only lines before grepping, so the explanatory prose
# at the top of each file doesn't trip the lint.
#
# The forbidden-token regex (single line for readability):
#   serial_println!  | format!  | \bString\b  | \bBox\b  |
#   Vec::new\(\)     | \bvec!   | panic!      | alloc::  |
#   String::         | Box::    | Rc::        | Arc::    | RefCell::
#
# Word boundaries on String/Box prevent false matches on
# "MyStringBuf", "boxed", etc.  alloc:: catches direct path uses like
# `alloc::vec::Vec`.
FORBIDDEN_RE='(serial_println!|format!|\bString\b|\bBox\b|Vec::new\(\)|\bvec!|\bpanic!|alloc::|String::|Box::|Rc::|Arc::|RefCell::)'

violations=0
for f in "${FILES[@]}"; do
    # awk: skip lines that are purely // or * comments before passing
    # to grep.  Print "file:line:content" so grep -n's normal format
    # is preserved.
    while IFS= read -r line; do
        violations=$((violations + 1))
        printf '%s\n' "$line"
    done < <(
        awk '
            {
                # strip leading whitespace for comment detection
                s = $0
                sub(/^[[:space:]]+/, "", s)
                # skip pure-comment lines (// …) and block-comment
                # continuations (* …, */)
                if (s ~ /^\/\//)              next
                if (s ~ /^\*/)                next
                if (s ~ /^\/\*/)              next
                # otherwise emit "file:lineno:content"
                printf "%s:%d:%s\n", FILENAME, NR, $0
            }
        ' "$f" | grep -E ":[0-9]+:.*${FORBIDDEN_RE}"
    )
done

if [ "$violations" -gt 0 ]; then
    echo "" >&2
    echo "check_fault_immune: FORBIDDEN allocating/formatting tokens found in fault-immune files." >&2
    echo "" >&2
    echo "These files (kernel/src/ke/bugcheck.rs, kernel/src/util/no_alloc_fmt.rs)" >&2
    echo "must remain allocator-free and serial-mutex-free.  See the module-level" >&2
    echo "doc comment at the top of bugcheck.rs for the full contract." >&2
    exit 1
fi

echo "check_fault_immune: OK"
exit 0
