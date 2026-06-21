#!/usr/bin/env python3
"""
patch-gui-gl-smoke.py — Host-side smoke test for patch-gui-gl.sh

Exercises the software-GL (Mesa llvmpipe) image-provisioning tool end-to-end
WITHOUT needing qemu-x86_64, a kernel build, or a real Firefox/Mesa tree:

  - bash -n               syntax check
  - --help                prints usage, exits 0
  - unknown arg           exits non-zero (arg validation)
  - --verify (GL-less)    reports the closure MISSING and exits non-zero
  - --image injection     synthetic GL libs are injected into a scratch ext2
                          image via debugfs; each reads back byte-identical;
                          e2fsck still reports the image clean; and a follow-up
                          --verify now passes (closure complete)

The GL libraries are fabricated as small deterministic blobs (the tool copies
file CONTENT, it does not parse ELF), so the test is hermetic.  The DRI driver
is staged under usr/lib/xorg/modules/dri/ exactly as install-firefox-musl.sh
lays it out.

Run directly:

    python3 scripts/patch-gui-gl-smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed
    2  — environment prerequisite missing (mke2fs/debugfs) — treated as skip
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "patch-gui-gl.sh"

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"
SKIP = "\033[33mSKIP\033[0m"

failures = 0

# The required GL closure members the verify gate checks (must match
# GL_REQUIRED in patch-gui-gl.sh), as (staging-relative-path, image-abs-path).
# Versioned aliases are also injected by the tool but the verify gate keys off
# the SONAMEs + the software DRI driver, so the smoke stages exactly those.
GL_MEMBERS = [
    ("usr/lib/libGL.so.1",                      "/usr/lib/libGL.so.1"),
    ("usr/lib/libEGL.so.1",                     "/usr/lib/libEGL.so.1"),
    ("usr/lib/libgbm.so.1",                     "/usr/lib/libgbm.so.1"),
    ("usr/lib/libglapi.so.0",                   "/usr/lib/libglapi.so.0"),
    ("usr/lib/libLLVM-17.so",                   "/usr/lib/libLLVM-17.so"),
    ("usr/lib/libelf.so.1",                     "/usr/lib/libelf.so.1"),
    ("usr/lib/libwayland-server.so.0",          "/usr/lib/libwayland-server.so.0"),
    ("usr/lib/libxshmfence.so.1",               "/usr/lib/libxshmfence.so.1"),
    ("usr/lib/libXxf86vm.so.1",                 "/usr/lib/libXxf86vm.so.1"),
    ("usr/lib/xorg/modules/dri/swrast_dri.so",  "/usr/lib/xorg/modules/dri/swrast_dri.so"),
]
# Versioned/extra aliases the tool also injects (so the staging tree has them
# present and the inject loop finds them).
GL_ALIASES = [
    "usr/lib/libGL.so.1.2.0",
    "usr/lib/libEGL.so.1.0.0",
    "usr/lib/libgbm.so.1.0.0",
    "usr/lib/libglapi.so.0.0.0",
    "usr/lib/libLLVM-17.0.6.so",
    "usr/lib/libelf-0.191.so",
    "usr/lib/libz.so.1",
    "usr/lib/xorg/modules/dri/libgallium_dri.so",
]


def check(label: str, ok: bool, detail: str = "") -> bool:
    global failures
    tag = PASS if ok else FAIL
    if not ok:
        failures += 1
    line = f"{tag}  {label}"
    if detail:
        line += f"\n      {detail}"
    print(line)
    return ok


def run(args, **kw):
    return subprocess.run(
        ["bash", str(SCRIPT)] + args,
        capture_output=True, text=True, timeout=180, **kw,
    )


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def stage_gl_tree(stage: Path) -> dict:
    """Write deterministic blobs for the full GL closure; return path->bytes."""
    contents = {}
    n = 1
    for rel, _abs in GL_MEMBERS:
        p = stage / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        # Distinct, non-trivial body per member so readback comparison is real.
        body = (f"GL-STUB:{rel}\n".encode() + bytes((n * 7) % 256 for _ in range(64)))
        p.write_bytes(body)
        contents[rel] = body
        n += 1
    for rel in GL_ALIASES:
        p = stage / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        body = (f"GL-ALIAS:{rel}\n".encode() + bytes((n * 11) % 256 for _ in range(32)))
        p.write_bytes(body)
        contents[rel] = body
        n += 1
    return contents


def make_glless_image(td: Path) -> Path:
    """Create a scratch ext2 image WITHOUT any GL libs (just a stub /usr/lib)."""
    empty = td / "glless-stage"
    (empty / "usr/lib").mkdir(parents=True)
    (empty / "usr/lib/placeholder").write_text("not gl\n")
    img = td / "glless.img"
    mk = subprocess.run(
        ["mke2fs", "-q", "-F", "-t", "ext2", "-d", str(empty), str(img), "16m"],
        capture_output=True, text=True)
    if mk.returncode != 0:
        raise RuntimeError(mk.stderr)
    return img


def main() -> int:
    print(f"{INFO}  patch-gui-gl smoke — using {SCRIPT}")
    if not SCRIPT.exists():
        print(f"{FAIL}  script not found")
        return 1

    # 1. bash -n syntax
    syn = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    check("bash -n (syntax)", syn.returncode == 0, syn.stderr.strip())

    # 2. --help
    r = run(["--help"])
    check("--help exits 0 + prints usage", r.returncode == 0 and "Usage:" in r.stdout)

    # 3. unknown arg rejected
    r = run(["--bogus-flag"])
    check("unknown arg rejected (rc!=0)", r.returncode != 0)

    if not (have("mke2fs") and have("debugfs") and have("e2fsck")):
        print(f"{SKIP}  image checks (mke2fs/debugfs/e2fsck absent)")
        print()
        if failures:
            print(f"{FAIL}  {failures} check(s) failed")
            return 1
        print(f"{PASS}  syntax/arg checks passed (image checks skipped)")
        return 0

    with tempfile.TemporaryDirectory(prefix="gui-gl-smoke-", dir=os.environ.get("TMPDIR")) as td:
        tdp = Path(td)

        # 4. --verify on a GL-less image: reports MISSING, exits non-zero.
        try:
            glless = make_glless_image(tdp)
        except RuntimeError as e:
            check("mke2fs GL-less scratch image", False, str(e)[:300])
            glless = None
        if glless is not None:
            r = run(["--verify", str(glless)])
            check("--verify on GL-less image reports incomplete (rc!=0)",
                  r.returncode != 0 and "MISSING" in r.stdout, r.stdout[-300:])

        # 5. --image injection roundtrip into a scratch ext2 image.
        stage = tdp / "disk"
        stage.mkdir()
        staged = stage_gl_tree(stage)

        img = tdp / "data.img"
        emptydir = tdp / "emptyimg"
        emptydir.mkdir()
        # Pre-populate a /usr/lib so the image has the base dir (mirrors a real
        # FF image that already ships non-GL libs).
        (emptydir / "usr/lib").mkdir(parents=True)
        (emptydir / "usr/lib/libc.musl-x86_64.so.1").write_text("musl stub\n")
        mk = subprocess.run(
            ["mke2fs", "-q", "-F", "-t", "ext2", "-d", str(emptydir), str(img), "64m"],
            capture_output=True, text=True)
        if mk.returncode != 0:
            check("mke2fs scratch image", False, mk.stderr.strip()[:300])
        else:
            r = run(["--disk-dir", str(stage), "--image", str(img), "--in-place"])
            check("--image injection rc=0", r.returncode == 0, r.stdout[-500:])

            # Each injected member reads back byte-identical.
            ok_all = True
            mism = ""
            for rel, contents in staged.items():
                absn = "/" + rel
                cat = subprocess.run(["debugfs", "-R", f"cat {absn}", str(img)],
                                     capture_output=True)
                if cat.stdout != contents:
                    ok_all = False
                    mism = f"mismatch at {absn} ({len(cat.stdout)} vs {len(contents)} bytes)"
            check("injected GL libs read back byte-identical", ok_all, mism)

            # e2fsck still clean.
            fsck = subprocess.run(["e2fsck", "-fn", str(img)],
                                  capture_output=True, text=True)
            check("e2fsck clean after injection (rc 0)", fsck.returncode == 0,
                  fsck.stdout[-300:])

            # Follow-up --verify now passes (closure complete).
            r = run(["--verify", str(img)])
            check("--verify on patched image now passes (rc 0)",
                  r.returncode == 0 and "[ok]" in r.stdout, r.stdout[-300:])

    print()
    if failures:
        print(f"{FAIL}  {failures} check(s) failed")
        return 1
    print(f"{PASS}  all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
