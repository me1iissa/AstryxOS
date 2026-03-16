#!/usr/bin/env python3
"""
AstryxOS Automated GUI Pixel Analyser
======================================
Parses "[GUITEST] pixel" telemetry lines emitted by the kernel's
compositor (compositor.rs::emit_pixel_telemetry) and validates that
each sampled pixel falls within the expected colour range.

Also optionally validates a QMP screendump PPM if provided.

Usage:
    python3 scripts/analyze-gui.py build/gui-test-serial.log [screenshot.ppm]

Exit codes:
    0 — all required checks pass
    1 — one or more checks failed
"""

import re
import struct
import sys


# ─────────────────────────────────────────────────────────────────────────────
# Colour helper
# ─────────────────────────────────────────────────────────────────────────────

def hex_to_rgb(h: str):
    """Convert '#RRGGBB' to (r, g, b) ints."""
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def colour_dist(r, g, b, er, eg, eb):
    return max(abs(r - er), abs(g - eg), abs(b - eb))


PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
WARN = "\033[33mWARN\033[0m"


def check(name, desc, r, g, b, er, eg, eb, tol=8):
    dist = colour_dist(r, g, b, er, eg, eb)
    ok = dist <= tol
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}: {desc}")
    print(f"         got #{r:02X}{g:02X}{b:02X}  "
          f"expected ~#{er:02X}{eg:02X}{eb:02X}  "
          f"(dist={dist}, tol={tol})")
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Parse serial log
# ─────────────────────────────────────────────────────────────────────────────

def parse_serial(path: str):
    pixels = {}   # name → (x, y, r, g, b)
    width = 0
    height = 0
    frames = 0
    done = False

    with open(path, "r", errors="replace") as f:
        for line in f:
            # [GUITEST] pixel X Y NAME #RRGGBB
            m = re.search(
                r'\[GUITEST\] pixel (\d+) (\d+) (\S+) #([0-9A-Fa-f]{6})', line)
            if m:
                x, y, name, col = m.group(1), m.group(2), m.group(3), m.group(4)
                r, g, b = hex_to_rgb(col)
                pixels[name] = (int(x), int(y), r, g, b)
                continue

            # [GUITEST] width=W height=H frames=N
            m = re.search(
                r'\[GUITEST\] width=(\d+) height=(\d+) frames=(\d+)', line)
            if m:
                width, height, frames = int(m.group(1)), int(m.group(2)), int(m.group(3))
                continue

            if "[GUITEST] DONE" in line:
                done = True

    return pixels, width, height, frames, done


# ─────────────────────────────────────────────────────────────────────────────
# Expected colour formulae (must match compositor.rs gradient math)
# ─────────────────────────────────────────────────────────────────────────────

def gradient_at(y: int, h: int):
    """
    Reproduce compositor.rs desktop background gradient in Python.

    top:  R=0x0A G=0x0A B=0x20  (deep navy)
    bot:  R=0x0D G=0x1B B=0x2A  (dark teal)
    formula (integer, u32 wrapping):
        r = top_r + (bot_r - top_r) * y // h
    """
    if h == 0:
        return (0x0A, 0x0A, 0x20)
    tr, tg, tb = 0x0A, 0x0A, 0x20
    br, bg, bb = 0x0D, 0x1B, 0x2A
    r = tr + (br - tr) * y // h
    g = tg + (bg - tg) * y // h
    b = tb + (bb - tb) * y // h
    return (r, g, b)


# ─────────────────────────────────────────────────────────────────────────────
# PPM screenshot validation (optional)
# ─────────────────────────────────────────────────────────────────────────────

def sample_ppm(path: str, x: int, y: int):
    """Return (r, g, b) at pixel (x, y) from a P6 PPM file."""
    try:
        with open(path, "rb") as f:
            # Parse header
            magic = f.readline().strip()
            if magic != b"P6":
                return None
            # Skip comments
            while True:
                line = f.readline().strip()
                if not line.startswith(b"#"):
                    break
            w, h = map(int, line.split())
            maxval = int(f.readline().strip())
            bpp = 2 if maxval > 255 else 1
            offset = (y * w + x) * 3 * bpp
            f.seek(offset, 1)   # relative to current pos (after header)
            data = f.read(3 * bpp)
            if bpp == 1:
                return data[0], data[1], data[2]
            else:
                r = struct.unpack(">H", data[0:2])[0] >> 8
                g = struct.unpack(">H", data[2:4])[0] >> 8
                b = struct.unpack(">H", data[4:6])[0] >> 8
                return r, g, b
    except Exception:
        return None


def validate_screenshot(path: str, width: int, height: int):
    """
    Spot-check 3 pixels in the PPM screenshot against the serial telemetry
    expected values.  These are best-effort — SVGA VRAM and backbuffer may
    differ slightly due to cursor overlay or blit timing.
    """
    print(f"\n  Screenshot: {path}")
    if width == 0 or height == 0:
        print(f"  [{WARN}] Screen dimensions unknown — skipping screenshot checks")
        return True   # not a failure

    checks = [
        # (label, x, y, expected_r, expected_g, expected_b, tol)
        ("screenshot_desktop_center",
         width // 2, height // 2,
         *gradient_at(height // 2, height), 12),
        ("screenshot_taskbar",
         width // 2, height - 20,
         0x1A, 0x1A, 0x2E, 16),
    ]

    passed = 0
    for label, x, y, er, eg, eb, tol in checks:
        px = sample_ppm(path, x, y)
        if px is None:
            print(f"  [{WARN}] {label}: could not read PPM pixel at ({x},{y})")
        else:
            if check(label, f"PPM pixel at ({x},{y})", *px, er, eg, eb, tol):
                passed += 1

    return True   # screenshot failures are advisory, not blocking


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze-gui.py <serial.log> [screenshot.ppm]")
        sys.exit(1)

    serial_log = sys.argv[1]
    screenshot = sys.argv[2] if len(sys.argv) > 2 else None

    pixels, width, height, frames, done = parse_serial(serial_log)

    print("=" * 52)
    print("  AstryxOS GUI Test Pixel Analysis")
    print("=" * 52)

    passed = 0
    total = 0

    # ── Liveness checks ───────────────────────────────────────────────────────
    total += 1
    if done:
        print(f"  [{PASS}] kernel_done: [GUITEST] DONE received")
        passed += 1
    else:
        print(f"  [{FAIL}] kernel_done: never saw [GUITEST] DONE in serial log")

    total += 1
    if frames > 0:
        print(f"  [{PASS}] frame_count: {frames} frame(s) composed")
        passed += 1
    else:
        print(f"  [{FAIL}] frame_count: 0 frames — compositor did not render")

    total += 1
    if width > 0 and height > 0:
        print(f"  [{PASS}] resolution:  {width}×{height}")
        passed += 1
    else:
        print(f"  [{FAIL}] resolution:  compositor not initialized (w={width} h={height})")

    # ── Desktop gradient ──────────────────────────────────────────────────────
    print()
    print("  Desktop background gradient:")

    if "desktop_center" in pixels:
        _, _, r, g, b = pixels["desktop_center"]
        er, eg, eb = gradient_at(height // 2, height) if height else (0x0B, 0x12, 0x25)
        total += 1
        if check("desktop_center", "mid-screen gradient colour", r, g, b, er, eg, eb, tol=5):
            passed += 1
        # Sanity: must not be pure black (compositor ran)
        total += 1
        if r > 0 or g > 0 or b > 0:
            print(f"  [{PASS}] not_black:     pixel is non-zero (compositor rendered)")
            passed += 1
        else:
            print(f"  [{FAIL}] not_black:     pixel is #000000 — compositor may be broken")
    else:
        print(f"  [{WARN}] desktop_center not found in telemetry")

    if "desktop_top" in pixels:
        _, _, r, g, b = pixels["desktop_top"]
        er, eg, eb = gradient_at(10, height) if height else (0x0A, 0x0A, 0x20)
        total += 1
        if check("desktop_top", "top-of-screen gradient colour", r, g, b, er, eg, eb, tol=3):
            passed += 1
    else:
        print(f"  [{WARN}] desktop_top not found in telemetry")

    # ── Taskbar ───────────────────────────────────────────────────────────────
    print()
    print("  Taskbar:")

    if "taskbar" in pixels:
        _, _, r, g, b = pixels["taskbar"]
        # Taskbar background: TASKBAR_COLOR = 0xFF1A1A2E (R=0x1A G=0x1A B=0x2E)
        total += 1
        if check("taskbar", "taskbar strip colour (#1A1A2E)", r, g, b, 0x1A, 0x1A, 0x2E, tol=12):
            passed += 1
    else:
        print(f"  [{WARN}] taskbar not found in telemetry")

    # ── Window title bars ─────────────────────────────────────────────────────
    print()
    print("  Window title bars:")

    if "term_title" in pixels:
        _, _, r, g, b = pixels["term_title"]
        # Active title bar: COLOR_TITLE_BAR_ACTIVE = 0xFF1B1B1B
        total += 1
        if check("term_title", "terminal titlebar — active (#1B1B1B)", r, g, b, 0x1B, 0x1B, 0x1B, tol=8):
            passed += 1
    else:
        print(f"  [{WARN}] term_title not found in telemetry")

    if "expl_title" in pixels:
        _, _, r, g, b = pixels["expl_title"]
        # Inactive title bar: COLOR_TITLE_BAR_INACTIVE = 0xFF2D2D2D
        total += 1
        if check("expl_title", "explorer titlebar — inactive (#2D2D2D)", r, g, b, 0x2D, 0x2D, 0x2D, tol=8):
            passed += 1
    else:
        print(f"  [{WARN}] expl_title not found in telemetry")

    # ── Window client area: must not be pure black or background gradient ─────
    print()
    print("  Window client areas:")

    if "term_client" in pixels:
        _, _, r, g, b = pixels["term_client"]
        # Client area is drawn (surface or bg_color fill) — just check non-gradient
        # i.e. it shouldn't match the raw desktop background exactly.
        gc_r, gc_g, gc_b = gradient_at(380, height) if height else (0x0B, 0x12, 0x24)
        is_gradient = colour_dist(r, g, b, gc_r, gc_g, gc_b) < 3
        total += 1
        if not is_gradient:
            print(f"  [{PASS}] term_client: window content drawn over desktop "
                  f"(#{r:02X}{g:02X}{b:02X} ≠ gradient)")
            passed += 1
        else:
            print(f"  [{FAIL}] term_client: pixel matches raw desktop gradient "
                  f"— window may not have rendered")
    else:
        print(f"  [{WARN}] term_client not found in telemetry")

    # ── Optional screenshot checks ────────────────────────────────────────────
    if screenshot:
        print()
        print("  PPM screenshot (advisory):")
        validate_screenshot(screenshot, width, height)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 52)
    print(f"  Results: {passed}/{total} checks passed")

    if passed == total:
        print(f"\033[32m  OVERALL: PASS\033[0m")
        print("=" * 52)
        sys.exit(0)
    else:
        print(f"\033[31m  OVERALL: FAIL\033[0m")
        print("=" * 52)
        sys.exit(1)


if __name__ == "__main__":
    main()
