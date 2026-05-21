#!/usr/bin/env python3
"""
inject-libxul-symtab.py — Splice a .symtab from a Mozilla Breakpad .sym file
into a stripped libxul.so, producing a symbol-bearing copy for kdb rip-trace
resolution.

Usage:
    python3 scripts/inject-libxul-symtab.py \
        --sym    <path/to/libxul.so.sym>    \
        --input  <path/to/libxul.so>        \
        --output <path/to/libxul.sym.so>

The Breakpad .sym format (see https://chromium.googlesource.com/breakpad/) has
two relevant per-symbol record types:

    FUNC   <hex_offset> <size_hex> <param_size_hex> <demangled_name>
    PUBLIC [m] <hex_offset> <param_size_hex> <demangled_name>

`FUNC` records carry an explicit byte size and are produced when the upstream
build was compiled with DWARF debug info (Mozilla's release builds for the
official Firefox channels).  `PUBLIC` records are derived from the dynamic
symbol table (.dynsym) plus per-platform demanglers and are emitted by
dump_syms when no DWARF is available — for example, third-party rebuilds
(Alpine's community/firefox-esr, Debian's firefox-esr, distro packages
generally).  PUBLIC carries no size; we set st_size = 0 and let nm / addr2line
treat the entry as a function-entry-point address.  The optional "m" token
flags a multiple-definition symbol; we ignore it (objcopy/nm handle dupes
correctly because we use STB_LOCAL).

`<hex_offset>` is the ELF VMA (load-time address for a PIE/shared object,
i.e. the same value you'd find in .symtab st_value for a shared library).

This script:
  1. Parses FUNC and PUBLIC records from the .sym file.
  2. Builds an Elf64_Sym array (.symtab) and a null-terminated string table
     (.strtab).
  3. Appends both sections to the ELF using objcopy --add-section.
  4. Updates the ELF header's e_shstrndx to reference the original section
     name table (no change needed; we use --set-section-flags to mark the
     sections correctly).

The executable code of libxul.so is NOT touched — only new section entries are
appended after the existing section data.  The Build ID is preserved
byte-for-byte.  The resulting file can be verified with:

    nm --defined-only libxul.sym.so | head -20
    readelf -S libxul.sym.so | grep -E "symtab|strtab"

References:
  - ELF-64 ABI specification (generic ABI, https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)
  - Mozilla Breakpad .sym format: https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/symbol_files.md
  - binutils objcopy(1) man page
"""

import argparse
import struct
import subprocess
import sys
import os
import tempfile
from pathlib import Path

# Elf64_Sym layout (24 bytes per entry, little-endian)
# st_name   uint32  4
# st_info   uint8   1
# st_other  uint8   1
# st_shndx  uint16  2
# st_value  uint64  8
# st_size   uint64  8
ELF64_SYM = struct.Struct("<IBBHQQ")
assert ELF64_SYM.size == 24

# STB_GLOBAL = 1, STT_FUNC = 2 → st_info = (STB_GLOBAL << 4) | STT_FUNC = 0x12
# We use STB_LOCAL (0) | STT_FUNC (2) = 0x02 for internal symbols to avoid
# conflicting with the existing .dynsym global binding, which nm would prefer.
# Local STT_FUNC symbols are still named and resolved by nm/addr2line.
ST_INFO_LOCAL_FUNC = (0 << 4) | 2   # STB_LOCAL | STT_FUNC

# SHN_UNDEF = 0, we use it for zero-value placeholder (null sym)
SHN_UNDEF = 0

# We mark all FUNC symbols as belonging to section index 15 (.text).
# Section 15 is the .text section at VMA 0x10c7060.
# A more robust approach would be to walk sections and find which one
# contains each FUNC's VMA, but for libxul.so the bulk of code is in .text,
# and nm resolves names from st_value regardless of st_shndx for STT_FUNC.
# Using SHN_ABS (0xfff1) avoids needing the exact index.
SHN_ABS = 0xfff1


def parse_sym(sym_path: Path) -> list[tuple[int, int, str]]:
    """
    Parse FUNC and PUBLIC records from a Mozilla Breakpad .sym file.

    Returns a list of (vma, size, name) tuples, one per FUNC or PUBLIC record.
    Names are already demangled in the .sym file.

    PUBLIC records carry no explicit size (Breakpad spec: size field absent —
    PUBLIC tokens are entry-point pointers, not extents).  We set size=0 for
    those entries.  nm and addr2line treat STT_FUNC symbols with st_size=0 as
    entry-point markers and still resolve names via the nearest-below lookup
    that binutils performs internally, which is sufficient for kdb
    rip-trace-resolve attribution.

    FUNC and PUBLIC are not mutually exclusive in a well-formed .sym; in
    practice Mozilla's release builds emit FUNC only, and dump_syms builds
    against stripped third-party binaries (Alpine, Debian) emit PUBLIC only.
    We accept both so a single injection pass handles either source.
    """
    funcs: list[tuple[int, int, str]] = []
    # The .sym file may be large (690 MiB for Mozilla release builds, ~90 MiB
    # for Alpine PUBLIC-only) — read line-by-line to avoid loading it whole.
    n_func = 0
    n_public = 0
    with open(sym_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("FUNC "):
                # FUNC [m] <addr_hex> <size_hex> <param_size_hex> <name>
                # The "m" multiple-definition flag is optional (sits at
                # parts[1]); when absent the address is at parts[1] and the
                # name at parts[4].  Mozilla release builds emit FUNC without
                # the m flag; we accept both to be tolerant of future format
                # variants.
                parts = line.split(None, 5)
                if len(parts) < 5:
                    continue
                if parts[1] == "m":
                    if len(parts) < 6:
                        continue
                    addr_field, size_field = parts[2], parts[3]
                    name = parts[5].rstrip("\n")
                else:
                    addr_field, size_field = parts[1], parts[2]
                    name = parts[4].rstrip("\n")
                try:
                    vma = int(addr_field, 16)
                    size = int(size_field, 16)
                except ValueError:
                    continue
                if name:
                    funcs.append((vma, size, name))
                    n_func += 1
            elif line.startswith("PUBLIC "):
                # PUBLIC [m] <addr_hex> <param_size_hex> <name>
                # The optional "m" multiple-definition flag sits at parts[1];
                # the address is then at parts[2] and the name at parts[4].
                # Without "m" the address is at parts[1] and the name at
                # parts[3].
                parts = line.split(None, 4)
                if len(parts) < 4:
                    continue
                if parts[1] == "m":
                    if len(parts) < 5:
                        continue
                    addr_field = parts[2]
                    name = parts[4].rstrip("\n")
                else:
                    addr_field = parts[1]
                    name = parts[3].rstrip("\n")
                try:
                    vma = int(addr_field, 16)
                except ValueError:
                    continue
                if name and vma != 0:
                    # st_size = 0 — PUBLIC has no size; nm / addr2line tolerate
                    # this and treat the symbol as an entry-point marker.
                    funcs.append((vma, 0, name))
                    n_public += 1
    print(f"      Parsed FUNC={n_func:,}  PUBLIC={n_public:,}")
    return funcs


def build_symtab_strtab(
    funcs: list[tuple[int, int, str]],
) -> tuple[bytes, bytes]:
    """
    Build raw .symtab and .strtab section data from FUNC records.

    Returns (symtab_bytes, strtab_bytes).

    The .symtab starts with a mandatory null entry (ELF ABI §4.1).
    The .strtab starts with a null byte.
    """
    strtab = bytearray(b"\x00")  # index 0 = empty name
    symtab = bytearray(ELF64_SYM.pack(0, 0, 0, 0, 0, 0))  # null symbol

    for vma, size, name in funcs:
        # Encode name into strtab
        encoded = name.encode("utf-8", errors="replace") + b"\x00"
        st_name = len(strtab)
        strtab.extend(encoded)

        sym = ELF64_SYM.pack(
            st_name,          # st_name: offset into .strtab
            ST_INFO_LOCAL_FUNC,  # st_info: STB_LOCAL | STT_FUNC
            0,                # st_other: STV_DEFAULT
            SHN_ABS,          # st_shndx: SHN_ABS (no relocation needed)
            vma,              # st_value: ELF VMA = Breakpad FUNC address
            size,             # st_size: function size in bytes
        )
        symtab.extend(sym)

    return bytes(symtab), bytes(strtab)


def inject_sections(
    input_path: Path,
    output_path: Path,
    symtab_bytes: bytes,
    strtab_bytes: bytes,
) -> None:
    """
    Use objcopy to append .symtab and .strtab sections to the input ELF,
    writing the result to output_path.  Then patch the .symtab section header
    in-place to set:
      - sh_link  → index of .strtab (so nm/readelf resolves symbol names)
      - sh_info  → 1 (all our symbols are STB_LOCAL; by convention sh_info
                   names the first non-local entry, i.e. past all locals)
      - sh_entsize → 24 (sizeof Elf64_Sym)
      - sh_addralign → 8

    objcopy --add-section appends raw binary content as a new section but does
    not set sh_link or sh_entsize for non-standard section types; we fix that
    with a targeted in-place patch of the ELF section-header array.

    References:
      - ELF-64 ABI: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html
      - binutils objcopy(1)
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        symtab_file = os.path.join(tmpdir, "symtab.bin")
        strtab_file = os.path.join(tmpdir, "strtab.bin")

        with open(symtab_file, "wb") as f:
            f.write(symtab_bytes)
        with open(strtab_file, "wb") as f:
            f.write(strtab_bytes)

        cmd = [
            "objcopy",
            # Add .strtab first — objcopy appends sections in order,
            # so .strtab will have a lower section index than .symtab,
            # which we then fix via sh_link.
            "--add-section", f".strtab={strtab_file}",
            "--set-section-flags", ".strtab=readonly",
            "--add-section", f".symtab={symtab_file}",
            "--set-section-flags", ".symtab=readonly",
            str(input_path),
            str(output_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] objcopy failed: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    # ── Patch section headers in-place ───────────────────────────────────────
    # Read the ELF header to locate the section-header table, then scan
    # sections to find .symtab and .strtab by name, and fix up .symtab's
    # metadata fields.
    _patch_symtab_shdr(output_path)


def _patch_symtab_shdr(path: Path) -> None:
    """
    Fix up the .symtab section header written by objcopy.

    objcopy --add-section writes the section data correctly but leaves
    sh_link=0, sh_entsize=0, sh_info=0, and sh_addralign=1 for sections
    it does not natively understand.  The ELF ABI (§4.6.1) requires:

      .symtab.sh_link     = index of the associated .strtab section
      .symtab.sh_entsize  = sizeof(Elf64_Sym) = 24
      .symtab.sh_info     = index of first non-STB_LOCAL symbol
                            (since all our symbols are STB_LOCAL this is
                            total_count + 1; callers that need global-only
                            scans start from sh_info — setting it past our
                            local-only table is correct)
      .symtab.sh_addralign = 8 (64-bit alignment of Elf64_Sym arrays)

    We also ensure .strtab.sh_type is SHT_STRTAB (3), which objcopy may
    leave as SHT_PROGBITS (1) when using --set-section-flags=readonly.
    """
    ESHDR = struct.Struct("<IIQQQQ II QQ")  # Elf64_Shdr (64 bytes)
    assert ESHDR.size == 64

    SHT_STRTAB = 3
    SHT_SYMTAB = 2

    with open(path, "r+b") as f:
        raw = bytearray(f.read())

    # ── Parse ELF header ─────────────────────────────────────────────────────
    e_shoff     = struct.unpack_from("<Q", raw, 40)[0]
    e_shentsize = struct.unpack_from("<H", raw, 58)[0]
    e_shnum     = struct.unpack_from("<H", raw, 60)[0]
    e_shstrndx  = struct.unpack_from("<H", raw, 62)[0]

    if e_shentsize != 64:
        raise ValueError(f"Unexpected e_shentsize={e_shentsize}")

    # ── Load section name string table (.shstrtab) ────────────────────────────
    shstrtab_shdr = raw[e_shoff + e_shstrndx * 64: e_shoff + (e_shstrndx + 1) * 64]
    shstrtab_off  = struct.unpack_from("<Q", shstrtab_shdr, 24)[0]
    shstrtab_size = struct.unpack_from("<Q", shstrtab_shdr, 32)[0]
    shstrtab      = raw[shstrtab_off: shstrtab_off + shstrtab_size]

    def section_name(shdr_bytes: bytes) -> str:
        sh_name = struct.unpack_from("<I", shdr_bytes)[0]
        end = shstrtab.index(b"\x00", sh_name)
        return shstrtab[sh_name:end].decode("utf-8", errors="replace")

    # ── Find .symtab and .strtab indices ─────────────────────────────────────
    symtab_idx = strtab_idx = None
    symtab_n_entries = 0
    for i in range(e_shnum):
        off = e_shoff + i * 64
        shdr = raw[off: off + 64]
        name = section_name(shdr)
        sh_type = struct.unpack_from("<I", shdr, 4)[0]
        sh_size = struct.unpack_from("<Q", shdr, 32)[0]
        if name == ".symtab" and sh_type == SHT_SYMTAB:
            symtab_idx = i
            symtab_n_entries = sh_size // 24  # raw size / sizeof(Elf64_Sym)
        elif name == ".strtab" and i != e_shstrndx:
            # Find the .strtab that is NOT the section-name string table
            # (.shstrtab).  We identify .shstrtab by e_shstrndx; the
            # newly-added .strtab is any other section named ".strtab".
            # We pick the last such occurrence in case objcopy appends
            # multiple auxiliary string tables (it does not in practice, but
            # being defensive here prevents a silent sh_link mismatch).
            strtab_idx = i

    if symtab_idx is None:
        raise RuntimeError(".symtab section not found in output ELF")
    if strtab_idx is None:
        raise RuntimeError("new .strtab section not found in output ELF")

    # ── Patch .symtab section header ─────────────────────────────────────────
    symtab_off = e_shoff + symtab_idx * 64
    shdr = raw[symtab_off: symtab_off + 64]
    (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
     sh_size, sh_link, sh_info, sh_addralign, sh_entsize) = ESHDR.unpack(shdr)

    patched = ESHDR.pack(
        sh_name, sh_type, sh_flags, sh_addr, sh_offset,
        sh_size,
        strtab_idx,           # sh_link → .strtab index
        symtab_n_entries,     # sh_info = total symbols (all local)
        8,                    # sh_addralign = 8
        24,                   # sh_entsize = sizeof(Elf64_Sym)
    )
    raw[symtab_off: symtab_off + 64] = patched

    # ── Fix .strtab section type if objcopy wrote SHT_PROGBITS ───────────────
    strtab_off = e_shoff + strtab_idx * 64
    st_shdr = raw[strtab_off: strtab_off + 64]
    cur_type = struct.unpack_from("<I", st_shdr, 4)[0]
    if cur_type != SHT_STRTAB:
        st_shdr = bytearray(st_shdr)
        struct.pack_into("<I", st_shdr, 4, SHT_STRTAB)
        raw[strtab_off: strtab_off + 64] = bytes(st_shdr)

    with open(path, "wb") as f:
        f.write(raw)

    print(f"      Patched .symtab[{symtab_idx}]: sh_link={strtab_idx}, "
          f"sh_info={symtab_n_entries}, sh_entsize=24, sh_addralign=8")


def verify_output(output_path: Path) -> None:
    """
    Quick sanity checks on the output ELF.
    """
    result = subprocess.run(
        ["readelf", "-S", str(output_path)],
        capture_output=True, text=True
    )
    if ".symtab" not in result.stdout:
        print("[WARN] .symtab not found in section headers after injection!",
              file=sys.stderr)
    if ".strtab" not in result.stdout:
        print("[WARN] .strtab not found in section headers after injection!",
              file=sys.stderr)

    nm_result = subprocess.run(
        ["nm", "--defined-only", str(output_path)],
        capture_output=True, text=True
    )
    lines = nm_result.stdout.strip().splitlines()
    if lines:
        print(f"[OK] nm returned {len(lines)} defined symbols.")
        print("[OK] First 5 symbols:")
        for line in lines[:5]:
            print(f"     {line}")
    else:
        print("[WARN] nm returned no symbols!", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Splice Breakpad FUNC symbols into a stripped libxul.so as .symtab"
    )
    parser.add_argument("--sym", required=True, type=Path,
                        help="Path to the Mozilla Breakpad .sym file")
    parser.add_argument("--input", required=True, type=Path,
                        help="Path to the stripped libxul.so")
    parser.add_argument("--output", required=True, type=Path,
                        help="Output path for the symbol-bearing libxul.so")
    args = parser.parse_args()

    if not args.sym.exists():
        print(f"[ERROR] .sym file not found: {args.sym}", file=sys.stderr)
        sys.exit(1)
    if not args.input.exists():
        print(f"[ERROR] input ELF not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"[1/4] Parsing FUNC records from {args.sym} ...")
    funcs = parse_sym(args.sym)
    print(f"      Found {len(funcs):,} functions.")

    print(f"[2/4] Building .symtab + .strtab ...")
    symtab_bytes, strtab_bytes = build_symtab_strtab(funcs)
    sym_count = len(symtab_bytes) // 24
    print(f"      .symtab: {sym_count:,} entries ({len(symtab_bytes)/1024/1024:.1f} MiB)")
    print(f"      .strtab: {len(strtab_bytes)/1024/1024:.1f} MiB")

    print(f"[3/4] Injecting sections into {args.output} ...")
    inject_sections(args.input, args.output, symtab_bytes, strtab_bytes)

    print(f"[4/4] Verifying output ...")
    verify_output(args.output)

    # Verify Build ID is unchanged
    bid_in = subprocess.run(
        ["readelf", "-n", str(args.input)],
        capture_output=True, text=True
    ).stdout
    bid_out = subprocess.run(
        ["readelf", "-n", str(args.output)],
        capture_output=True, text=True
    ).stdout
    if "Build ID" in bid_in and bid_in == bid_out:
        print("[OK] Build ID unchanged (executable code not modified).")
    else:
        print("[WARN] Build ID mismatch — check objcopy invocation.", file=sys.stderr)

    in_size = args.input.stat().st_size
    out_size = args.output.stat().st_size
    print(f"\nDone.")
    print(f"  Input:  {in_size/1024/1024:.1f} MiB")
    print(f"  Output: {out_size/1024/1024:.1f} MiB")
    print(f"  Delta:  +{(out_size - in_size)/1024/1024:.1f} MiB (debug data only)")


if __name__ == "__main__":
    main()
