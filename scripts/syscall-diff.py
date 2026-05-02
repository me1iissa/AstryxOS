#!/usr/bin/env python3
"""
syscall-diff.py — Align and diff Firefox syscall streams between native Linux
(strace -ff) and AstryxOS (firefox-test [LINUX-SYS] serial trace).

Goal: given a known-good native trace and an AstryxOS trace, emit JSON that
identifies the first divergence in observable kernel behaviour.

Usage (one-shot, non-interactive):
    scripts/syscall-diff.py --native-dir <strace -ff dir>           \
                            --astryx-log <serial.log path>          \
                            [--native-tid <pid>]                    \
                            [--skip <name>[,<name>...]]             \
                            [--skip-enoent-prefix]                  \
                            [--context N] [--debug]

Output (stdout): JSON with keys
    summary.{linux_total_calls, astryxos_total_calls, aligned_calls,
             divergence_class}
    first_divergence.{step_index, linux:{nr,name,args,ret},
                      astryxos:{nr,name,args,ret}}
    context_lines: 5 calls before divergence on each side

When --debug is passed, an additional `debug` field is emitted with side-by-side
TSV-style rows for the first 200 aligned calls (post-skip).

Format dependencies:
  * /usr/include/x86_64-linux-gnu/asm/unistd_64.h — nr->name table source.
    If absent, falls back to a small builtin table sufficient for FF startup.
  * strace -ff: one file per task, format
        <name>(<args>) = <retval>[ <errno> (...)]
  * AstryxOS [LINUX-SYS]: format
        [LINUX-SYS] #N pid=P num=NR a1=0xXX[ a2=0xXX]
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Syscall name table ───────────────────────────────────────────────────────

_FALLBACK_NAMES = {
    # Minimum set covering Firefox 115 ESR startup; full table loaded from
    # /usr/include/x86_64-linux-gnu/asm/unistd_64.h when available.
    0:"read", 1:"write", 2:"open", 3:"close", 4:"stat", 5:"fstat", 6:"lstat",
    7:"poll", 8:"lseek", 9:"mmap", 10:"mprotect", 11:"munmap", 12:"brk",
    13:"rt_sigaction", 14:"rt_sigprocmask", 15:"rt_sigreturn", 16:"ioctl",
    17:"pread64", 18:"pwrite64", 19:"readv", 20:"writev", 21:"access",
    22:"pipe", 23:"select", 24:"sched_yield", 25:"mremap", 28:"madvise",
    32:"dup", 33:"dup2", 35:"nanosleep", 39:"getpid", 41:"socket",
    42:"connect", 56:"clone", 57:"fork", 58:"vfork", 59:"execve", 60:"exit",
    61:"wait4", 62:"kill", 63:"uname", 72:"fcntl", 79:"getcwd", 89:"readlink",
    96:"gettimeofday", 158:"arch_prctl", 202:"futex", 217:"getdents64",
    218:"set_tid_address", 228:"clock_gettime", 229:"clock_getres",
    230:"clock_nanosleep", 231:"exit_group", 232:"epoll_wait",
    233:"epoll_ctl", 257:"openat", 262:"newfstatat", 270:"pselect6",
    271:"ppoll", 273:"set_robust_list", 274:"get_robust_list", 281:"epoll_pwait",
    284:"eventfd", 290:"eventfd2", 291:"epoll_create1", 292:"dup3",
    293:"pipe2", 318:"getrandom", 319:"memfd_create", 322:"execveat",
    332:"statx", 435:"clone3", 449:"futex_waitv",
}


def load_syscall_table() -> Tuple[Dict[int, str], Dict[str, int]]:
    """Parse `unistd_64.h` if available; else use the builtin fallback."""
    nr_to_name: Dict[int, str] = dict(_FALLBACK_NAMES)
    p = Path("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")
    if p.exists():
        rx = re.compile(r"^\s*#define\s+__NR_(\S+)\s+(\d+)\s*$")
        for line in p.read_text().splitlines():
            m = rx.match(line)
            if m:
                name, nr = m.group(1), int(m.group(2))
                nr_to_name[nr] = name
    name_to_nr = {v: k for k, v in nr_to_name.items()}
    # strace prints some legacy names; alias them so name->nr resolves.
    aliases = {
        "newfstatat": 262, "fstatat": 262, "fstatat64": 262,
        "newstat": 4, "newlstat": 6, "newfstat": 5,
    }
    for n, k in aliases.items():
        name_to_nr.setdefault(n, k)
    return nr_to_name, name_to_nr


# ── Strace parsing ───────────────────────────────────────────────────────────

# Match `name(args) = retval [errno (descr)]`.
# strace also emits unfinished/resumed lines (`<unfinished ...>` / `<...
# resumed>`); we treat those as a single combined call by ignoring the
# resume marker and waiting for the full line.  In practice strace -ff
# rarely splits on a single thread's stream when no signals interrupt
# syscalls, but we handle the case defensively.
_STRACE_FULL = re.compile(
    r"^(?P<name>[a-z_][a-z0-9_]*)"     # syscall name
    r"\((?P<args>.*)\)\s*=\s*"         # args list (greedy minus paren count)
    r"(?P<ret>-?\d+|0x[0-9a-fA-F]+|\?)"  # return value
    r"(?:\s+(?P<errno>[A-Z_][A-Z0-9_]+))?"  # optional errno name
    r".*$"
)
_STRACE_UNFIN = re.compile(r"^(?P<name>[a-z_][a-z0-9_]*)\((?P<args>.*?)<unfinished")
_STRACE_EXIT  = re.compile(r"^\+\+\+ exited with (?P<code>-?\d+) \+\+\+")
_STRACE_KILL  = re.compile(r"^\+\+\+ killed by ")
_STRACE_SIG   = re.compile(r"^---\s+SIG[A-Z]+")


def parse_strace_args_truncated(args_str: str, max_args: int = 6) -> List[str]:
    """Split the strace argument list at top-level commas.

    Strace prints full Python-style nested expressions (`{flags=A|B, ...}`,
    `[a, b, c]`, `"string"`, etc.).  A naive split on `,` produces wrong
    columns because of nested commas inside braces / brackets / strings.
    Walk char-by-char tracking nesting depth + escape state so we cut only
    at commas at depth 0.
    """
    out: List[str] = []
    depth = 0
    in_str = False
    escape = False
    cur = []
    for c in args_str:
        if in_str:
            cur.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            if len(out) >= max_args:
                # Append the remainder verbatim and stop.
                rest = args_str[len("".join(out)) + len(out):]  # rough
                if rest.strip():
                    out.append(rest.strip())
                return out
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur).strip())
    return out


def parse_strace_file(path: Path,
                      name_to_nr: Dict[str, int]) -> List[Dict]:
    """Return a list of syscall dicts for one strace -ff file."""
    calls: List[Dict] = []
    text = path.read_text(errors="replace")
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if _STRACE_SIG.match(line) or _STRACE_EXIT.match(line) or \
           _STRACE_KILL.match(line):
            continue
        m = _STRACE_FULL.match(line)
        if not m:
            mu = _STRACE_UNFIN.match(line)
            if mu:
                # unfinished: keep the entry name with no return so alignment
                # still sees the call (matches AstryxOS, which logs at entry)
                name = mu.group("name")
                nr = name_to_nr.get(name)
                if nr is not None:
                    calls.append({
                        "nr": nr, "name": name,
                        "args": parse_strace_args_truncated(mu.group("args"))[:6],
                        "ret": None, "errno": None,
                        "raw": line,
                    })
            continue
        name = m.group("name")
        nr = name_to_nr.get(name)
        if nr is None:
            # Unknown syscall name — emit as -1/<name> so the diff still sees
            # something but classifies as missing-from-table.
            nr = -1
        ret = m.group("ret")
        try:
            ret_val = int(ret, 0) if ret != "?" else None
        except ValueError:
            ret_val = None
        calls.append({
            "nr": nr,
            "name": name,
            "args": parse_strace_args_truncated(m.group("args"))[:6],
            "ret": ret_val,
            "errno": m.group("errno"),
            "raw": line,
        })
    return calls


def find_main_strace_file(native_dir: Path,
                          override_tid: Optional[int]) -> Path:
    """Pick the strace file containing the initial execve.

    With strace -ff we typically have one file per task.  The first file
    written corresponds to the original (parent) process; the very first line
    in that file is the `execve(...)` of firefox-bin.
    """
    candidates = sorted(native_dir.glob("trace.*"))
    if not candidates:
        raise SystemExit(f"no trace.* files under {native_dir}")
    if override_tid is not None:
        target = native_dir / f"trace.{override_tid}"
        if not target.exists():
            raise SystemExit(f"no such trace file: {target}")
        return target
    # Pick the largest file (main thread accumulates the most syscalls during
    # the linker prologue + xpcom startup).  This is a heuristic that beats
    # "first by mtime" because strace creates the parent's file first but
    # lots of work runs on the parent itself before clone3 spawns helpers.
    return max(candidates, key=lambda p: p.stat().st_size)


# ── AstryxOS [LINUX-SYS] parsing ─────────────────────────────────────────────

_LINUX_SYS_RE = re.compile(
    r"\[LINUX-SYS\]\s+#(?P<n>\d+)\s+pid=(?P<pid>\d+)\s+num=(?P<num>\d+)"
    r"\s+a1=(?P<a1>0x[0-9a-fA-F]+)"
    r"(?:\s+a2=(?P<a2>0x[0-9a-fA-F]+))?"
)


def parse_astryx_log(path: Path,
                     pid_filter: Optional[int],
                     nr_to_name: Dict[int, str]) -> List[Dict]:
    """Return a list of syscall dicts from [LINUX-SYS] lines in serial log."""
    calls: List[Dict] = []
    text = path.read_text(errors="replace")
    for line in text.splitlines():
        m = _LINUX_SYS_RE.search(line)
        if not m:
            continue
        pid = int(m.group("pid"))
        if pid_filter is not None and pid != pid_filter:
            continue
        nr = int(m.group("num"))
        a1 = m.group("a1")
        a2 = m.group("a2")
        args = [a1]
        if a2 is not None:
            args.append(a2)
        calls.append({
            "nr": nr,
            "name": nr_to_name.get(nr, f"syscall_{nr}"),
            "args": args,
            "ret": None,    # AstryxOS [LINUX-SYS] does not log returns
            "errno": None,
            "raw": line,
            "seq": int(m.group("n")),
        })
    return calls


# ── Alignment + diff ─────────────────────────────────────────────────────────

# Many calls during the dynamic linker probe do not appear on AstryxOS because
# the guest filesystem layout differs (no glibc-hwcaps subdirs, no
# /etc/ld.so.cache, etc.).  When --skip-enoent-prefix is set we drop leading
# ENOENT openat/newfstatat/access calls from the native stream until the first
# successful one -- this aligns the streams to "real" work.
_PROBE_NAMES = {"openat", "newfstatat", "access", "stat", "fstat"}


def maybe_strip_enoent_prefix(native: List[Dict]) -> Tuple[List[Dict], int]:
    """Trim leading native-only noise that AstryxOS skips by construction.

    Two distinct kinds of leading entries are dropped:

    1. The initial ``execve(...)`` strace logs as the first event of the
       traced process — AstryxOS does not surface execve through
       ``[LINUX-SYS]`` because the tracer is enabled after the kernel jumps
       into the new ELF entry point.  Drop one execve at most.
    2. Any subsequent ``openat/newfstatat/access/stat/fstat`` that returns
       ``ENOENT`` until we hit the first non-ENOENT call.  These reflect the
       dynamic linker probing host-only directories (``/tmp/...`` from
       ``LD_LIBRARY_PATH``, ``glibc-hwcaps/x86-64-v4`` etc.) that simply do
       not exist on AstryxOS.
    """
    out: List[Dict] = []
    dropped = 0
    saw_execve = False
    in_prefix = True
    for c in native:
        if in_prefix and not saw_execve and c["name"] == "execve":
            saw_execve = True
            dropped += 1
            continue
        if in_prefix and c["name"] in _PROBE_NAMES and c["errno"] == "ENOENT":
            dropped += 1
            continue
        in_prefix = False
        out.append(c)
    return out, dropped


def filter_skip(stream: List[Dict], skip: set) -> List[Dict]:
    return [c for c in stream if c["name"] not in skip]


def classify_divergence(linux: Dict, astryx: Dict) -> str:
    if linux["nr"] != astryx["nr"]:
        return "missing_or_extra_call"
    # Same syscall — check observable shape on the AstryxOS side.
    # We don't have astryx returns, so we can only flag when args (in their
    # available subset) differ structurally.
    if linux.get("ret") is not None:
        ret = linux["ret"]
        if ret < 0 and not linux.get("errno"):
            return "return_value"
    return "args_or_seq_differ"


def diff_streams(linux: List[Dict], astryx: List[Dict],
                 context: int = 5) -> Dict:
    """Walk both lists in lock-step, return first index where nr disagrees."""
    n = min(len(linux), len(astryx))
    aligned = 0
    first = None
    for i in range(n):
        if linux[i]["nr"] == astryx[i]["nr"]:
            aligned += 1
            continue
        first = i
        break
    summary = {
        "linux_total_calls":    len(linux),
        "astryxos_total_calls": len(astryx),
        "aligned_calls":        aligned,
    }
    if first is None:
        if len(linux) > len(astryx):
            summary["divergence_class"] = "astryxos_truncated"
            tail_idx = len(astryx)
            return {
                "summary": summary,
                "first_divergence": {
                    "step_index": tail_idx,
                    "linux":   _summarize_call(linux[tail_idx]) if tail_idx < len(linux) else None,
                    "astryxos": None,
                },
                "context_lines": _ctx(linux, astryx, tail_idx, context),
            }
        if len(astryx) > len(linux):
            summary["divergence_class"] = "linux_truncated"
            tail_idx = len(linux)
            return {
                "summary": summary,
                "first_divergence": {
                    "step_index": tail_idx,
                    "linux":    None,
                    "astryxos": _summarize_call(astryx[tail_idx]) if tail_idx < len(astryx) else None,
                },
                "context_lines": _ctx(linux, astryx, tail_idx, context),
            }
        summary["divergence_class"] = "no_divergence"
        return {"summary": summary, "first_divergence": None, "context_lines": []}
    summary["divergence_class"] = classify_divergence(linux[first], astryx[first])
    return {
        "summary": summary,
        "first_divergence": {
            "step_index": first,
            "linux":   _summarize_call(linux[first]),
            "astryxos": _summarize_call(astryx[first]),
        },
        "context_lines": _ctx(linux, astryx, first, context),
    }


def _summarize_call(c: Dict) -> Dict:
    return {
        "nr":   c["nr"],
        "name": c["name"],
        "args": c["args"][:6],
        "ret":  c.get("ret"),
        "errno": c.get("errno"),
    }


def _ctx(linux: List[Dict], astryx: List[Dict], i: int, n: int) -> Dict:
    lo = max(0, i - n)
    hi_l = min(len(linux),  i + n + 1)
    hi_a = min(len(astryx), i + n + 1)
    return {
        "linux":    [_summarize_call(c) for c in linux[lo:hi_l]],
        "astryxos": [_summarize_call(c) for c in astryx[lo:hi_a]],
        "window_start": lo,
    }


# ── Driver ───────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Align and diff Firefox syscall streams "
                    "(native Linux vs AstryxOS).")
    ap.add_argument("--native-dir", required=True, type=Path,
                    help="Directory containing strace -ff trace.<tid> files.")
    ap.add_argument("--astryx-log", required=True, type=Path,
                    help="AstryxOS serial log path (.serial.log).")
    ap.add_argument("--native-tid", type=int, default=None,
                    help="If set, force the native main thread to "
                         "trace.<TID>; default = largest file.")
    ap.add_argument("--astryx-pid", type=int, default=1,
                    help="AstryxOS [LINUX-SYS] pid filter (default 1).")
    ap.add_argument("--skip", default="",
                    help="Comma-separated syscall names to skip on BOTH sides "
                         "before alignment (e.g. mmap,arch_prctl).")
    ap.add_argument("--skip-enoent-prefix", action="store_true",
                    help="Drop leading ENOENT openat/newfstatat/access on the "
                         "native side until the first non-ENOENT result. "
                         "Compensates for absent glibc-hwcaps directories.")
    ap.add_argument("--skip-enoent-probes", action="store_true",
                    help="Drop ALL ENOENT openat/newfstatat/access/stat/fstat "
                         "calls on the native side, not just the leading "
                         "prefix.  Useful when the host and AstryxOS have "
                         "different ld.so search-path layouts.")
    ap.add_argument("--context", type=int, default=5,
                    help="Number of preceding calls to include in output (5).")
    ap.add_argument("--debug", action="store_true",
                    help="Emit a side-by-side TSV-style debug table of the "
                         "first 200 aligned calls, in result['debug'].")
    args = ap.parse_args()

    nr_to_name, name_to_nr = load_syscall_table()
    main_file = find_main_strace_file(args.native_dir, args.native_tid)
    native = parse_strace_file(main_file, name_to_nr)
    astryx = parse_astryx_log(args.astryx_log, args.astryx_pid, nr_to_name)

    skip = set(s for s in args.skip.split(",") if s)
    enoent_dropped = 0
    enoent_probe_dropped = 0
    if args.skip_enoent_prefix:
        native, enoent_dropped = maybe_strip_enoent_prefix(native)
    if args.skip_enoent_probes:
        before = len(native)
        native = [c for c in native
                  if not (c["name"] in _PROBE_NAMES and c["errno"] == "ENOENT")]
        enoent_probe_dropped = before - len(native)
    if skip:
        native = filter_skip(native, skip)
        astryx = filter_skip(astryx, skip)

    result = diff_streams(native, astryx, context=args.context)
    result["meta"] = {
        "native_file":       str(main_file),
        "astryx_log":        str(args.astryx_log),
        "astryx_pid":        args.astryx_pid,
        "skip":              sorted(skip),
        "skip_enoent_prefix": args.skip_enoent_prefix,
        "enoent_prefix_dropped": enoent_dropped,
        "skip_enoent_probes": args.skip_enoent_probes,
        "enoent_probes_dropped": enoent_probe_dropped,
    }
    if args.debug:
        n = min(200, len(native), len(astryx))
        result["debug"] = [
            {
                "i":       i,
                "linux":   f"{native[i]['name']}({','.join(native[i]['args'][:3])})"
                           f" = {native[i].get('ret')} {native[i].get('errno') or ''}".strip(),
                "astryx":  f"{astryx[i]['name']} a1={astryx[i]['args'][0]}"
                           if i < len(astryx) else "<eof>",
                "match":   native[i]["nr"] == astryx[i]["nr"],
            }
            for i in range(n)
        ]
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
