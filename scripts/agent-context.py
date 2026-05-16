#!/usr/bin/env python3
"""
agent-context.py — Live shared-context helper for AstryxOS agent sessions.

Non-interactive, one-shot argv, JSON output. All subcommands exit cleanly with
structured output. File locking ensures safe concurrent appends from parallel
agents.

Session files:
  .claude/session/CURRENT.md   — coordinator-maintained live state (≤200 lines default, see _DEFAULT_MAX_LINES)
  .claude/session/EVENTS.jsonl — append-only event stream (one JSON per line)

Subcommands:

  read-current [--section SECTION] [--json]
      Print CURRENT.md (or a named section) to stdout.
      --json wraps output in {"ok": true, "content": "..."}.

  append-event <kind> --agent-id <id> --payload '<json>'
      Atomically append one event line to EVENTS.jsonl.
      kind: dispatch|completion|decision|finding|pivot|pr_merged|pr_opened

  digest-since <ts>
      Emit a compact summary of events since ISO timestamp.
      Output: {"ok": true, "events": [...], "count": N}

  register-dispatch --agent-id <id> --role <role> --task <task>
                    [--parent <parent>]
      Append a `dispatch` event AND update CURRENT.md "Active investigations".

  register-completion --agent-id <id> --outcome <text>
                      [--commits <sha,sha>] [--pr <#NNN>]
      Append a `completion` event AND move entry from "Active investigations"
      to "Recent findings" in CURRENT.md. Prunes old entries to keep ≤200 lines.

  prune-current [--max-lines N]
      Trim CURRENT.md to ≤N lines (default 200) by dropping oldest list entries
      in each rolling section.

  summary
      Print a one-paragraph plain-text summary of current session state.
      Output: {"ok": true, "summary": "..."}
"""

import argparse
import datetime
import fcntl
import json
import os
import re
import sys
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SESSION_DIR = _REPO_ROOT / ".claude" / "session"
_CURRENT_MD = _SESSION_DIR / "CURRENT.md"
_EVENTS_JSONL = _SESSION_DIR / "EVENTS.jsonl"

_SECTION_MAX = {
    "Active investigations": 10,
    "Open PRs": 20,
    "Recent decisions": 10,
    "Known gates / not-yet-investigated": 20,
    "Recent findings": 10,
    "Quick links": 30,
}
_DEFAULT_MAX_LINES = 200

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _out(obj: dict) -> None:
    print(json.dumps(obj))


def _err(msg: str, code: int = 1) -> None:
    print(json.dumps({"ok": False, "error": msg}))
    sys.exit(code)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_session_dir() -> None:
    _SESSION_DIR.mkdir(parents=True, exist_ok=True)


def _lock_file(path: Path):
    """Open + exclusive-lock path for atomic read-modify-write; returns file obj."""
    fh = open(path, "a+")  # 'a+' creates if missing, positions at end for appends
    fcntl.flock(fh, fcntl.LOCK_EX)
    fh.seek(0)
    return fh


# ---------------------------------------------------------------------------
# CURRENT.md section parsing
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^## (.+)$", re.MULTILINE)


def _parse_sections(text: str) -> dict[str, tuple[int, int, str]]:
    """Return {section_name: (header_idx, end_idx, body_text)}.

    All indices are 0-based into text.splitlines(keepends=True).
    header_idx   — index of the '## ...' header line.
    end_idx      — exclusive end of this section's content (= next header or EOF).
    body_text    — stripped body text (excluding the header line itself).
    """
    lines = text.splitlines(keepends=True)
    sections: dict[str, tuple[int, int, str]] = {}
    headers: list[tuple[str, int]] = []  # (name, 0-based-line-index)

    for i, line in enumerate(lines):
        m = _SECTION_RE.match(line.rstrip())
        if m:
            headers.append((m.group(1), i))

    for idx, (name, start) in enumerate(headers):
        end = headers[idx + 1][1] if idx + 1 < len(headers) else len(lines)
        body = "".join(lines[start + 1:end])
        sections[name] = (start, end, body.strip())

    return sections


def _read_current_md() -> str:
    if not _CURRENT_MD.exists():
        return ""
    return _CURRENT_MD.read_text(encoding="utf-8")


def _write_current_md(text: str) -> None:
    _ensure_session_dir()
    _CURRENT_MD.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Rolling-section append helper
# ---------------------------------------------------------------------------

def _prepend_to_section(md_text: str, section: str, new_entry: str,
                         max_entries: int) -> str:
    """
    Prepend `new_entry` (a bullet line, no leading newline) to the named section.
    Trims old entries beyond max_entries. Returns updated markdown text.
    """
    lines = md_text.splitlines(keepends=True)
    sections = _parse_sections(md_text)

    if section not in sections:
        # Append a new section
        tail = f"\n## {section}\n- {new_entry}\n"
        return md_text + tail

    header_idx, end_idx, _ = sections[section]
    # header_idx is the ## header line (0-based); body starts at header_idx+1
    body_start = header_idx + 1  # 0-based index of first body line
    body_end = end_idx           # 0-based exclusive

    # Collect current bullet lines in the body
    body_lines = lines[body_start:body_end]
    bullets = [l for l in body_lines if l.strip().startswith("-")]
    non_bullets = [l for l in body_lines if not l.strip().startswith("-")]

    # Insert new bullet at front, trim to max
    new_bullets = [f"- {new_entry}\n"] + bullets
    if len(new_bullets) > max_entries:
        new_bullets = new_bullets[:max_entries]

    new_body = non_bullets + new_bullets

    new_lines = lines[:body_start] + new_body + lines[body_end:]
    return "".join(new_lines)


def _remove_from_section(md_text: str, section: str, pattern: str) -> str:
    """Remove bullet lines matching pattern (substring) from section."""
    lines = md_text.splitlines(keepends=True)
    sections = _parse_sections(md_text)
    if section not in sections:
        return md_text

    header_idx, end_idx, _ = sections[section]
    body_start = header_idx + 1  # first body line
    body_end = end_idx           # exclusive

    new_lines = []
    for i, line in enumerate(lines):
        if body_start <= i < body_end and line.strip().startswith("-") and pattern in line:
            continue
        new_lines.append(line)
    return "".join(new_lines)


# ---------------------------------------------------------------------------
# Subcommand: read-current
# ---------------------------------------------------------------------------

def cmd_read_current(args) -> None:
    text = _read_current_md()
    if not text:
        if args.json:
            _out({"ok": True, "content": "", "exists": False})
        else:
            print("(CURRENT.md not found — run coordinator to seed it)")
        return

    if args.section:
        sections = _parse_sections(text)
        name = args.section
        if name not in sections:
            available = list(sections.keys())
            if args.json:
                _out({"ok": False, "error": f"section '{name}' not found",
                      "available": available})
            else:
                print(f"Section '{name}' not found. Available: {available}",
                      file=sys.stderr)
            sys.exit(1)
        content = f"## {name}\n{sections[name][2]}"
    else:
        content = text

    if args.json:
        _out({"ok": True, "content": content})
    else:
        print(content, end="" if content.endswith("\n") else "\n")


# ---------------------------------------------------------------------------
# Subcommand: append-event
# ---------------------------------------------------------------------------

def cmd_append_event(args) -> None:
    _ensure_session_dir()
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        _err(f"payload is not valid JSON: {exc}")

    event = {
        "ts": _now_iso(),
        "kind": args.kind,
        "agent_id": args.agent_id,
        **payload,
    }
    line = json.dumps(event) + "\n"

    with open(_EVENTS_JSONL, "a", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.write(line)
        fcntl.flock(fh, fcntl.LOCK_UN)

    _out({"ok": True, "event": event})


# ---------------------------------------------------------------------------
# Subcommand: digest-since
# ---------------------------------------------------------------------------

def cmd_digest_since(args) -> None:
    since_ts = args.ts
    if not _EVENTS_JSONL.exists():
        _out({"ok": True, "events": [], "count": 0, "since": since_ts})
        return

    events = []
    with open(_EVENTS_JSONL, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("ts", "") >= since_ts:
                events.append(ev)

    _out({"ok": True, "events": events, "count": len(events), "since": since_ts})


# ---------------------------------------------------------------------------
# Subcommand: register-dispatch
# ---------------------------------------------------------------------------

def cmd_register_dispatch(args) -> None:
    _ensure_session_dir()
    ts = _now_iso()

    # Append dispatch event
    event = {
        "ts": ts,
        "kind": "dispatch",
        "agent_id": args.agent_id,
        "role": args.role,
        "task": args.task,
        "parent": args.parent or "coordinator",
    }
    with open(_EVENTS_JSONL, "a", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.write(json.dumps(event) + "\n")
        fcntl.flock(fh, fcntl.LOCK_UN)

    # Update CURRENT.md
    entry = f"`{args.agent_id[:8]}` ({args.role}) — {args.task}"
    with _lock_file(_CURRENT_MD) as fh:
        text = fh.read()
        text = _prepend_to_section(text, "Active investigations", entry,
                                   _SECTION_MAX["Active investigations"])
        fh.seek(0)
        fh.truncate()
        fh.write(text)

    _out({"ok": True, "event": event,
          "current_updated": True,
          "section": "Active investigations"})


# ---------------------------------------------------------------------------
# Subcommand: register-completion
# ---------------------------------------------------------------------------

def cmd_register_completion(args) -> None:
    _ensure_session_dir()
    ts = _now_iso()
    commits = [c.strip() for c in args.commits.split(",") if c.strip()] if args.commits else []

    event = {
        "ts": ts,
        "kind": "completion",
        "agent_id": args.agent_id,
        "outcome_summary": args.outcome,
        "commits": commits,
        "pr": args.pr or "",
    }
    with open(_EVENTS_JSONL, "a", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.write(json.dumps(event) + "\n")
        fcntl.flock(fh, fcntl.LOCK_UN)

    # Update CURRENT.md: remove from Active investigations, add to Recent findings
    pr_tag = f" ({args.pr})" if args.pr else ""
    commit_tag = f" [{commits[0][:8]}]" if commits else ""
    finding_entry = (
        f"`{args.agent_id[:8]}` — {args.outcome}{pr_tag}{commit_tag}"
    )
    with _lock_file(_CURRENT_MD) as fh:
        text = fh.read()
        # Remove matching active-investigations entry (match by agent_id prefix)
        text = _remove_from_section(text, "Active investigations", args.agent_id[:8])
        # Add to Recent findings
        text = _prepend_to_section(text, "Recent findings", finding_entry,
                                   _SECTION_MAX["Recent findings"])
        # Prune overall length
        text = _do_prune(text, _DEFAULT_MAX_LINES)
        fh.seek(0)
        fh.truncate()
        fh.write(text)

    _out({"ok": True, "event": event,
          "current_updated": True,
          "sections": ["Active investigations", "Recent findings"]})


# ---------------------------------------------------------------------------
# Subcommand: prune-current
# ---------------------------------------------------------------------------

def _do_prune(text: str, max_lines: int) -> str:
    """
    Prune rolling sections so the total line count stays under max_lines.
    For each section that has a defined max-entries cap, trim oldest bullets first.
    Then hard-trim overall document if still over max_lines.
    """
    # Per-section entry caps
    for section, cap in _SECTION_MAX.items():
        lines = text.splitlines(keepends=True)
        sections = _parse_sections(text)
        if section not in sections:
            continue
        header_idx, end_idx, _ = sections[section]
        body_lines = lines[header_idx + 1:end_idx]
        bullets = [l for l in body_lines if l.strip().startswith("-")]
        if len(bullets) > cap:
            # Remove oldest (last) bullets beyond cap
            to_remove = bullets[cap:]
            for b in to_remove:
                text = text.replace(b, "", 1)

    # Hard line cap: drop trailing lines from last section if still over
    all_lines = text.splitlines(keepends=True)
    if len(all_lines) > max_lines:
        text = "".join(all_lines[:max_lines])

    return text


def cmd_prune_current(args) -> None:
    max_lines = args.max_lines
    if not _CURRENT_MD.exists():
        _out({"ok": True, "pruned": False, "reason": "CURRENT.md not found"})
        return

    with _lock_file(_CURRENT_MD) as fh:
        text = fh.read()
        before = len(text.splitlines())
        text = _do_prune(text, max_lines)
        after = len(text.splitlines())
        fh.seek(0)
        fh.truncate()
        fh.write(text)

    _out({"ok": True, "pruned": True, "lines_before": before,
          "lines_after": after, "max_lines": max_lines})


# ---------------------------------------------------------------------------
# Subcommand: summary
# ---------------------------------------------------------------------------

def cmd_summary(args) -> None:
    text = _read_current_md()
    if not text:
        _out({"ok": True, "summary": "No session context found (CURRENT.md missing)."})
        return

    sections = _parse_sections(text)

    goal = sections.get("Goal", (0, 0, "(unknown)"))[2]
    active = sections.get("Active investigations", (0, 0, ""))[2]
    findings = sections.get("Recent findings", (0, 0, ""))[2]
    gates = sections.get("Known gates / not-yet-investigated", (0, 0, ""))[2]

    active_count = len([l for l in active.splitlines() if l.strip().startswith("-")])
    findings_count = len([l for l in findings.splitlines() if l.strip().startswith("-")])
    gate_count = len([l for l in gates.splitlines() if l.strip().startswith("-")])

    # Event counts
    event_count = 0
    if _EVENTS_JSONL.exists():
        with open(_EVENTS_JSONL, "r", encoding="utf-8") as fh:
            event_count = sum(1 for l in fh if l.strip())

    summary = (
        f"Goal: {goal.strip()}. "
        f"{active_count} active investigation(s) in flight. "
        f"{findings_count} recent finding(s) recorded. "
        f"{gate_count} known gate(s) / backlog item(s). "
        f"{event_count} total events in EVENTS.jsonl."
    )
    _out({"ok": True, "summary": summary,
          "active_count": active_count,
          "findings_count": findings_count,
          "gate_count": gate_count,
          "event_count": event_count})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-context.py",
        description="Live shared-context helper for AstryxOS agent sessions.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # read-current
    p_rc = sub.add_parser("read-current",
                           help="Print CURRENT.md (or a named section)")
    p_rc.add_argument("--section", metavar="NAME",
                      help="Only print this section (e.g. 'Goal')")
    p_rc.add_argument("--json", action="store_true",
                      help="Wrap output in JSON envelope")

    # append-event
    p_ae = sub.add_parser("append-event",
                           help="Append one event to EVENTS.jsonl")
    p_ae.add_argument("kind",
                      choices=["dispatch", "completion", "decision",
                               "finding", "pivot", "pr_merged", "pr_opened"])
    p_ae.add_argument("--agent-id", required=True)
    p_ae.add_argument("--payload", required=True,
                      help="JSON object to merge into event (must be valid JSON)")

    # digest-since
    p_ds = sub.add_parser("digest-since",
                           help="Summarize events since ISO timestamp")
    p_ds.add_argument("ts", metavar="TIMESTAMP",
                      help="ISO 8601 timestamp (e.g. 2026-05-16T00:00:00Z)")

    # register-dispatch
    p_rd = sub.add_parser("register-dispatch",
                           help="Record dispatch event + update CURRENT.md")
    p_rd.add_argument("--agent-id", required=True)
    p_rd.add_argument("--role", required=True)
    p_rd.add_argument("--task", required=True)
    p_rd.add_argument("--parent", default="coordinator")

    # register-completion
    p_rco = sub.add_parser("register-completion",
                            help="Record completion event + update CURRENT.md")
    p_rco.add_argument("--agent-id", required=True)
    p_rco.add_argument("--outcome", required=True)
    p_rco.add_argument("--commits", default="",
                       metavar="SHA,SHA",
                       help="Comma-separated commit SHAs")
    p_rco.add_argument("--pr", default="",
                       help="PR reference e.g. #238")

    # prune-current
    p_pc = sub.add_parser("prune-current",
                           help="Trim CURRENT.md to max lines")
    p_pc.add_argument("--max-lines", type=int, default=_DEFAULT_MAX_LINES,
                      metavar="N")

    # summary
    sub.add_parser("summary",
                   help="One-paragraph summary of session state")

    args = parser.parse_args()

    dispatch = {
        "read-current":       cmd_read_current,
        "append-event":       cmd_append_event,
        "digest-since":       cmd_digest_since,
        "register-dispatch":  cmd_register_dispatch,
        "register-completion": cmd_register_completion,
        "prune-current":      cmd_prune_current,
        "summary":            cmd_summary,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
