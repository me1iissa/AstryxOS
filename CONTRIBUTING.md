# Contributing to AstryxOS

Welcome. Before you do anything else, identify which guide applies to you.

---

## Human contributors

Read [HUMAN_CONTRIBUTING.md](HUMAN_CONTRIBUTING.md).

It covers: environment setup, branch naming, commit format, PR workflow,
test requirements, style guide, and how to file bugs.

---

## AI agent contributors (Claude, GPT, etc.)

Read [AI_CONTRIBUTING.md](AI_CONTRIBUTING.md).

It covers: worktree isolation, the canonical test command, known pitfalls
(conflict-marker awk hacks, win32-pe-test, commit identity), wave structure,
and how to extend the test suite autonomously.

---

## Everyone: process rules

These apply to all contributors, human or AI:

1. **One change per branch.** No drive-by refactors inside a feature branch.
2. **Tests are required.** Every new syscall or feature must ship with at
   least one headless test in `kernel/src/test_runner.rs`.
3. **The test suite must pass before merging.**
   Run `python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300`
   and confirm 139/140 (or better).
4. **Do not enable `win32-pe-test`** in CI or default builds. It hangs.
5. **No proprietary source citations.** ReactOS and Linux references are fine.
   Leaked Windows NT source trees are not.
