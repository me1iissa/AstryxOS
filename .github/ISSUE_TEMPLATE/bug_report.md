---
name: Bug report
about: Something in AstryxOS misbehaves
title: "[BUG] "
labels: bug
assignees: ''
---

## Summary

<Short one-liner of what's wrong.>

## Environment

- Commit SHA: `<output of git rev-parse HEAD>`
- Host OS: `<uname -a or lsb_release -d>`
- QEMU version: `<qemu-system-x86_64 --version>`
- Rust toolchain: `<rustc +nightly --version>`

## Steps to Reproduce

1. `./build.sh release`
2. `python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300`
3. <what happens next>

## Expected vs. Observed

**Expected:** <what should happen>

**Observed:** <what actually happens>

## Serial Log Snippet

```
<paste the relevant 30-50 lines of build/test-serial.log>
```

## Additional Context

<any relevant screenshots, core dumps, additional commands tried>

## Checklist

- [ ] I ran `python3 scripts/watch-test.py` and not `bash scripts/run-test.sh --no-build`
- [ ] The bug is reproducible on a clean checkout
- [ ] I did not enable the `win32-pe-test` feature
- [ ] I searched existing issues before filing
