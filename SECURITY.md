# Security Policy

## Supported Versions

AstryxOS is research software. Only the current `master` branch is supported.
Tagged releases are rare; when they happen, only the most recent tag receives
security updates.

| Version | Supported |
|---------|-----------|
| `master` | Yes |
| older tags | No |

## Reporting a Vulnerability

Please report security issues privately rather than filing a public GitHub
issue for anything that could be exploited.

**Preferred channel:** GitHub Security Advisories — open a private advisory at
<https://github.com/me1iissa/AstryxOS/security/advisories/new>.

**Fallback channel:** Email `184648288+me1iissa@users.noreply.github.com` with
the subject line `[SECURITY] <short description>`.

When reporting, please include:

- A short description of the issue
- Steps to reproduce (ideally a minimal test case or `/disk/bin/` binary)
- The git commit SHA or output of `git rev-parse HEAD`
- Your expected vs. observed behaviour
- Any mitigating factors you have already considered

## Disclosure Timeline

- Acknowledgement within **7 days** of receiving the report
- Initial assessment within **14 days**
- Fix targeted for **30 days** from report (complex issues may take longer;
  we will keep you updated)
- Public disclosure after the fix lands, with credit unless you request
  anonymity

## In Scope

- Kernel memory-safety bugs (use-after-free, out-of-bounds access, double
  free, stack/heap corruption)
- Privilege escalation from Ring 3 to Ring 0
- Sandbox or subsystem-isolation escapes (Linux ABI process escaping into
  Aether-native territory and vice versa)
- Buffer overruns in syscall argument handling
- Authentication or authorisation bypass (there is minimal auth; report if
  you find any that is bypassable)
- Path-traversal bugs in the VFS (`open("../../foo")` escaping mounts)
- Bugs enabling one process to read or write another's memory without the
  kernel's consent
- Issues in the dynamic linker path that could enable arbitrary code
  execution from a crafted ELF

## Out of Scope

- Denial of service via out-of-memory exhaustion (the OOM killer is in
  place; research-OS memory limits are not hardened)
- Crashes that only reproduce with the `win32-pe-test` feature flag
  enabled (the flag is off by default precisely because the path is known
  to be unstable)
- Bugs in clearly third-party code on `/disk/` (Firefox, glibc, musl,
  TinyCC) — please report those upstream
- Missing features that are already on the roadmap (see
  `docs/DEVELOPMENT_PLAN.md`)

## Hall of Fame

None yet. First reporter gets the first entry.
