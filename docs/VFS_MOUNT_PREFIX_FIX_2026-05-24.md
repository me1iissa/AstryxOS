# VFS substrate — Linux personality CWD-aware path resolution (2026-05-24)

## Goal

Close the substrate gap that blocked `git commit`, `git log`,
`git cat-file -p HEAD:hello.txt`, and any utility that calls `open(2)`,
`readlink(2)`, `truncate(2)`, `chmod(2)`, or `symlink(2)` with a path
relative to the process working directory.

## Symptom

Per `docs/PIVOT_E_TIER_D_2026-05-24.md` (the PIVOT-E Tier D dispatch that
shipped git on AstryxOS), Phase 2 reached 3/6 with `git commit`,
`git log`, and `git cat-file` all failing.  The git commit failure was
the most informative:

```
[BBDEMO] git-commit | Untracked files:
[BBDEMO] git-commit |   (use "git add <file>..." to include in what will be committed)
[BBDEMO] git-commit |   dev/
[BBDEMO] git-commit |   disk/
[BBDEMO] git-commit |   esting
[BBDEMO] git-commit |   etc/
[BBDEMO] git-commit |   lib
[BBDEMO] git-commit |   lib64
[BBDEMO] git-commit |   mnt/
[BBDEMO] git-commit |   opt
[BBDEMO] git-commit |   proc/
[BBDEMO] git-commit |   sys/
[BBDEMO] git-commit |   tmp/
[BBDEMO] git-commit |   usr
[BBDEMO] git-commit |   var/
```

`git` (cwd `/tmp/repo`, `--git-dir=/tmp/repo/.git`,
`--work-tree=/tmp/repo`) was walking what it believed was the work-tree
and getting back the entries of the ROOT mount, not `/tmp/repo`.

## Root cause

Targeted diagnostic in `sys_getdents64` plus a wider probe at the
`sys_open_linux` entry showed the precise failure mode:

```
[VFS/sys_open_linux-DIAG] path='.' cwd='/tmp/repo' pid=6
[VFS/getdents64-DIAG] fd=3 open_path='.' mount_idx=0 inode=1 entries=16
    first20=[dev,tmp,home,bin,etc,lib,lib64,usr,opt,var,root,proc,sys,mnt,disk,esting,]
```

`git` calls the legacy single-path `open(2)` (syscall 2) with relative
paths like `.`, `file_a`, and `sub/file_b`.  Per POSIX
(IEEE Std 1003.1-2017 `open(2)` §RATIONALE, and
`man 7 path_resolution`):

> *"If a pathname begins with the slash character ('/'), the
>  predecessor of the first filename in the pathname shall be taken to
>  be the root directory of the process. If a pathname does not begin
>  with a slash, the predecessor of the first filename in the pathname
>  shall be taken to be the current working directory of the process."*

AstryxOS's `crate::vfs::resolve_path_opts` is intentionally CWD-blind —
every input is anchored at `/`.  The Linux personality dispatch
(`sys_openat` AT_FDCWD, `sys_stat_linux`, `sys_access`,
`sys_mkdir_linux`, `sys_rmdir_linux`, `sys_unlink_linux`) was updated
in PIVOT-E Tier D (PR #452) to resolve relative paths against
`Process::cwd` before handing off, but FIVE adjacent syscalls were
missed:

| #  | Name        | Symptom in git                       |
|----|-------------|--------------------------------------|
|  2 | `open`      | `open(".")` resolves to `/` not cwd  |
| 76 | `truncate`  | `truncate("file_a", 0)` → `/file_a`  |
| 88 | `symlink`   | `symlink(t, "newname")` → `/newname` |
| 89 | `readlink`  | `readlink("link")` → readlink of `/link` |
| 90 | `chmod`     | `chmod("file_a", 0o644)` → `/file_a` |

For `open(2)`, the open-path stored on the resulting fd is the verbatim
relative path the caller supplied — so subsequent `getdents64(fd)`
reads the inode the resolver picked (root, inode 1) and returns its
entries, exactly as observed.

The "esting" entry visible in the git output is the alphabetically-sorted
display of the ROOT-mount entry `disk/` followed by the prefix `\t`
indent that git uses for untracked entries, with the leading `t` of
`testing` ... actually it is the entry `esting` ; the JSON-escape
`\testing` is `TAB + esting` and `esting` collates between `disk` and
`etc`.  No matter — the broader symptom is unambiguous: every entry
shown is a child of `/`.

## Fix

Five surgical changes in `kernel/src/subsys/linux/syscall.rs`,
mirroring the established pattern (PR #452, `sys_stat_linux` /
`sys_access`):

1. `sys_open_linux_inner` (syscall #2): resolve relative `path_raw`
   against `Process::cwd` BEFORE entering the special-path matchers
   (`/dev/dsp`, `/dev/vport0p0`, `/dev/ptmx`, `/dev/pts/N`) so the
   downstream `crate::vfs::open` sees a fully-anchored absolute path.
   Empty paths fall through unchanged so POSIX `ENOENT` semantics are
   preserved.
2. Syscall #76 `truncate`: route the path through
   `resolve_user_path_to_owned()`, the shared helper that prefixes
   `Process::cwd` for relative paths (already used by `sys_mkdir_linux`
   et al).
3. Syscall #88 `symlink`: apply the same prefix to `newpath`.  The
   `oldpath`/`target` is OPAQUE link content per POSIX (`symlink(2)`:
   the contents may be relative and are resolved at link traversal
   time, not at creation) — it is stored verbatim.
4. Syscall #89 `readlink`: same prefix on the link-path argument
   (inline, since the handler has its own /proc/self/{exe,cwd,fd}
   special cases that should still match by absolute path).
5. Syscall #90 `chmod`: route through `resolve_user_path_to_owned`.

## Why fix it in the personality layer

`crate::vfs::resolve_path_opts` could in principle be made CWD-aware
directly.  We deliberately keep it CWD-blind because:

* Many kernel-internal callers (`test_runner`, the boot-time `init`
  sequence in `vfs::init`, the `/proc/<pid>/*` synthesis paths) pass
  absolute paths and would observe surprising new behaviour if the
  CWD ever leaked in from a stale per-CPU register.
* The POSIX rule applies at the *system-call* boundary
  (`man 7 path_resolution`).  The VFS layer's job is to walk a
  canonical absolute path; the personality layer's job is to apply
  the POSIX rules that convert userspace's (dirfd, pathname) tuple
  into one.  Keeping the layering crisp matches Linux's own internal
  `getname_flags()` / `filename_lookup()` split.

## Verification

### Phase 2 (was 3/6, now 6/6)

```
[PIVOT-E-GIT] === Phase 2 — local-only init/add/commit ===
[PIVOT-E-GIT]   git-version    PASS rc=0 bytes=19 banner=true
[PIVOT-E-GIT]   git-init       PASS rc=0 bytes=52 banner=true
[PIVOT-E-GIT]   git-add        PASS rc=0 bytes=0  banner=true
[PIVOT-E-GIT]   git-commit     PASS rc=0 bytes=158 banner=true
[PIVOT-E-GIT]   git-log        PASS rc=0 bytes=33 banner=true
[PIVOT-E-GIT]   git-cat-file   PASS rc=0 bytes=12 banner=true
[PIVOT-E-GIT] === Phase 2 SUMMARY === pass=6/6
```

All six local-only git steps pass.  `git commit` creates the initial
commit, `git log --oneline` shows it, `git cat-file -p HEAD:hello.txt`
prints `hello world`.

### Phase 3 (git clone https://) — not closed by this PR

```
[BBDEMO] git-clone-https | fatal: unable to find remote helper for 'https'
```

`git-remote-http` IS staged at `/disk/usr/libexec/git-core/` but git
looks up `git-remote-https` first (Alpine's package layout has it as a
symlink to `git-remote-http`; FAT32 has no symlinks so the alias is
lost).  Closing Phase 3 needs the staging script to install a SECOND
copy of `git-remote-http` under the name `git-remote-https` — orthogonal
to the VFS substrate and tracked as PIVOT-E Tier D follow-up.

### Regression check

`--features test-mode` full suite: **286 PASS, 8 FAIL**.  The 8 failures
match the pre-existing allowlist documented in the W215 / PIVOT bring-up
notes (Musl hello / TCC compile / glibc_hello / sigchld / ascension all
depend on artefacts staged via `--firefox-test` or `--build-tcc.sh`;
unix-socketpair-epollin, monotonic-rate, and execve_leak pre-date this
work).  No new regressions.

The new test
`Linux open/readlink/truncate/chmod/symlink: relative-path CWD
resolution` passes, exercising
`sys_open_linux(".", O_RDONLY)`,
`sys_open_linux("file_a", O_RDONLY)`,
`sys_open_linux("sub/file_b", O_RDONLY)`, and
`sys_open_linux("/tmp/cwdtest/file_a", O_RDONLY)` from a process whose
cwd is `/tmp/cwdtest`, asserting that each fd's inode matches what
`crate::vfs::stat` returns for the explicit absolute path.

## References

* POSIX (IEEE Std 1003.1-2017):
  - `open(2)`:    <https://pubs.opengroup.org/onlinepubs/9699919799/functions/open.html>
  - `readlink(2)`: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/readlink.html>
  - `truncate(2)`: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/truncate.html>
  - `chmod(2)`:    <https://pubs.opengroup.org/onlinepubs/9699919799/functions/chmod.html>
  - `symlink(2)`:  <https://pubs.opengroup.org/onlinepubs/9699919799/functions/symlink.html>
  - Pathname resolution §4.13: <https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_13>
* Linux man pages:
  - `path_resolution(7)`: <https://man7.org/linux/man-pages/man7/path_resolution.7.html>
  - `open(2)`: <https://man7.org/linux/man-pages/man2/open.2.html>
* Related prior work: `docs/PIVOT_E_TIER_D_2026-05-24.md` (the dispatch
  that named the substrate gap and shipped the parallel openat /
  stat / access / mkdir / rmdir / unlink fixes).
