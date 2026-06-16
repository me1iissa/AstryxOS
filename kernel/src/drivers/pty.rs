//! Pseudo-Terminal (PTY) driver — /dev/ptmx + /dev/pts/N
//!
//! Provides up to 16 PTY pairs.  Opening `/dev/ptmx` allocates a pair and
//! returns the master fd; `ioctl(TIOCGPTN)` returns the slave number N;
//! opening `/dev/pts/N` gives the slave fd.
//!
//! Data written to the master appears on the slave's read buffer and vice
//! versa.  Each pair carries its own `Termios` so a TUI program flipping
//! its slave into raw mode does not perturb the kernel-console `TTY0`
//! state, and its own winsize so `TIOCGWINSZ` on the slave reports the
//! pair's dimensions (not TTY0's).
//!
//! Surface follows POSIX `termios(3)`, `pty(7)`, `pts(4)` and the Linux
//! ioctl numbering documented at
//! <https://www.kernel.org/doc/Documentation/admin-guide/devices.txt>
//! (major 5 minor 2 = /dev/ptmx, major 136..143 minor N = /dev/pts/N).
//!
//! `unlockpt` and `grantpt` are essentially no-ops here — there is no
//! POSIX-group `tty` to chown to on a FAT32 backing store, and the lock
//! flag is tracked but never enforced (matching the conventional Linux
//! behaviour where userspace `unlockpt(3)` is required for cleanliness
//! but the kernel does not reject opens on a locked pair).

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::tty::{Termios, Winsize, NCCS,
    ICRNL, INLCR, IGNCR, OPOST, ONLCR, CS8, CREAD, CLOCAL,
    ECHO, ECHOE, ICANON, ISIG, IEXTEN, NOFLSH,
    VINTR, VQUIT, VERASE, VKILL, VEOF, VTIME, VMIN,
    VSTART, VSTOP, VSUSP, VEOL, VREPRINT, VDISCARD, VWERASE, VLNEXT};
use crate::ipc::waitlist::{ring_poll_bell_for_obj, wake_tids, PollBellSource, WaitList};

/// Maximum simultaneous PTY pairs.
const MAX_PTYS: usize = 16;
/// Ring buffer capacity per direction.
const BUF_CAP: usize = 4096;

pub struct PtyPair {
    pub in_use:         bool,
    pub slave_locked:   bool,
    /// master→slave (written by master, read by slave)
    pub m2s: Vec<u8>,
    /// slave→master (written by slave, read by master)
    pub s2m: Vec<u8>,
    /// Per-pair termios state.  TUIs (vi, top, htop, tmux, nano) flip
    /// this to raw / non-canonical mode at startup and restore it at
    /// exit; keeping it per-pair (not on the global `TTY0`) ensures the
    /// kernel console is unaffected.  See POSIX `termios(3)`.
    pub termios: Termios,
    /// Per-pair window size.  Initialised to 80×24 (the historical VT100
    /// default) so a TUI that runs `TIOCGWINSZ` before the harness has
    /// pushed dimensions still sees a sane row/col pair.  Stored as the
    /// canonical Linux `struct winsize` layout (rows, cols, xpixel,
    /// ypixel).  See POSIX `tty_ioctl(4)` and `Documentation/admin-guide/
    /// devices.txt` section "PTY major/minor allocation".
    pub winsize: Winsize,
    /// Foreground process group.  Read by `tcgetpgrp(3)` and modified
    /// by `tcsetpgrp(3)`; v1 returns 0 if never set (POSIX leaves the
    /// return value implementation-defined for an un-associated TTY).
    pub fg_pgid: u32,
    /// Number of currently-open MASTER descriptors for this pair.  Bumped on
    /// `/dev/ptmx` open (which allocates the pair, so it starts at 1) and on
    /// `dup`; decremented on close.  When it reaches 0 the slave side is
    /// "hung up": a slave `read(2)` returns 0 (EOF) and a slave `poll(2)`
    /// reports `POLLHUP` (pts(4) / pty(7): closing the last master fd hangs
    /// up the slave, like SIGHUP on a real terminal).
    pub master_open: u32,
    /// Number of currently-open SLAVE descriptors.  Bumped on `/dev/pts/N`
    /// open and `dup`; decremented on close.  When it reaches 0 the master
    /// side sees EOF / `POLLHUP` symmetrically.
    pub slave_open: u32,
    /// Sticky flag: set the first time the slave is opened.  Distinguishes
    /// "slave never opened yet" (right after `alloc()` — the master must block,
    /// not EOF, since the server is about to fork a child that opens the slave)
    /// from "slave was opened and has since fully closed" (master EOF).  pts(4):
    /// the master sees hang-up only after the slave actually existed.
    pub slave_ever_opened: bool,
}

impl PtyPair {
    /// Const constructor used by callers that may want to pre-initialise
    /// a `PtyPair` outside the `PAIRS` array (e.g. tests).  Not used by
    /// the live allocation path — `alloc()` constructs entries directly
    /// into the static array — but kept public for symmetry with other
    /// driver-state types.
    #[allow(dead_code)]
    pub const fn empty() -> Self {
        Self {
            in_use:       false,
            slave_locked: true,
            m2s: Vec::new(),
            s2m: Vec::new(),
            termios: const_default_termios(),
            winsize: Winsize {
                ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0,
            },
            fg_pgid: 0,
            master_open: 0,
            slave_open: 0,
            slave_ever_opened: false,
        }
    }
}

/// `const` constructor for the default cooked-mode termios.  Mirrors
/// `Termios::default_cooked()` in `drivers::tty` but is usable from a
/// `const fn` context so `PtyPair::empty()` can be const-initialised.
/// Field-for-field equivalent; if either diverges from POSIX defaults the
/// other should follow.  See POSIX `termios(3)` for the c_iflag /
/// c_oflag / c_cflag / c_lflag baseline.
const fn const_default_termios() -> Termios {
    let mut c_cc = [0u8; NCCS];
    c_cc[VINTR]    = 3;     // ^C
    c_cc[VQUIT]    = 28;    // ^\
    c_cc[VERASE]   = 127;   // DEL
    c_cc[VKILL]    = 21;    // ^U
    c_cc[VEOF]     = 4;     // ^D
    c_cc[VTIME]    = 0;
    c_cc[VMIN]     = 1;
    c_cc[VSTART]   = 17;    // ^Q
    c_cc[VSTOP]    = 19;    // ^S
    c_cc[VSUSP]    = 26;    // ^Z
    c_cc[VEOL]     = 0;
    c_cc[VREPRINT] = 18;    // ^R
    c_cc[VDISCARD] = 15;    // ^O
    c_cc[VWERASE]  = 23;    // ^W
    c_cc[VLNEXT]   = 22;    // ^V
    Termios {
        c_iflag: ICRNL,
        c_oflag: OPOST | ONLCR,
        c_cflag: CS8 | CREAD | CLOCAL,
        c_lflag: ECHO | ECHOE | ICANON | ISIG | IEXTEN,
        c_line:  0,
        c_cc,
    }
}

// Static table — can't use Vec<PtyPair> in a static, so use Option array.
static PAIRS: Mutex<[Option<PtyPair>; MAX_PTYS]> =
    Mutex::new([const { None }; MAX_PTYS]);

// Per-pair reader wait lists, kept OUTSIDE `PAIRS` so `PAIRS` is never held
// across `schedule()`.  Lock order mirrors the pipe driver
// (`crate::ipc::pipe`): a waiter takes `*_WAITERS` then briefly `PAIRS` to
// re-check the condition; a writer/closer takes `PAIRS`, drops it, then takes
// `*_WAITERS` to wake.  No path holds both at once, so the two orders agree.
//
// `SLAVE_READ_WAITERS[n]` parks a thread blocked in `read(slave)` on an empty
// `m2s`; woken when a master write feeds `m2s` or the master hangs up.
// `MASTER_READ_WAITERS[n]` is the symmetric list for `read(master)` on `s2m`.
static SLAVE_READ_WAITERS:  Mutex<[Option<WaitList>; MAX_PTYS]> =
    Mutex::new([const { None }; MAX_PTYS]);
static MASTER_READ_WAITERS: Mutex<[Option<WaitList>; MAX_PTYS]> =
    Mutex::new([const { None }; MAX_PTYS]);

/// Outcome of a `wait_*_readable` prepare-to-park, mirroring the pipe driver's
/// `WaitOutcome`.  `Ready` = the condition (data, or peer hang-up giving EOF)
/// is already satisfied; `Enqueued` = the caller is parked and MUST call
/// `crate::sched::schedule()`; `Gone` = the pair was freed (treat as EOF).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitOutcome { Ready, Enqueued, Gone }

// ── Lifecycle ─────────────────────────────────────────────────────────────────

/// Allocate a new PTY pair.  Returns the PTY index (= slave number N) or
/// `None` if all pairs are in use.
pub fn alloc() -> Option<u8> {
    let mut pairs = PAIRS.lock();
    for (i, slot) in pairs.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(PtyPair {
                in_use:       true,
                slave_locked: true,
                m2s: Vec::new(),
                s2m: Vec::new(),
                termios: const_default_termios(),
                winsize: Winsize {
                    ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0,
                },
                fg_pgid: 0,
                // Opening /dev/ptmx both allocates the pair AND returns the
                // master fd, so the master starts with one open reference.
                master_open: 1,
                slave_open: 0,
                slave_ever_opened: false,
            });
            crate::serial_println!("[PTY] Allocated pair {}", i);
            return Some(i as u8);
        }
    }
    None
}

/// True if PTY pair `n` is currently allocated (both ends not yet freed).
///
/// Used by the `stat(2)` path for `/dev/pts/N` to distinguish a live slave
/// node from a stale one: per `pts(4)` the slave node exists only while the
/// pair is allocated, so a `stat` of a freed pair index must report ENOENT.
pub fn is_alive(n: u8) -> bool {
    let pairs = PAIRS.lock();
    pairs.get(n as usize).map(|s| s.is_some()).unwrap_or(false)
}

/// Unlock the slave side (called by `unlockpt`).
pub fn unlock_slave(n: u8) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.slave_locked = false;
    }
}

/// Free a PTY pair (called when both ends are closed).
pub fn free(n: u8) {
    let mut pairs = PAIRS.lock();
    if let Some(slot) = pairs.get_mut(n as usize) {
        *slot = None;
        crate::serial_println!("[PTY] Freed pair {}", n);
    }
}

// ── I/O ───────────────────────────────────────────────────────────────────────

/// Write to the master side (data appears on slave's read buffer).
///
/// Bytes land in the slave's input queue (`m2s`) after per-byte INPUT
/// processing governed by the SLAVE termios `c_iflag` (POSIX `termios(3)`):
/// `ICRNL` maps a carriage-return to a newline ("Translate carriage return to
/// newline on input", the cooked default), `INLCR` maps a newline to CR, and
/// `IGNCR` drops a carriage-return entirely.  This is what makes a typed Enter
/// — which an `ssh -tt` client sends as a bare CR — arrive at the shell as the
/// `\n` it expects to terminate a line.
///
/// If the slave's line discipline has `ECHO` set (`termios c_lflag & ECHO`, the
/// cooked-terminal default), the input is also echoed to the slave's OUTPUT —
/// i.e. copied into `s2m`, the master's read side — so a remote terminal driving
/// the master sees what it typed.  Per `termios(3)`, echo is emitted on the
/// slave's output path and is therefore subject to the same `OPOST|ONLCR`
/// output processing: an echoed newline becomes CR-NL, so a typed Enter shows
/// as a clean CRLF (cursor to column 0 + line feed) rather than a bare LF that
/// would leave the next prompt mid-line.  An interactive program that switches
/// the slave to raw mode (clearing `ECHO`) takes over echo itself, so this
/// kernel echo correctly goes silent then.
///
/// The return value is the number of *input* bytes consumed from `data` (POSIX
/// `write(2)` semantics), bounded by `m2s` capacity; echo is best-effort and
/// capacity-bounded so a flood never grows `s2m` unboundedly.
///
/// ## Signal generation (job control)
///
/// When the slave line discipline has `ISIG` set and is in canonical
/// (cooked) mode — the interactive-shell default (see `const_default_termios`)
/// — the special control characters generate a job-control signal to the
/// terminal's foreground process group instead of being queued as input, per
/// POSIX `termios(3)` "Special Characters" and the ISIG description:
///
///   * `VINTR` (`^C`, default 3)  → `SIGINT`
///   * `VQUIT` (`^\`, default 28) → `SIGQUIT`
///   * `VSUSP` (`^Z`, default 26) → `SIGTSTP`
///
/// The signal goes to the foreground pgrp recorded by `tcsetpgrp(3)` /
/// `ioctl(TIOCSPGRP)` (`fg_pgid`); a shell sets that to its launched
/// pipeline's pgid, so `^C` interrupts the running command, not the shell.
/// Unless `NOFLSH` is set, generating the signal also flushes the pending
/// input queue (`m2s`) so a half-typed line is discarded, matching the
/// canonical terminal behaviour.  When `ISIG` is clear or the slave is in
/// raw mode (`!ICANON` — an editor/pager/`less` owns the keystrokes), the
/// control byte is passed through unchanged.
///
/// The actual signal delivery (`signal::kill(-pgid, sig)`) takes
/// `PROCESS_TABLE`, so it is performed AFTER `PAIRS` is dropped — the same
/// lock-order discipline the wake helpers follow (`*_WAITERS`/`PROCESS_TABLE`
/// never nested under `PAIRS`).
pub fn master_write(n: u8, data: &[u8]) -> usize {
    // Signal to deliver to the foreground pgrp after dropping PAIRS, if a
    // control character was recognised: (pgid, signo).  Collected under the
    // lock, delivered after, so PROCESS_TABLE is never taken under PAIRS.
    let mut pending_signal: Option<(u32, u8)> = None;
    let consumed = {
        let mut pairs = PAIRS.lock();
        if let Some(Some(p)) = pairs.get_mut(n as usize) {
            let iflag = p.termios.c_iflag;
            let lflag = p.termios.c_lflag;
            let echo = lflag & ECHO != 0;
            let isig = lflag & ISIG != 0;
            let cooked = lflag & ICANON != 0;
            let noflsh = lflag & NOFLSH != 0;
            let vintr = p.termios.c_cc[VINTR];
            let vquit = p.termios.c_cc[VQUIT];
            let vsusp = p.termios.c_cc[VSUSP];
            let fg = p.fg_pgid;
            // Output processing for the echo mirrors slave_write (OPOST|ONLCR).
            let oproc = p.termios.c_oflag & OPOST != 0 && p.termios.c_oflag & ONLCR != 0;
            let mut consumed = 0usize;
            for &raw in data {
                // Job-control signal generation (ISIG in cooked mode).  The
                // control byte is consumed for signal generation and NOT
                // queued as input; only the FIRST recognised control byte in
                // this write generates a signal (a single keypress).  Per
                // termios(3), the comparison is against the *raw* byte (the
                // c_cc[] entries are stored as raw control codes), checked
                // before ICRNL/INLCR translation.
                if isig && cooked && pending_signal.is_none() {
                    let sig = if raw == vintr {
                        Some(crate::signal::SIGINT)
                    } else if raw == vquit {
                        Some(crate::signal::SIGQUIT)
                    } else if raw == vsusp {
                        Some(crate::signal::SIGTSTP)
                    } else {
                        None
                    };
                    if let Some(signo) = sig {
                        // Echo the control character as `^C` / `^\` / `^Z`
                        // (a printable caret + the letter) so the terminal
                        // shows the interrupt, matching the conventional
                        // cooked-terminal display.  Best-effort, space-bounded.
                        if echo {
                            let letter = b'@'.wrapping_add(raw); // raw 3 → 'C'
                            if BUF_CAP.saturating_sub(p.s2m.len()) >= 2 {
                                p.s2m.push(b'^');
                                p.s2m.push(letter);
                            }
                        }
                        // Unless NOFLSH, discard the pending (half-typed) input
                        // line — the canonical-terminal flush on signal.
                        if !noflsh {
                            p.m2s.clear();
                        }
                        // Record the target; deliver after PAIRS is dropped.
                        // fg_pgid==0 means no foreground pgrp was ever set
                        // (TIOCSPGRP never called) — drop the signal silently
                        // rather than broadcasting to pgid 0.
                        if fg != 0 {
                            pending_signal = Some((fg, signo));
                        }
                        consumed += 1;
                        continue;
                    }
                }
                // IGNCR: drop a CR before it reaches the input queue (still counts
                // as consumed — the byte was processed, just discarded).
                if raw == b'\r' && iflag & IGNCR != 0 {
                    consumed += 1;
                    continue;
                }
                // ICRNL: CR→NL.  INLCR: NL→CR.  (Mutually applied per byte.)
                let ch = if raw == b'\r' && iflag & ICRNL != 0 {
                    b'\n'
                } else if raw == b'\n' && iflag & INLCR != 0 {
                    b'\r'
                } else {
                    raw
                };
                if BUF_CAP.saturating_sub(p.m2s.len()) < 1 {
                    break; // input queue full — stop, report input consumed so far
                }
                p.m2s.push(ch);
                // ECHO of this processed input character onto the slave output.
                if echo {
                    if ch == b'\n' && oproc {
                        // Echoed newline → CR-NL (clean Enter), space permitting.
                        if BUF_CAP.saturating_sub(p.s2m.len()) >= 2 {
                            p.s2m.push(b'\r');
                            p.s2m.push(b'\n');
                        }
                    } else if BUF_CAP.saturating_sub(p.s2m.len()) >= 1 {
                        p.s2m.push(ch);
                    }
                }
                consumed += 1;
            }
            consumed
        } else {
            0
        }
    };
    // PAIRS is dropped — now safe to take PROCESS_TABLE for signal delivery.
    if let Some((pgid, signo)) = pending_signal {
        // kill(-pgid, sig): deliver to every process in the foreground group.
        // signal::kill already implements the negative-pid pgrp fan-out
        // (POSIX kill(2): "If pid is negative ... sig shall be sent to all
        // processes ... whose process group ID is equal to the absolute
        // value of pid").
        let target = -(pgid as i64) as u64;
        crate::signal::kill(target, signo);
    }
    consumed
}

/// Read from the master side (data written by slave).
pub fn master_read(n: u8, buf: &mut [u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let to_copy = buf.len().min(p.s2m.len());
        buf[..to_copy].copy_from_slice(&p.s2m[..to_copy]);
        p.s2m.drain(..to_copy);
        to_copy
    } else {
        0
    }
}

/// Returns true if the master read buffer (slave→master) has data.
pub fn master_readable(n: u8) -> bool {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| !p.s2m.is_empty())
        .unwrap_or(false)
}

/// Write to the slave side (data appears on master's read buffer).
///
/// This is the path the slave's stdout takes to reach a terminal driving the
/// master (e.g. an `ssh -tt` server relaying to its client).  Per POSIX
/// `termios(3)`, output written to a terminal is subject to output processing
/// governed by the SLAVE termios `c_oflag`: when `OPOST` is set (the framework
/// for implementation-defined output processing) and `ONLCR` is set ("Map NL to
/// CR-NL on output"), each newline is translated to a carriage-return + newline
/// so a line-oriented terminal returns the cursor to column 0 before advancing
/// — without it, each line drifts right (the "staircase").  `ONLCR` is the
/// default for a cooked terminal (see `const_default_termios`), and an
/// `openpty(3)`/`stty`-managed slave leaves it on; clearing it (`stty -onlcr`)
/// disables the translation, so the behaviour is strictly termios-driven.
///
/// We translate only a *bare* `\n` (one not already preceded by a `\r`) and pass
/// an existing `\r\n` through unchanged, so a writer that already emits CRLF is
/// not double-translated.  Only `ONLCR` is implemented; `ONLRET`/`OCRNL`/`ONOCR`
/// and tab/column expansion are intentionally left out (a raw byte stream needs
/// no column tracking).  Flow control is still driven by the destination ring:
/// the return value is the number of *input* bytes consumed (so a partial-fill
/// caused by a near-full `s2m` is reported in input units, as POSIX `write(2)`
/// expects), never more than `data.len()`.
pub fn slave_write(n: u8, data: &[u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let opost = p.termios.c_oflag & OPOST != 0;
        let onlcr = p.termios.c_oflag & ONLCR != 0;
        if opost && onlcr {
            // Translate slave output NL → CR-NL as bytes flow to the master.
            // Track whether the previous byte was a CR so an existing `\r\n`
            // is not turned into `\r\r\n` (only a bare `\n` gains a `\r`).
            // `prev_cr` is seeded from the last byte already queued in `s2m`
            // so the no-double-translate rule holds across successive writes.
            let mut prev_cr = p.s2m.last().copied() == Some(b'\r');
            let mut consumed = 0usize;
            for &b in data {
                if b == b'\n' && !prev_cr {
                    // A bare newline needs CR+LF — both bytes must fit, or we
                    // stop here (reporting only the fully-emitted input).
                    if BUF_CAP.saturating_sub(p.s2m.len()) < 2 {
                        break;
                    }
                    p.s2m.push(b'\r');
                    p.s2m.push(b'\n');
                } else {
                    if BUF_CAP.saturating_sub(p.s2m.len()) < 1 {
                        break;
                    }
                    p.s2m.push(b);
                }
                prev_cr = b == b'\r';
                consumed += 1;
            }
            consumed
        } else {
            // OPOST/ONLCR cleared (e.g. `stty -onlcr`, or a TUI in raw mode):
            // pass the bytes through verbatim.
            let space = BUF_CAP.saturating_sub(p.s2m.len());
            let to_copy = data.len().min(space);
            p.s2m.extend_from_slice(&data[..to_copy]);
            to_copy
        }
    } else {
        0
    }
}

/// Read from the slave side (data written by master).
pub fn slave_read(n: u8, buf: &mut [u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let to_copy = buf.len().min(p.m2s.len());
        buf[..to_copy].copy_from_slice(&p.m2s[..to_copy]);
        p.m2s.drain(..to_copy);
        to_copy
    } else {
        0
    }
}

/// Returns true if the slave read buffer (master→slave) has data.
pub fn slave_readable(n: u8) -> bool {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| !p.m2s.is_empty())
        .unwrap_or(false)
}

// ── Open-count / hang-up tracking ───────────────────────────────────────────
//
// pts(4) / pty(7): closing the LAST master fd hangs up the slave (slave reads
// then return 0/EOF and slave poll reports POLLHUP); symmetrically, closing
// the last slave fd makes the master see EOF/POLLHUP.  These counts let the
// read/poll paths distinguish "empty but peer still open → block" from
// "peer fully closed → EOF".

/// Bump the master open-count (a `dup` of a master fd).  `/dev/ptmx` open does
/// NOT call this — `alloc()` seeds `master_open = 1`.
pub fn inc_master(n: u8) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.master_open = p.master_open.saturating_add(1);
    }
}

/// Bump the slave open-count (open of `/dev/pts/N`, or a `dup`).  Sets the
/// sticky `slave_ever_opened` flag so the master's hang-up edge only fires
/// after the slave has actually existed (see `master_hung_up`).
pub fn inc_slave(n: u8) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.slave_open = p.slave_open.saturating_add(1);
        p.slave_ever_opened = true;
    }
}

/// Drop one master reference.  When it reaches 0 the slave is hung up: wake any
/// slave reader parked on an empty `m2s` so it observes EOF, and ring the poll
/// bell so a slave `poll(2)` re-evaluates and sees `POLLHUP`.  Returns the
/// remaining master count (0 ⇒ the pair may now be reaped when the slave side
/// is also gone — see `maybe_free`).
pub fn dec_master(n: u8) -> u32 {
    let remaining = {
        let mut pairs = PAIRS.lock();
        match pairs.get_mut(n as usize) {
            Some(Some(p)) => {
                p.master_open = p.master_open.saturating_sub(1);
                p.master_open
            }
            _ => return 0,
        }
    };
    if remaining == 0 {
        // Slave side is now hung up — wake its readers so an empty read
        // returns 0 (EOF) instead of blocking forever, and notify pollers.
        wake_slave_readers(n);
    }
    maybe_free(n);
    remaining
}

/// Drop one slave reference; symmetric to `dec_master`.
pub fn dec_slave(n: u8) -> u32 {
    let remaining = {
        let mut pairs = PAIRS.lock();
        match pairs.get_mut(n as usize) {
            Some(Some(p)) => {
                p.slave_open = p.slave_open.saturating_sub(1);
                p.slave_open
            }
            _ => return 0,
        }
    };
    if remaining == 0 {
        wake_master_readers(n);
    }
    maybe_free(n);
    remaining
}

/// Reap the pair once BOTH ends are fully closed.  Called from the close path;
/// a no-op while either end still has an open fd (pts(4): the slave node and
/// the pair exist only while the pair is in use).
fn maybe_free(n: u8) {
    let both_gone = {
        let pairs = PAIRS.lock();
        match pairs.get(n as usize).and_then(|s| s.as_ref()) {
            Some(p) => p.master_open == 0 && p.slave_open == 0,
            None => false,
        }
    };
    if both_gone {
        free(n);
        // Drop any stale wait-list slots for the reaped pair.
        SLAVE_READ_WAITERS.lock()[n as usize]  = None;
        MASTER_READ_WAITERS.lock()[n as usize] = None;
    }
}

/// True when the SLAVE side is hung up (last master fd closed).  A slave
/// `read(2)` of an empty `m2s` then returns 0 (EOF); a slave `poll(2)` reports
/// `POLLHUP`.  A freed/unknown pair counts as hung up (EOF, not a spin).
pub fn slave_hung_up(n: u8) -> bool {
    let pairs = PAIRS.lock();
    match pairs.get(n as usize).and_then(|s| s.as_ref()) {
        Some(p) => p.master_open == 0,
        None => true,
    }
}

/// True when the MASTER side is hung up (last slave fd closed).  Symmetric to
/// `slave_hung_up`.  Note: while the slave has never been opened
/// (`slave_open == 0` right after `alloc()`), the master is NOT yet hung up —
/// the slave fd is expected to open shortly (an `ssh -tt` server opens the
/// master, forks, and the child opens the slave).  We therefore only treat the
/// master as hung up once a slave HAS been opened and then all closed.  That
/// transition is tracked by `slave_ever_opened`.
pub fn master_hung_up(n: u8) -> bool {
    let pairs = PAIRS.lock();
    match pairs.get(n as usize).and_then(|s| s.as_ref()) {
        Some(p) => p.slave_open == 0 && p.slave_ever_opened,
        None => true,
    }
}

// ── Blocking-read prepare-to-park (mirrors crate::ipc::pipe) ─────────────────

/// Prepare to block a `read(slave)` that found `m2s` empty.  Re-checks the
/// condition (data available, OR slave hung up giving EOF) under the wait-list
/// lock to close the check-and-park lost-wakeup window, then parks the caller.
/// The caller MUST `schedule()` on `Enqueued`.
pub fn wait_slave_readable(n: u8, wake_tick: u64) -> WaitOutcome {
    let tid = crate::proc::current_tid();
    let mut waiters = SLAVE_READ_WAITERS.lock();
    let outcome = {
        let pairs = PAIRS.lock();
        match pairs.get(n as usize).and_then(|s| s.as_ref()) {
            None => WaitOutcome::Gone,
            // Data, or master-closed (EOF) — proceed without parking.
            Some(p) if !p.m2s.is_empty() || p.master_open == 0 => WaitOutcome::Ready,
            Some(_) => WaitOutcome::Enqueued,
        }
    };
    if matches!(outcome, WaitOutcome::Ready | WaitOutcome::Gone) {
        return outcome;
    }
    let slot = &mut waiters[n as usize];
    if slot.is_none() { *slot = Some(WaitList::new()); }
    slot.as_mut().unwrap().enqueue_self_blocked(tid, wake_tick);
    drop(waiters);
    WaitOutcome::Enqueued
}

/// Symmetric prepare-to-park for `read(master)` on an empty `s2m`.
pub fn wait_master_readable(n: u8, wake_tick: u64) -> WaitOutcome {
    let tid = crate::proc::current_tid();
    let mut waiters = MASTER_READ_WAITERS.lock();
    let outcome = {
        let pairs = PAIRS.lock();
        match pairs.get(n as usize).and_then(|s| s.as_ref()) {
            None => WaitOutcome::Gone,
            Some(p) if !p.s2m.is_empty() || (p.slave_open == 0 && p.slave_ever_opened)
                => WaitOutcome::Ready,
            Some(_) => WaitOutcome::Enqueued,
        }
    };
    if matches!(outcome, WaitOutcome::Ready | WaitOutcome::Gone) {
        return outcome;
    }
    let slot = &mut waiters[n as usize];
    if slot.is_none() { *slot = Some(WaitList::new()); }
    slot.as_mut().unwrap().enqueue_self_blocked(tid, wake_tick);
    drop(waiters);
    WaitOutcome::Enqueued
}

/// Wake every thread parked in `read(slave)` on pair `n`, and ring the poll
/// bell so slave-watching pollers re-evaluate.  Called after a master write
/// feeds `m2s` and on slave hang-up.  `PAIRS` must NOT be held by the caller
/// (lock order: `*_WAITERS` is taken here with no `PAIRS` hold).
pub fn wake_slave_readers(n: u8) {
    let drained = {
        let mut waiters = SLAVE_READ_WAITERS.lock();
        match waiters[n as usize].as_mut() {
            Some(list) => list.drain_all(),
            None => Vec::new(),
        }
    };
    wake_tids(&drained);
    ring_poll_bell_for_obj(PollBellSource::Pty, n as u64);
}

/// Wake every thread parked in `read(master)` on pair `n`; symmetric.
pub fn wake_master_readers(n: u8) {
    let drained = {
        let mut waiters = MASTER_READ_WAITERS.lock();
        match waiters[n as usize].as_mut() {
            Some(list) => list.drain_all(),
            None => Vec::new(),
        }
    };
    wake_tids(&drained);
    ring_poll_bell_for_obj(PollBellSource::Pty, n as u64);
}

/// Best-effort cleanup: drop `tid` from pair `n`'s slave-read wait list after a
/// timed-out / interrupted park, so a stale entry is never left behind.
pub fn waiter_cleanup_slave(n: u8, tid: u64) {
    let mut waiters = SLAVE_READ_WAITERS.lock();
    if let Some(list) = waiters[n as usize].as_mut() {
        list.remove_tid(tid);
    }
}

/// Symmetric cleanup for a master-read waiter.
pub fn waiter_cleanup_master(n: u8, tid: u64) {
    let mut waiters = MASTER_READ_WAITERS.lock();
    if let Some(list) = waiters[n as usize].as_mut() {
        list.remove_tid(tid);
    }
}

// ── Window size ───────────────────────────────────────────────────────────────

/// Returns `(cols, rows)` for `n`.  Falls back to 80×24 (the historical
/// VT100 default) on an unknown pair so a caller never sees a 0×0 winsize
/// which several ncurses entry points treat as fatal.
pub fn get_winsz(n: u8) -> (u16, u16) {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| (p.winsize.ws_col, p.winsize.ws_row))
        .unwrap_or((80, 24))
}

/// Set `(cols, rows)` for `n`.  Pixel dimensions are zeroed because
/// AstryxOS PTYs are character-only (no graphical backing) — matching the
/// convention used by `xterm` for non-graphical PTYs documented in POSIX
/// `tty_ioctl(4)`.  A future SIGWINCH delivery hook would fire here.
pub fn set_winsz(n: u8, cols: u16, rows: u16) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.winsize.ws_col = cols;
        p.winsize.ws_row = rows;
        p.winsize.ws_xpixel = 0;
        p.winsize.ws_ypixel = 0;
    }
}

/// Read the full `Winsize` struct for `n` (rows, cols, xpixel, ypixel).
/// Falls back to a sane 80×24 default on an unknown pair (see `get_winsz`).
pub fn get_winsize_full(n: u8) -> Winsize {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| p.winsize)
        .unwrap_or(Winsize {
            ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0,
        })
}

/// Write the full `Winsize` struct (including pixel dimensions) for `n`.
/// Used by `TIOCSWINSZ` ioctl handlers that may receive non-zero
/// `ws_xpixel`/`ws_ypixel` (e.g. terminal emulators that honour DPI).
pub fn set_winsize_full(n: u8, ws: Winsize) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.winsize = ws;
    }
}

// ── Per-pair termios ──────────────────────────────────────────────────────────

/// Get a copy of the pair's current `Termios`.  Falls back to POSIX
/// cooked-mode defaults on an unknown pair so `tcgetattr(3)` always
/// returns a valid struct rather than failing with EBADF — matching the
/// Linux ABI for an open PTY slave fd.
pub fn get_termios(n: u8) -> Termios {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| p.termios)
        .unwrap_or_else(|| const_default_termios())
}

/// Set the pair's `Termios`.  TUIs call this through `tcsetattr(3)` /
/// `ioctl(TCSETS)` to switch the PTY into raw mode at startup and
/// restore cooked mode at exit.  We do not validate flag combinations —
/// userspace owns that — and we do not generate SIGWINCH or similar
/// side effects.
pub fn set_termios(n: u8, t: Termios) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.termios = t;
    }
}

/// Set `Termios` and flush both ring buffers (TCSETSF semantics).  POSIX
/// `tcsetattr(3)` with `TCSAFLUSH` discards pending input + output before
/// applying the new attributes.
pub fn set_termios_flush(n: u8, t: Termios) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.termios = t;
        p.m2s.clear();
        p.s2m.clear();
    }
}

// ── Per-pair foreground pgrp ──────────────────────────────────────────────────

/// Return the foreground process group for `n` (0 if never set).  Read
/// by `tcgetpgrp(3)`.
pub fn get_fg_pgid(n: u8) -> u32 {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| p.fg_pgid)
        .unwrap_or(0)
}

/// Set the foreground process group.  Modified by `tcsetpgrp(3)` /
/// `ioctl(TIOCSPGRP)`.  v1 does not enforce session/process-group
/// membership — the value is recorded and returned faithfully.
pub fn set_fg_pgid(n: u8, pgid: u32) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.fg_pgid = pgid;
    }
}
