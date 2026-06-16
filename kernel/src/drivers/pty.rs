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
    ICRNL, OPOST, ONLCR, CS8, CREAD, CLOCAL,
    ECHO, ECHOE, ICANON, ISIG, IEXTEN,
    VINTR, VQUIT, VERASE, VKILL, VEOF, VTIME, VMIN,
    VSTART, VSTOP, VSUSP, VEOL, VREPRINT, VDISCARD, VWERASE, VLNEXT};

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
pub fn master_write(n: u8, data: &[u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let space = BUF_CAP.saturating_sub(p.m2s.len());
        let to_copy = data.len().min(space);
        p.m2s.extend_from_slice(&data[..to_copy]);
        to_copy
    } else {
        0
    }
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
pub fn slave_write(n: u8, data: &[u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let space = BUF_CAP.saturating_sub(p.s2m.len());
        let to_copy = data.len().min(space);
        p.s2m.extend_from_slice(&data[..to_copy]);
        to_copy
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
