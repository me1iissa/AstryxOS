//! X11 server — in-kernel Xastryx implementation.
//!
//! Listens on the AF_UNIX path `/tmp/.X11-unix/X0`.
//!
//! # Supported opcodes
//! - Connection setup (little-endian only).
//! - Window lifecycle: CreateWindow(1), ChangeWindowAttrs(2), GetWindowAttrs(3),
//!   DestroyWindow(4), MapWindow(8), UnmapWindow(10), ConfigureWindow(12),
//!   GetGeometry(14), QueryTree(15).
//! - Atoms: InternAtom(16), GetAtomName(17).
//! - Properties: ChangeProperty(18), DeleteProperty(19), GetProperty(20), ListProperties(21).
//! - Input: SelectInput(25), Grab/Ungrab Pointer/Button/Keyboard(26-32), WarpPointer(41),
//!   SetInputFocus(42), GetInputFocus(43), QueryKeymap(44).
//! - Fonts: OpenFont(45), CloseFont(46), QueryFont(47), ListFonts(49).
//! - Pixmaps: CreatePixmap(53), FreePixmap(54).
//! - GCs: CreateGC(55), ChangeGC(56), CopyGC(57), FreeGC(60).
//! - Drawing: ClearArea(61), CopyArea(62), PolyFillRectangle(70), PutImage(72),
//!   ImageText8(76), ImageText16(77).
//! - Colormaps: CreateColormap(78), FreeColormap(79), AllocColor(84), QueryColors(91).
//! - Extensions: QueryExtension(98), ListExtensions(99).
//! - Keyboard: ChangeKeyboardMapping(100), GetKeyboardMapping(101),
//!   ChangeKeyboardControl(102), Bell(104), SetModifierMapping(118), GetModifierMapping(119).
//! - Pointer: SetPointerMapping(116), GetPointerMapping(117).
//! - NoOperation(127).

pub mod atoms;
pub mod proto;
pub mod resource;
pub mod event;

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::net::unix;
use spin::Mutex;
use core::sync::atomic::{AtomicBool, Ordering};
use resource::{ResourceBody, ResourceTable, WindowData, PixmapData, GcData, PictureData, GlyphSet, GlyphInfo};

/// Set to true once `init()` completes. Checked in `poll()` without taking
/// the SERVER mutex so the fast path (not yet initialized) is zero-cost.
static X11_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────────────
const MAX_CLIENTS:      usize = 32;
const SOCKET_PATH:      &[u8] = b"/tmp/.X11-unix/X0\0";
const RESOURCE_ID_BASE: u32   = 0x0040_0000;
const RESOURCE_ID_MASK: u32   = 0x001F_FFFF;
const FONT_ID_FIXED:    u32   = 0xF001;

// ── Per-connection state ─────────────────────────────────────────────────────

struct Client {
    fd:              u64,
    seq:             u16,
    setup_done:      bool,
    /// Per-client event mask selected on the root window (updated by
    /// ChangeWindowAttributes when the target is ROOT_WINDOW_ID).
    root_event_mask: u32,
    resources:       Box<ResourceTable>,
}

impl Client {
    fn new(fd: u64) -> Self {
        Client { fd, seq: 0, setup_done: false,
                 root_event_mask: 0,
                 resources: Box::new(ResourceTable::new()) }
    }
    fn next_seq(&mut self) -> u16 { self.seq = self.seq.wrapping_add(1); self.seq }
    fn send(&self, data: &[u8])   {
        #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
        if data.len() >= 4 && data[0] == 1 {
            // Reply: log fd, seq, reply_length, total_bytes
            let seq = u16::from_le_bytes([data[2], data[3]]);
            let extra = if data.len() >= 8 { u32::from_le_bytes([data[4], data[5], data[6], data[7]]) } else { 0 };
            crate::serial_println!("[X11REPLY] fd={} seq={} reply_len={} total={}",
                self.fd, seq, extra, data.len());
        }
        #[cfg(feature = "xeyes-test")]
        if data.len() == 32 && data[0] != 1 {
            // Event (type != 1 reply, != connection-setup) or Error (type 0).
            // Log type + the window field for Expose/Map/Configure correlation.
            let etype = data[0] & 0x7f;
            let win = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let win2 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            crate::serial_println!("[X11EVT] fd={} type={} seq={} win={:#x} win2={:#x}",
                self.fd, etype, u16::from_le_bytes([data[2], data[3]]), win, win2);
            // Full 32-byte hexdump of the event so the golden diff can compare the
            // exact wire encoding (x/y/w/h/count for Expose, override-redirect for
            // MapNotify, etc.) against a real X server's event bytes.
            let mut hx = [0u8; 3*32];
            let mut p = 0usize;
            for &byte in &data[..32] {
                const H: &[u8;16] = b"0123456789abcdef";
                hx[p] = H[(byte>>4) as usize]; hx[p+1] = H[(byte&0xf) as usize];
                hx[p+2] = b' '; p += 3;
            }
            let s = core::str::from_utf8(&hx[..p]).unwrap_or("");
            crate::serial_println!("[X11EVTHEX] type={}: {}", etype, s);
        }
        unix::write(self.fd, data);
    }
    fn send_error(&self, code: u8, bad_id: u32, opcode: u8) {
        let mut p = [0u8; 32];
        p[0] = 0; p[1] = code;
        w16(&mut p, 2, self.seq);
        w32(&mut p, 4, bad_id);
        p[10] = opcode;
        self.send(&p);
    }
}

// ── Selection owner table ─────────────────────────────────────────────────────

const MAX_SELECTIONS: usize = 8;

#[derive(Clone, Copy)]
struct SelectionOwner {
    selection: u32,   // selection atom ID (0 = unused slot)
    owner:     u32,   // owner window ID (0 = no current owner)
    owner_fd:  u64,   // client fd that set ownership (u64::MAX = none)
    timestamp: u32,   // X timestamp when ownership was acquired
}
impl SelectionOwner {
    const fn empty() -> Self {
        SelectionOwner { selection: 0, owner: 0, owner_fd: u64::MAX, timestamp: 0 }
    }
}

// ── Server state ─────────────────────────────────────────────────────────────

struct Server {
    initialized:     bool,
    listen_fd:       u64,
    clients:         [Option<Client>; MAX_CLIENTS],
    /// Properties on the root window (shared across all clients).
    root_properties: [Option<resource::PropertyEntry>; resource::MAX_PROPERTIES],
    /// ICCCM selection ownership table.
    selections:      [SelectionOwner; MAX_SELECTIONS],
    /// Server-global input focus window.  Per X11 protocol §SetInputFocus,
    /// focus is a server-wide resource, not per-connection.  All clients share
    /// this value; the last SetInputFocus request wins.
    focus_window:    u32,
}
impl Server {
    const fn new() -> Self {
        Server {
            initialized:     false,
            listen_fd:       0,
            clients:         [const { None }; MAX_CLIENTS],
            root_properties: [const { None }; resource::MAX_PROPERTIES],
            selections:      [SelectionOwner::empty(); MAX_SELECTIONS],
            focus_window:    proto::ROOT_WINDOW_ID,
        }
    }
}
unsafe impl Send for Server {}
static SERVER: Mutex<Server> = Mutex::new(Server::new());

// ── MIT-SHM attachment table ─────────────────────────────────────────────────
//
// MIT-SHM ShmAttach binds an X resource id (`shmseg`) to a previously-created
// SysV shared-memory segment (the integer `shmid` the client got from
// `shmget`).  ShmPutImage then references the `shmseg`; the server resolves it
// to the `shmid`, looks up the segment's physical backing via
// `sysv_shm::segment_phys`, and reads pixel data directly.  Attachments are
// few (a compositor uses a handful of back-buffers), so a small fixed table
// shared across all clients is sufficient.
const MAX_SHM_ATTACH: usize = 32;

#[derive(Clone, Copy)]
struct ShmAttach {
    shmseg: u32, // X resource id (0 = free slot)
    shmid:  u32, // SysV shmid the segment was created with
    fd:     u64, // owning client connection (for cleanup on disconnect)
}
impl ShmAttach {
    const fn empty() -> Self { ShmAttach { shmseg: 0, shmid: 0, fd: 0 } }
}
static SHM_ATTACH: Mutex<[ShmAttach; MAX_SHM_ATTACH]> =
    Mutex::new([ShmAttach::empty(); MAX_SHM_ATTACH]);

// ── GLX context table ────────────────────────────────────────────────────────
//
// GLX context bookkeeping.  With direct (client-side llvmpipe) rendering the
// server never executes GL; it only needs to (a) acknowledge context creation
// with a valid XID, (b) hand back a non-zero context tag on MakeCurrent, and
// (c) answer IsDirect=true.  We record the context XID so DestroyContext and
// QueryContext can validate it.
const MAX_GLX_CONTEXTS: usize = 64;

#[derive(Clone, Copy)]
struct GlxContext {
    xid: u32, // GLX context resource id (0 = free slot)
    fd:  u64, // owning client connection
}
impl GlxContext {
    const fn empty() -> Self { GlxContext { xid: 0, fd: 0 } }
}
static GLX_CONTEXTS: Mutex<[GlxContext; MAX_GLX_CONTEXTS]> =
    Mutex::new([GlxContext::empty(); MAX_GLX_CONTEXTS]);

/// Free all GLX contexts and MIT-SHM attachments owned by a (now-dead) client
/// connection.  Called from the client-reap path so a disconnecting client does
/// not leak server-side handles.  The SysV segments themselves are owned by the
/// client process and reclaimed on its exit; this only drops the X-server-side
/// shmseg→shmid binding.
fn glx_release_client(fd: u64) {
    {
        let mut tbl = GLX_CONTEXTS.lock();
        for c in tbl.iter_mut() { if c.fd == fd { *c = GlxContext::empty(); } }
    }
    {
        let mut tbl = SHM_ATTACH.lock();
        for a in tbl.iter_mut() { if a.fd == fd { *a = ShmAttach::empty(); } }
    }
}

// ── Wire helpers ─────────────────────────────────────────────────────────────

#[inline] fn r16(b: &[u8], o: usize) -> u16  { proto::read_u16le(b, o) }
#[inline] fn r32(b: &[u8], o: usize) -> u32  { proto::read_u32le(b, o) }
#[inline] fn w16(b: &mut [u8], o: usize, v: u16) { proto::write_u16le(b, o, v); }
#[inline] fn w32(b: &mut [u8], o: usize, v: u32) { proto::write_u32le(b, o, v); }

// ── Root-window property helpers ─────────────────────────────────────────────

/// Set a property in a raw property-array (same semantics as WindowData::set_property).
fn prop_arr_set(arr: &mut [Option<resource::PropertyEntry>; resource::MAX_PROPERTIES],
                name: u32, type_: u32, format: u8, data: &[u8], mode: u8) {
    let copy_len = data.len().min(resource::MAX_PROPERTY_DATA);
    for slot in arr.iter_mut() {
        if let Some(p) = slot {
            if p.name == name {
                match mode {
                    1 => { /* prepend: put new data before existing — just replace for simplicity */
                        let old_len = p.len;
                        let new_len = (copy_len + old_len).min(resource::MAX_PROPERTY_DATA);
                        p.data.copy_within(0..old_len.min(resource::MAX_PROPERTY_DATA - copy_len), copy_len);
                        p.data[..copy_len].copy_from_slice(&data[..copy_len]);
                        p.len = new_len;
                    }
                    2 => { /* append */
                        let start = p.len;
                        let room  = resource::MAX_PROPERTY_DATA.saturating_sub(start);
                        let n = copy_len.min(room);
                        p.data[start..start+n].copy_from_slice(&data[..n]);
                        p.len = start + n;
                    }
                    _ => { /* replace */
                        p.data[..copy_len].copy_from_slice(&data[..copy_len]);
                        p.len = copy_len;
                        p.type_ = type_; p.format = format;
                    }
                }
                return;
            }
        }
    }
    // Insert new entry.
    for slot in arr.iter_mut() {
        if slot.is_none() {
            let mut p = resource::PropertyEntry::empty();
            p.name = name; p.type_ = type_; p.format = format;
            p.data[..copy_len].copy_from_slice(&data[..copy_len]);
            p.len = copy_len;
            *slot = Some(p);
            return;
        }
    }
}

/// Get a property from a raw property-array; returns (type_, format, len, data_copy).
fn prop_arr_get(arr: &[Option<resource::PropertyEntry>; resource::MAX_PROPERTIES], name: u32)
    -> Option<(u32, u8, usize, [u8; resource::MAX_PROPERTY_DATA])> {
    for slot in arr.iter() {
        if let Some(p) = slot {
            if p.name == name {
                let mut buf = [0u8; resource::MAX_PROPERTY_DATA];
                buf[..p.len].copy_from_slice(&p.data[..p.len]);
                return Some((p.type_, p.format, p.len, buf));
            }
        }
    }
    None
}

/// Delete a property from a raw property-array.
fn prop_arr_del(arr: &mut [Option<resource::PropertyEntry>; resource::MAX_PROPERTIES], name: u32) {
    for slot in arr.iter_mut() {
        if let Some(p) = slot { if p.name == name { *slot = None; return; } }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Bind and listen on `/tmp/.X11-unix/X0`.
pub fn init() {
    let _ = crate::vfs::mkdir("/tmp/.X11-unix");
    // The X11 server is a kernel-owned listener; record pid=0 as the
    // creator so SO_PEERCRED on an accepted connection still resolves
    // to a structurally-detectable "kernel listener" identity for any
    // client that inspects it.  Per unix(7) SO_PEERCRED.
    let fd = unix::create(unix::SockKind::Stream,
        unix::PeerCreds { pid: 0, uid: 0, gid: 0 });
    let r  = unix::bind(fd, SOCKET_PATH);
    if r < 0 {
        crate::serial_println!("[X11] bind failed: {}", r);
        return;
    }
    unix::listen(fd);
    {
        let mut srv = SERVER.lock();
        srv.listen_fd    = fd;
        srv.initialized  = true;

        // ── EWMH: pre-populate _NET_SUPPORTED on the root window ─────────
        // Per EWMH §3.1: the _NET_SUPPORTED property lists all EWMH atoms
        // the window manager honours.  Clients (including GTK, Qt, xterm) read
        // this on startup to decide which EWMH features to use.
        let net_supported            = atoms::intern("_NET_SUPPORTED",                false);
        let net_wm_state             = atoms::intern("_NET_WM_STATE",                 false);
        let net_wm_state_fullscreen  = atoms::intern("_NET_WM_STATE_FULLSCREEN",      false);
        let net_wm_state_max_vert    = atoms::intern("_NET_WM_STATE_MAXIMIZED_VERT",  false);
        let net_wm_state_max_horiz   = atoms::intern("_NET_WM_STATE_MAXIMIZED_HORIZ", false);
        let net_wm_state_hidden      = atoms::intern("_NET_WM_STATE_HIDDEN",          false);
        let net_active_window        = atoms::intern("_NET_ACTIVE_WINDOW",            false);
        let net_wm_name              = atoms::intern("_NET_WM_NAME",                  false);
        let net_wm_window_type       = atoms::intern("_NET_WM_WINDOW_TYPE",           false);
        let net_wm_window_type_normal= atoms::intern("_NET_WM_WINDOW_TYPE_NORMAL",    false);
        let net_wm_ping              = atoms::intern("_NET_WM_PING",                  false);
        // Pack the supported-atom list as 32-bit LE values.
        let supported = [
            net_wm_state, net_wm_state_fullscreen, net_wm_state_max_vert,
            net_wm_state_max_horiz, net_wm_state_hidden, net_active_window,
            net_wm_name, net_wm_window_type, net_wm_window_type_normal, net_wm_ping,
        ];
        let mut buf = [0u8; 80];
        for (i, &a) in supported.iter().enumerate() {
            proto::write_u32le(&mut buf, i * 4, a);
        }
        prop_arr_set(&mut srv.root_properties,
            net_supported, atoms::ATOM_ATOM, 32,
            &buf[..supported.len() * 4], 0);
    }
    X11_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[X11] Xastryx ready on /tmp/.X11-unix/X0 (fd={})", fd);
}

/// Inject a keyboard scancode event to the focused X11 client.
///
/// `keycode` is the X11 keycode (8–255).  Delivered to all connected clients
/// whose focused window has selected `KeyPress` / `KeyRelease` events.
/// Call from the PS/2 keyboard interrupt handler or test code.
pub fn inject_key_event(keycode: u8, pressed: bool) {
    let mut srv = SERVER.lock();
    if !srv.initialized { return; }
    let tick = crate::arch::x86_64::irq::get_ticks() as u32;
    let mask_needed = if pressed {
        proto::EVENT_MASK_KEY_PRESS
    } else {
        proto::EVENT_MASK_KEY_RELEASE
    };
    // Focus is server-global; all key events go to the single focused window.
    let fw = srv.focus_window;
    for slot in srv.clients.iter_mut() {
        if let Some(c) = slot {
            // Check whether the focused window has registered for this event.
            let send_ev = {
                let entries = &c.resources.entries;
                entries.iter().filter_map(|s| s.as_ref())
                    .find(|r| r.id == fw)
                    .map(|r| match &r.body {
                        resource::ResourceBody::Window(w) => w.event_mask & mask_needed != 0,
                        _ => false,
                    })
                    .unwrap_or(false)
            };
            if send_ev {
                let seq = c.next_seq();
                let ev = if pressed {
                    event::encode_key_press(seq, fw, keycode, 0, tick)
                } else {
                    event::encode_key_release(seq, fw, keycode, 0, tick)
                };
                unix::write(c.fd, &ev);
            }
        }
    }
}

/// Inject a mouse motion / button event to X11 clients.
///
/// `rx`/`ry` are root-space coordinates.  `buttons` is a button-state bitmask
/// (bit 0 = button 1, bit 1 = button 2, bit 2 = button 3).
pub fn inject_mouse_event(rx: i16, ry: i16, buttons: u8, prev_buttons: u8) {
    let mut srv = SERVER.lock();
    if !srv.initialized { return; }
    let tick = crate::arch::x86_64::irq::get_ticks() as u32;
    let state = (buttons as u16) << 8;
    // Focus is server-global; pointer events are delivered to the focused window.
    let fw = srv.focus_window;
    for slot in srv.clients.iter_mut() {
        if let Some(c) = slot {
            let evmask = {
                let entries = &c.resources.entries;
                entries.iter().filter_map(|s| s.as_ref())
                    .find(|r| r.id == fw)
                    .map(|r| match &r.body {
                        resource::ResourceBody::Window(w) => w.event_mask,
                        _ => 0,
                    })
                    .unwrap_or(0)
            };
            if evmask & proto::EVENT_MASK_POINTER_MOTION != 0 {
                let seq = c.next_seq();
                unix::write(c.fd, &event::encode_motion_notify(seq, fw, rx, ry, state, tick));
            }
            for btn in 0u8..3 {
                let mask = 1u8 << btn;
                let btn_num = btn + 1;
                if buttons & mask != 0 && prev_buttons & mask == 0 {
                    if evmask & proto::EVENT_MASK_BUTTON_PRESS != 0 {
                        let seq = c.next_seq();
                        unix::write(c.fd, &event::encode_button_press(
                            seq, fw, btn_num, rx, ry, state, tick));
                    }
                } else if buttons & mask == 0 && prev_buttons & mask != 0 {
                    if evmask & proto::EVENT_MASK_BUTTON_RELEASE != 0 {
                        let seq = c.next_seq();
                        unix::write(c.fd, &event::encode_button_release(
                            seq, fw, btn_num, rx, ry, state, tick));
                    }
                }
            }
        }
    }
}

/// Snapshot of an X11 window for the compositor to blit.
pub struct X11WindowSnapshot {
    pub x: i16,
    pub y: i16,
    pub width: u16,
    pub height: u16,
    pub pixels: Vec<u8>, // BGRA, width×height×4
}

/// Resolve a window's absolute (screen-space) origin by summing the
/// parent-relative offsets up the window tree until the root (id 1) or an
/// unknown parent is reached.  Window coordinates in the protocol are relative
/// to the parent, so a child widget's screen position is the sum of its and its
/// ancestors' offsets.  Bounded to avoid cycles in a corrupt tree.
fn absolute_origin(client: &Client, mut id: u32) -> (i32, i32) {
    let (mut ax, mut ay) = (0i32, 0i32);
    for _ in 0..32 {
        let mut found = false;
        for r in client.resources.entries.iter().filter_map(|s| s.as_ref()) {
            if r.id == id {
                if let resource::ResourceBody::Window(ref w) = r.body {
                    ax += w.x as i32;
                    ay += w.y as i32;
                    if w.parent == proto::ROOT_WINDOW_ID || w.parent == 0 { return (ax, ay); }
                    id = w.parent;
                    found = true;
                }
                break;
            }
        }
        if !found { break; }
    }
    (ax, ay)
}

/// Collect all mapped X11 client windows for compositor rendering.
/// Returns a Vec of snapshots (copies pixel data to avoid holding locks).
/// Coordinates are absolute (screen-space); child widget windows are resolved
/// relative to their ancestors.  Resources iterate in creation order, so a
/// parent precedes its children — i.e. children are blitted on top, matching
/// the X11 stacking model where later-mapped children draw over their parent.
pub fn get_mapped_windows() -> Vec<X11WindowSnapshot> {
    if !X11_INITIALIZED.load(Ordering::Acquire) { return Vec::new(); }
    let srv = SERVER.lock();
    let mut result = Vec::new();
    for slot in srv.clients.iter() {
        if let Some(client) = slot {
            for (rid, body) in client.resources.iter_all() {
                if let resource::ResourceBody::Window(ref w) = body {
                    if w.mapped && !w.pixels.is_empty() && w.width > 0 && w.height > 0 {
                        let (ax, ay) = absolute_origin(client, rid);
                        result.push(X11WindowSnapshot {
                            x: ax as i16,
                            y: ay as i16,
                            width: w.width,
                            height: w.height,
                            pixels: w.pixels.clone(),
                        });
                    }
                }
            }
        }
    }
    result
}

/// Test-only: read a single window-local BGRA pixel from a window's persistent
/// pixel buffer (`w.pixels`, the compositor source of truth).  Searches every
/// connected client for a window resource matching `win_id` (test windows use
/// globally-unique IDs), so callers need not know the server-side socket fd.
/// Returns `None` if no matching window/pixel is present or its buffer is
/// unallocated.
#[cfg(feature = "test-mode")]
pub fn test_read_window_pixel(win_id: u32, x: u32, y: u32) -> Option<[u8; 4]> {
    let srv = SERVER.lock();
    for c in srv.clients.iter().filter_map(|s| s.as_ref()) {
        for sl in c.resources.entries.iter() {
            if let Some(r) = sl {
                if r.id == win_id {
                    if let resource::ResourceBody::Window(ref w) = r.body {
                        if x >= w.width as u32 || y >= w.height as u32 { return None; }
                        let off = ((y * w.width as u32 + x) * 4) as usize;
                        if off + 4 > w.pixels.len() { return None; }
                        return Some([w.pixels[off], w.pixels[off + 1],
                                     w.pixels[off + 2], w.pixels[off + 3]]);
                    }
                }
            }
        }
    }
    None
}

/// Accept new clients and service pending reads.  Call from idle/scheduler loop.
pub fn poll() {
    if !X11_INITIALIZED.load(Ordering::Acquire) { return; }
    let lfd = { SERVER.lock().listen_fd };

    while unix::has_pending(lfd) {
        let r = unix::accept(lfd);
        if r < 0 { break; }
        let nfd = r as u64;
        let mut srv = SERVER.lock();
        for slot in srv.clients.iter_mut() {
            if slot.is_none() { *slot = Some(Client::new(nfd));
                crate::serial_println!("[X11] client fd={}", nfd); break; }
        }
    }

    // Reap dead clients: if the peer (client) socket is Free, the client
    // disconnected.  Close our server-side socket and free the slot.
    {
        let mut dead_fds = [u64::MAX; MAX_CLIENTS];
        let mut dead_idx = [usize::MAX; MAX_CLIENTS];
        {
            let s = SERVER.lock();
            for (i, sl) in s.clients.iter().enumerate() {
                if let Some(c) = sl {
                    let peer = unix::get_peer(c.fd);
                    let peer_alive = peer != u64::MAX
                        && unix::state(peer) != crate::net::unix::UnixState::Free;
                    if !peer_alive { dead_fds[i] = c.fd; dead_idx[i] = i; }
                }
            }
        }
        let mut srv = SERVER.lock();
        for i in 0..MAX_CLIENTS {
            if dead_idx[i] != usize::MAX {
                srv.clients[dead_idx[i]] = None;
                glx_release_client(dead_fds[i]);
                unix::close(dead_fds[i]);
            }
        }
    }

    let mut pending = [u64::MAX; MAX_CLIENTS];
    { let s = SERVER.lock();
      for (i, sl) in s.clients.iter().enumerate() {
          if let Some(c) = sl {
              let hd = unix::has_data(c.fd);
              #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
              if hd { crate::serial_println!("[X11POLL] svc_fd={} has_data=true avail={}", c.fd, unix::bytes_available(c.fd)); }
              if hd { pending[i] = c.fd; }
          }
      }
    }
    for &fd in &pending { if fd != u64::MAX { service_fd(fd); } }
}

// ─────────────────────────────────────────────────────────────────────────────

fn service_fd(fd: u64) {
    let mut buf = [0u8; 4096];
    let n = unix::read(fd, &mut buf);
    if n <= 0 { return; }
    let data = &buf[..n as usize];
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    crate::serial_println!("[X11SVC] fd={} read {} bytes", fd, n);
    let setup = {
        let s = SERVER.lock();
        s.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
         .map(|c| c.setup_done).unwrap_or(false)
    };
    if !setup { handle_setup(fd, data); return; }
    let mut off = 0usize;
    while off + 4 <= data.len() {
        // X11 core request length is a 16-bit count of 4-byte units (§Requests).
        // Under the BIG-REQUESTS extension a length field of 0 means the real
        // length is the following 32-bit word (in 4-byte units), inserted
        // between the 4-byte request header and the body — so the body that
        // would normally start at offset 4 starts at offset 8.  Treating length
        // 0 as "stop parsing" would silently drop this request AND every request
        // batched after it in the same read — desynchronising the client's
        // reply/sequence expectations.  (X11 BIG-REQUESTS extension spec.)
        let short_len = r16(data, off + 2) as usize;
        let req_len_units = if short_len == 0 {
            if off + 8 > data.len() { break; }
            // A big request always spans >= 2 units: the 4-byte request header
            // plus the inserted 4-byte extended-length word.  A reported length
            // of 0 or 1 is malformed; accepting it makes the body splice
            // [off+8..end] have start > end (end <= off+4) → slice-index panic
            // (and panic=abort would take the whole kernel down on hostile
            // client input).  Reject malformed big requests instead.
            let big = r32(data, off + 4) as usize;
            if big < 2 { break; }
            big
        } else {
            short_len
        };
        if req_len_units == 0 { break; } // malformed: zero even in big form
        let end = off + req_len_units * 4;
        if end > data.len() || end <= off { break; }
        if short_len == 0 {
            // Big request: normalise to standard layout before dispatch so the
            // per-op handlers (which read fields at fixed standard offsets) see
            // a conventional request.  Splice out the inserted 4-byte
            // extended-length word: keep the 4-byte header [off..off+4], then
            // the body [off+8..end].  The reconstructed 16-bit length field is
            // left as the request's true length truncated into 16 bits (the
            // handlers key off the slice length, not this field).
            let mut norm = alloc::vec::Vec::with_capacity(4 + (end - (off + 8)));
            norm.extend_from_slice(&data[off..off + 4]);
            norm.extend_from_slice(&data[off + 8..end]);
            handle_request(fd, &norm);
        } else {
            handle_request(fd, &data[off..end]);
        }
        off = end;
    }
}

// ── Setup ─────────────────────────────────────────────────────────────────────

fn handle_setup(fd: u64, data: &[u8]) {
    if data.len() < 12       { send_fail(fd, b"truncated"); return; }
    if data[0] != 0x6C       { send_fail(fd, b"big-endian not supported"); return; }
    if r16(data,2) != 11     { send_fail(fd, b"unsupported protocol"); return; }
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    {
        let n_auth = r16(data, 6) as usize;
        let d_auth = r16(data, 8) as usize;
        crate::serial_println!("[X11] setup: byte_order={:#x} maj={} min={} n_auth={} d_auth={} total_client={}",
            data[0], r16(data,2), r16(data,4), n_auth, d_auth, data.len());
    }
    let reply = build_setup_ok();
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    {
        crate::serial_println!("[X11] setup_ok len={} hdr={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} additional_units={} n_screens={} n_formats={}",
            reply.len(), reply[0], reply[1], reply[2], reply[3], reply[4], reply[5], reply[6], reply[7],
            r16(&reply,6), reply[28], reply[29]);
        crate::serial_println!("[X11] setup_ok res_base={:#x} res_mask={:#x} vendor_len={} max_req={}",
            r32(&reply,12), r32(&reply,16), r16(&reply,24), r16(&reply,26));
    }
    let n_written = unix::write(fd, &reply);
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    crate::serial_println!("[X11] setup_ok written={}", n_written);
    let mut srv = SERVER.lock();
    for sl in srv.clients.iter_mut() {
        if let Some(c) = sl { if c.fd == fd { c.setup_done = true; break; } }
    }
    crate::serial_println!("[X11] fd={} setup ok", fd);
}

fn send_fail(fd: u64, r: &[u8]) {
    let rl = r.len(); let pd = (rl+3)&!3;
    let mut b = [0u8; 64]; b[1]=rl as u8; w16(&mut b,2,11); w16(&mut b,6,(pd/4) as u16);
    b[8..8+rl.min(56)].copy_from_slice(&r[..rl.min(56)]);
    unix::write(fd, &b[..8+pd]);
}

fn build_setup_ok() -> [u8; 128] {
    let mut b = [0u8; 128];
    b[0]=1; w16(&mut b,2,11); w16(&mut b,6,30);
    let p=8; w32(&mut b,p,1); w32(&mut b,p+4,RESOURCE_ID_BASE); w32(&mut b,p+8,RESOURCE_ID_MASK);
    w32(&mut b,p+12,256); w16(&mut b,p+16,7); w16(&mut b,p+18,0x7FFF);
    b[p+20]=1; b[p+21]=1; b[p+24]=32; b[p+25]=32; b[p+26]=8; b[p+27]=255;
    let q=p+32; b[q..q+7].copy_from_slice(b"Xastryx");
    let r2=q+8; b[r2]=proto::ROOT_DEPTH; b[r2+1]=32; b[r2+2]=32;
    let s=r2+8;
    w32(&mut b,s,proto::ROOT_WINDOW_ID); w32(&mut b,s+4,proto::DEFAULT_COLORMAP);
    w32(&mut b,s+8,proto::WHITE_PIXEL); w32(&mut b,s+12,proto::BLACK_PIXEL);
    w16(&mut b,s+20,proto::SCREEN_WIDTH); w16(&mut b,s+22,proto::SCREEN_HEIGHT);
    w16(&mut b,s+24,proto::SCREEN_WIDTH_MM); w16(&mut b,s+26,proto::SCREEN_HEIGHT_MM);
    w16(&mut b,s+28,1); w16(&mut b,s+30,1); w32(&mut b,s+32,proto::ROOT_VISUAL);
    b[s+38]=proto::ROOT_DEPTH; b[s+39]=1;
    let d=s+40; b[d]=proto::ROOT_DEPTH; w16(&mut b,d+2,1);
    let v=d+8; w32(&mut b,v,proto::ROOT_VISUAL); b[v+4]=proto::VISUAL_CLASS_TRUECOLOR;
    b[v+5]=8; w16(&mut b,v+6,256); w32(&mut b,v+8,0x00FF0000);
    w32(&mut b,v+12,0x0000FF00); w32(&mut b,v+16,0x000000FF);
    b
}

// ── Request dispatch ──────────────────────────────────────────────────────────

fn handle_request(fd: u64, data: &[u8]) {
    if data.len() < 4 { return; }
    let opcode = data[0];
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    {
        static X11_REQ_N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        let n = X11_REQ_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n < 400 {
            // For core ops (opcode 1-127) data[1] is op-specific (CW depth, etc.).
            // For extension major opcodes (128-255) it is the minor opcode per X11
            // protocol §10.  Logging both unifies the trace for downstream parsing.
            let minor = data[1];
            // For draw ops the drawable id is at bytes 4..8 (X11 core protocol
            // §PolyFillArc/§PolyArc/§PolyFillRectangle/§CopyArea/§ClearArea/
            // §PutImage all carry the destination drawable there).  Surface it so
            // the trace shows WHICH window/pixmap a draw targets.
            let drawable = if data.len() >= 8 && matches!(opcode,
                61 | 62 | 64 | 65 | 66 | 67 | 70 | 71 | 72 | 76) {
                u32::from_le_bytes([data[4], data[5], data[6], data[7]])
            } else { 0 };
            crate::serial_println!("[X11] req#{} op={} minor={} len={} drawable={:#x}",
                                   n, opcode, minor, data.len(), drawable);
            // Full hexdump of CreateWindow(1)/CreateGC(55)/RENDER(139)/SHAPE(128)/
            // map-cluster requests so the GOLDEN protocol diff can compare wire
            // bytes (visual id, event-mask, border-width, picture-format) exactly.
            if matches!(opcode, 1 | 2 | 8 | 9 | 12 | 55 | 98 | 128 | 131 | 139)
                && n < 120 {
                let m = core::cmp::min(data.len(), 64);
                let mut hx = [0u8; 3*64];
                let mut p = 0usize;
                for &byte in &data[..m] {
                    const H: &[u8;16] = b"0123456789abcdef";
                    hx[p] = H[(byte>>4) as usize]; hx[p+1] = H[(byte&0xf) as usize];
                    hx[p+2] = b' '; p += 3;
                }
                let s = core::str::from_utf8(&hx[..p]).unwrap_or("");
                crate::serial_println!("[X11HEX] req#{} op={}: {}", n, opcode, s);
            }
        }
    }
    let seq = { let mut srv = SERVER.lock();
        match srv.clients.iter_mut().filter_map(|s| s.as_mut()).find(|c| c.fd == fd) {
            Some(c) => c.next_seq(), None => return } };
    match opcode {
        proto::OP_CREATE_WINDOW         => op_create_window(fd, data, seq),
        proto::OP_CHANGE_WINDOW_ATTRS   => op_change_win_attrs(fd, data),
        proto::OP_GET_WINDOW_ATTRS      => op_get_win_attrs(fd, data, seq),
        proto::OP_DESTROY_WINDOW        => op_destroy_window(fd, data, seq),
        proto::OP_DESTROY_SUBWINDOWS    => {} // best-effort no-op (no children tracked)
        proto::OP_CHANGE_SAVE_SET       => {} // ICCCM bookkeeping; ignored
        proto::OP_REPARENT_WINDOW       => {} // no WM hierarchy beyond root
        proto::OP_MAP_WINDOW            => op_map_window(fd, data, seq),
        proto::OP_MAP_SUBWINDOWS        => op_map_subwindows(fd, data, seq),
        proto::OP_UNMAP_WINDOW          => op_unmap_window(fd, data, seq),
        proto::OP_UNMAP_SUBWINDOWS      => {} // no-op
        proto::OP_CIRCULATE_WINDOW      => {} // no Z-order beyond top window
        proto::OP_CONFIGURE_WINDOW      => op_configure_window(fd, data, seq),
        proto::OP_GET_GEOMETRY          => op_get_geometry(fd, data, seq),
        proto::OP_QUERY_TREE            => op_query_tree(fd, data, seq),
        proto::OP_INTERN_ATOM           => op_intern_atom(fd, data, seq),
        proto::OP_GET_ATOM_NAME         => op_get_atom_name(fd, data, seq),
        proto::OP_CHANGE_PROPERTY       => op_change_property(fd, data),
        proto::OP_DELETE_PROPERTY       => op_delete_property(fd, data),
        proto::OP_GET_PROPERTY          => op_get_property(fd, data, seq),
        proto::OP_LIST_PROPERTIES       => op_list_properties(fd, data, seq),
        proto::OP_SET_SELECTION_OWNER   => op_set_selection_owner(fd, data, seq),
        proto::OP_GET_SELECTION_OWNER   => op_get_selection_owner(fd, data, seq),
        proto::OP_CONVERT_SELECTION     => op_convert_selection(fd, data, seq),
        proto::OP_SEND_EVENT            => op_send_event(fd, data, seq),
        proto::OP_GRAB_POINTER          => op_grab_reply(fd, seq),
        proto::OP_UNGRAB_POINTER        => {}
        proto::OP_GRAB_BUTTON           => {}
        proto::OP_UNGRAB_BUTTON         => {}
        proto::OP_GRAB_KEYBOARD         => op_grab_reply(fd, seq),
        proto::OP_UNGRAB_KEYBOARD       => {}
        proto::OP_ALLOW_EVENTS          => {}
        proto::OP_GRAB_SERVER           => {}
        proto::OP_UNGRAB_SERVER         => {}
        proto::OP_QUERY_POINTER         => op_query_pointer(fd, seq),
        proto::OP_TRANSLATE_COORDINATES => op_translate_coordinates(fd, data, seq),
        proto::OP_WARP_POINTER          => {}
        proto::OP_SET_INPUT_FOCUS       => op_set_input_focus(fd, data),
        proto::OP_GET_INPUT_FOCUS       => op_get_input_focus(fd, seq),
        proto::OP_QUERY_KEYMAP          => op_query_keymap(fd, seq),
        proto::OP_OPEN_FONT             => op_open_font(fd, data),
        proto::OP_CLOSE_FONT            => {}
        proto::OP_QUERY_FONT            => op_query_font(fd, seq),
        proto::OP_LIST_FONTS            => op_list_fonts(fd, seq),
        proto::OP_CREATE_PIXMAP         => op_create_pixmap(fd, data),
        proto::OP_FREE_PIXMAP           => op_free_pixmap(fd, data),
        proto::OP_CREATE_GC             => op_create_gc(fd, data),
        proto::OP_CHANGE_GC             => op_change_gc(fd, data),
        proto::OP_COPY_GC               => op_copy_gc(fd, data),
        proto::OP_FREE_GC               => op_free_gc(fd, data),
        proto::OP_CLEAR_AREA            => op_clear_area(fd, data),
        proto::OP_COPY_AREA             => op_copy_area(fd, data),
        proto::RENDER_MAJOR_OPCODE      => op_render(fd, data, seq),
        proto::SHM_MAJOR_OPCODE        => op_shm(fd, data, seq),
        proto::BIGREQ_MAJOR_OPCODE     => op_bigreq(fd, data, seq),
        proto::XFIXES_MAJOR_OPCODE     => op_xfixes(fd, data, seq),
        proto::DAMAGE_MAJOR_OPCODE     => op_damage(fd, data, seq),
        proto::XINPUT_MAJOR_OPCODE     => op_xinput(fd, data, seq),
        proto::COMPOSITE_MAJOR_OPCODE  => op_composite(fd, data, seq),
        proto::XTEST_MAJOR_OPCODE      => op_xtest(fd, data, seq),
        proto::SYNC_MAJOR_OPCODE       => op_sync_ext(fd, data, seq),
        proto::SHAPE_MAJOR_OPCODE      => op_shape(fd, data, seq),
        proto::XKEYBOARD_MAJOR_OPCODE  => op_xkeyboard(fd, data, seq),
        proto::DPMS_MAJOR_OPCODE       => op_dpms(fd, data, seq),
        proto::RANDR_MAJOR_OPCODE      => op_randr(fd, data, seq),
        proto::GLX_MAJOR_OPCODE        => op_glx(fd, data, seq),
        // Polygon / arc drawing ops.  Per X11 core protocol §PolyArc /
        // §PolyFillArc / §FillPoly / §PolyLine / §PolySegment / §PolyPoint /
        // §PolyRectangle — no reply; the request carries (drawable, gc,
        // [coords...]) and is rasterised into the drawable's pixel buffer.
        proto::OP_POLY_POINT            => op_poly_point(fd, data),
        proto::OP_POLY_LINE             => op_poly_line(fd, data),
        proto::OP_POLY_SEGMENT          => op_poly_segment(fd, data),
        proto::OP_POLY_RECTANGLE        => op_poly_rectangle(fd, data),
        proto::OP_POLY_ARC              => op_poly_arc(fd, data),
        proto::OP_FILL_POLY             => {} // filled polygons: not used by xeyes
        proto::OP_POLY_FILL_RECTANGLE   => op_poly_fill_rect(fd, data),
        proto::OP_POLY_FILL_ARC         => op_poly_fill_arc(fd, data),
        proto::OP_PUT_IMAGE             => op_put_image(fd, data),
        proto::OP_IMAGE_TEXT8           => op_image_text8(fd, data),
        proto::OP_IMAGE_TEXT16          => {}
        proto::OP_CREATE_COLORMAP       => {}
        proto::OP_FREE_COLORMAP         => {}
        proto::OP_ALLOC_COLOR           => op_alloc_color(fd, data, seq),
        proto::OP_QUERY_COLORS          => op_query_colors(fd, data, seq),
        proto::OP_QUERY_EXTENSION       => op_query_extension(fd, data, seq),
        proto::OP_LIST_EXTENSIONS       => op_list_extensions(fd, seq),
        proto::OP_CHANGE_KEYBOARD_MAPPING => {}
        proto::OP_GET_KEYBOARD_MAPPING  => op_get_keyboard_mapping(fd, data, seq),
        proto::OP_CHANGE_KEYBOARD_CONTROL => {}
        proto::OP_BELL                  => {}
        proto::OP_SET_POINTER_MAPPING   => op_set_pointer_mapping(fd, seq),
        proto::OP_GET_POINTER_MAPPING   => op_get_pointer_mapping(fd, seq),
        proto::OP_SET_MODIFIER_MAPPING  => op_set_modifier_mapping(fd, seq),
        proto::OP_GET_MODIFIER_MAPPING  => op_get_modifier_mapping(fd, seq),
        proto::OP_NO_OPERATION          => {}
        _ => {
            #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
            crate::serial_println!("[X11] unknown opcode={} len={}", opcode, data.len());
            with_client(fd, |c| c.send_error(proto::ERR_REQUEST, 0, opcode));
        }
    }
}

fn with_client<F: FnOnce(&mut Client)>(fd: u64, f: F) {
    let mut srv = SERVER.lock();
    if let Some(c) = srv.clients.iter_mut().filter_map(|s| s.as_mut()).find(|c| c.fd == fd) { f(c); }
}

// ── Window-destination drawing helpers ───────────────────────────────────────
//
// The compositor's source of truth for a mapped client window is its
// persistent per-window pixel buffer `WindowData::pixels` (BGRA, row-major,
// stride = width*4, window-local coordinates).  `compositor::compose()` refills
// the backbuffer with the root gradient and re-blits every window's `pixels`
// each frame, so any draw-op that targets a window MUST write into that buffer
// — writing the transient screen backbuffer directly is erased on the next
// frame.  All window-destination op handlers route through the helpers below so
// the screen backbuffer is never the destination for window content.

/// Fill a window-local rectangle in `w.pixels` with a solid BGRA colour.
/// Coordinates are window-relative; the rectangle is clipped to window bounds.
fn window_fill_pixels(fd: u64, win_id: u32, x: i32, y: i32, w: i32, h: i32, bgra: [u8; 4]) {
    if w <= 0 || h <= 0 { return; }
    with_client(fd, |c| {
        if let Some(win) = c.resources.get_window_mut(win_id) {
            win.ensure_pixels();
            let ww = win.width as i32;
            let wh = win.height as i32;
            for py in y.max(0)..((y + h).min(wh)) {
                for px in x.max(0)..((x + w).min(ww)) {
                    let off = ((py * ww + px) * 4) as usize;
                    if off + 4 <= win.pixels.len() {
                        win.pixels[off..off + 4].copy_from_slice(&bgra);
                    }
                }
            }
        }
    });
}

/// Paint a window-local region to the window's background, honouring the X core
/// protocol `background-pixmap` attribute: if the window has a background pixmap
/// set, the pixmap is tiled (origin at the window's top-left) into the region;
/// otherwise the region is filled with the solid `background-pixel`.  `(x,y,w,h)`
/// is window-local; `w`/`h` of 0 mean "to the window's right/bottom edge" per
/// the ClearArea semantics.  Used on ClearArea and MapWindow so that clients
/// (e.g. the xeyes Eyes widget) which draw static content into a background
/// pixmap and rely on the server to paint it become visible.
/// Paint a window's background (background_pixel or background_pixmap) into its
/// persistent `pixels` surface.
///
/// `full_window` distinguishes the two callers:
///   - `true`  — the implicit "window became viewable" background paint issued
///     on MapWindow / MapSubwindows.  Per the X core protocol the server paints
///     the background ONCE when the window first becomes viewable; afterwards,
///     client draws (RENDER Composite, core arcs, PutImage) layer on top and
///     must persist.  This path is therefore idempotent: it is gated on the
///     `bg_painted` flag so a second MapWindow over already-drawn content cannot
///     clobber it.  (Was the #581 `x11_render_d` regression: a MapWindow after a
///     Composite re-painted black over the red.)
///   - `false` — an explicit ClearArea request.  ClearArea is a deliberate
///     erase-to-background of a client-specified region and always paints.
fn paint_window_background(fd: u64, win_id: u32, x: i32, y: i32, rw: i32, rh: i32,
                           full_window: bool) {
    // Resolve background pixmap id + window size, then (if a pixmap) snapshot it.
    let (bg_pixmap, ww, wh, bg_pixel, already_painted) = {
        let srv = SERVER.lock();
        match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
            .and_then(|c| c.resources.entries.iter().filter_map(|s| s.as_ref())
                .find(|r| r.id == win_id)
                .and_then(|r| if let ResourceBody::Window(ref w) = r.body {
                    Some((w.background_pixmap, w.width as i32, w.height as i32,
                          w.background_pixel, w.bg_painted))
                } else { None })) {
            Some(v) => v,
            None => return,
        }
    };
    // Idempotent viewable-time background paint: if the surface already had its
    // background applied (and possibly subsequent client draws layered on top),
    // a repeat full-window paint must NOT overwrite that content.
    if full_window && already_painted { return; }
    let region_w = if rw == 0 { ww - x } else { rw };
    let region_h = if rh == 0 { wh - y } else { rh };
    if region_w <= 0 || region_h <= 0 { return; }

    // bg_pixmap: 0 = None (solid background-pixel), 1 = ParentRelative (treat as
    // solid for our flat hierarchy), other = a Pixmap id to tile.
    if bg_pixmap <= 1 {
        let bgra = [(bg_pixel & 0xFF) as u8, ((bg_pixel >> 8) & 0xFF) as u8,
                    ((bg_pixel >> 16) & 0xFF) as u8, 0xFF];
        window_fill_pixels(fd, win_id, x, y, region_w, region_h, bgra);
        if full_window { mark_bg_painted(fd, win_id); }
        return;
    }

    // Snapshot the background pixmap (clone to drop the lock before drawing).
    let snap = {
        let srv = SERVER.lock();
        srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
            .and_then(|c| c.resources.get_pixmap(bg_pixmap)
                .map(|p| (p.pixels.clone(), p.width as i32, p.height as i32)))
    };
    let (px, pw, ph) = match snap { Some(v) => v, None => return };
    if pw <= 0 || ph <= 0 { return; }

    with_client(fd, |c| {
        if let Some(win) = c.resources.get_window_mut(win_id) {
            win.ensure_pixels();
            let dww = win.width as i32;
            let dwh = win.height as i32;
            for py in y.max(0)..((y + region_h).min(dwh)) {
                // Tile: source row wraps the pixmap height (background tiling
                // is relative to the window origin per X core protocol).
                let sy = py.rem_euclid(ph);
                for dx in x.max(0)..((x + region_w).min(dww)) {
                    let sx = dx.rem_euclid(pw);
                    let so = ((sy * pw + sx) * 4) as usize;
                    let dofs = ((py * dww + dx) * 4) as usize;
                    if so + 4 <= px.len() && dofs + 4 <= win.pixels.len() {
                        win.pixels[dofs..dofs + 4].copy_from_slice(&px[so..so + 4]);
                    }
                }
            }
            if full_window { win.bg_painted = true; }
        }
    });
}

/// Mark a window's persistent surface as having had its viewable-time
/// background painted, so a subsequent full-window background paint becomes a
/// no-op (later client draws must persist).  Used by the solid-fill path of
/// `paint_window_background`, which routes through `window_fill_pixels` and so
/// does not itself touch the `bg_painted` flag.
fn mark_bg_painted(fd: u64, win_id: u32) {
    with_client(fd, |c| {
        if let Some(win) = c.resources.get_window_mut(win_id) {
            win.bg_painted = true;
        }
    });
}

/// Draw an 8×16 VGA-font string into a window's `w.pixels` (compositor source
/// of truth).  `fg`/`bg` are 0x00RRGGBB; the glyph cell background is filled
/// with `bg` (X11 ImageText8 semantics) and foreground pixels with `fg`.
/// `(tx, ty)` is the window-local baseline-top-left of the first glyph.
fn window_draw_text_pixels(fd: u64, win_id: u32, tx: i32, ty: i32, text: &str, fg: u32, bg: u32) {
    use crate::gui::compositor::VGA_FONT_8X16;
    const FW: i32 = 8;
    const FH: i32 = 16;
    let to_bgra = |c: u32| -> [u8; 4] {
        [(c & 0xFF) as u8, ((c >> 8) & 0xFF) as u8, ((c >> 16) & 0xFF) as u8, 0xFF]
    };
    let fg_bgra = to_bgra(fg);
    let bg_bgra = to_bgra(bg);
    with_client(fd, |c| {
        if let Some(win) = c.resources.get_window_mut(win_id) {
            win.ensure_pixels();
            let ww = win.width as i32;
            let wh = win.height as i32;
            let mut cx = tx;
            for ch in text.chars() {
                let cc = ch as u32;
                // ImageText8 draws over a solid background cell.
                for row in 0..FH {
                    let py = ty + row;
                    if py < 0 || py >= wh { continue; }
                    let glyph_byte = if (0x20..=0x7E).contains(&cc) {
                        VGA_FONT_8X16[((cc - 0x20) as usize) * 16 + row as usize]
                    } else { 0 };
                    for col in 0..FW {
                        let px = cx + col;
                        if px < 0 || px >= ww { continue; }
                        let off = ((py * ww + px) * 4) as usize;
                        if off + 4 > win.pixels.len() { continue; }
                        let bit = (glyph_byte >> (7 - col)) & 1 != 0;
                        win.pixels[off..off + 4].copy_from_slice(if bit { &fg_bgra } else { &bg_bgra });
                    }
                }
                cx += FW;
            }
        }
    });
}

/// Composite a window-local BGRA source rectangle into `w.pixels`.
///
/// `src` is a tightly packed BGRA buffer of `src_w × src_h` pixels; the region
/// `[(0,0)..(rw,rh)]` of `src` is placed at window-local `(dx,dy)`.  `op` is the
/// X Render PictOp: SRC/CLEAR copy the source; OVER (and any other value, which
/// the X Render protocol treats here as the default OVER for our purposes)
/// performs straight-alpha Porter-Duff "over" using the source alpha channel.
/// Both source and destination are clipped to their respective bounds.
fn window_composite_pixels(
    fd: u64, win_id: u32,
    dx: i32, dy: i32, rw: i32, rh: i32,
    src: &[u8], src_w: i32, src_h: i32, op: u8,
) {
    if rw <= 0 || rh <= 0 || src_w <= 0 || src_h <= 0 { return; }
    with_client(fd, |c| {
        if let Some(win) = c.resources.get_window_mut(win_id) {
            win.ensure_pixels();
            let ww = win.width as i32;
            let wh = win.height as i32;
            for row in 0..rh {
                let py = dy + row;
                if py < 0 || py >= wh || row >= src_h { continue; }
                for col in 0..rw {
                    let px = dx + col;
                    if px < 0 || px >= ww || col >= src_w { continue; }
                    let so = ((row * src_w + col) * 4) as usize;
                    let do_ = ((py * ww + px) * 4) as usize;
                    if so + 4 > src.len() || do_ + 4 > win.pixels.len() { continue; }
                    let sa = src[so + 3] as u32;
                    match op {
                        proto::RENDER_OP_SRC | proto::RENDER_OP_CLEAR => {
                            win.pixels[do_..do_ + 4].copy_from_slice(&src[so..so + 4]);
                        }
                        // RENDER_OP_OVER and default: straight-alpha "over".
                        _ => {
                            if sa == 255 {
                                win.pixels[do_..do_ + 4].copy_from_slice(&src[so..so + 4]);
                            } else if sa > 0 {
                                let ia = 255 - sa;
                                win.pixels[do_]     = ((src[so]     as u32 * sa + win.pixels[do_]     as u32 * ia) / 255) as u8;
                                win.pixels[do_ + 1] = ((src[so + 1] as u32 * sa + win.pixels[do_ + 1] as u32 * ia) / 255) as u8;
                                win.pixels[do_ + 2] = ((src[so + 2] as u32 * sa + win.pixels[do_ + 2] as u32 * ia) / 255) as u8;
                                win.pixels[do_ + 3] = (sa + win.pixels[do_ + 3] as u32 * ia / 255) as u8;
                            }
                        }
                    }
                }
            }
        }
    });
}

// ── CreateWindow (1) ──────────────────────────────────────────────────────────

fn op_create_window(fd: u64, data: &[u8], _seq: u16) {
    if data.len() < 32 { return; }
    let depth  = data[1];
    let wid    = r32(data, 4);
    let parent = r32(data, 8);
    let x      = r16(data, 12) as i16;
    let y      = r16(data, 14) as i16;
    let width  = r16(data, 16).max(1);
    let height = r16(data, 18).max(1);
    let bw     = r16(data, 20);
    let class  = r16(data, 22);
    let visual = r32(data, 24);
    let vmask  = r32(data, 28);
    let mut event_mask = 0u32; let mut bg_pixel = 0u32; let mut bg_pixmap = 0u32;
    let mut override_redirect = false;
    let mut vi = 32usize;
    if vmask & proto::CW_BACK_PIXMAP       != 0 { bg_pixmap = r32(data, vi); vi += 4; }
    if vmask & proto::CW_BACK_PIXEL        != 0 { bg_pixel = r32(data, vi); vi += 4; }
    if vmask & proto::CW_BORDER_PIXMAP     != 0 { vi += 4; }
    if vmask & proto::CW_BORDER_PIXEL      != 0 { vi += 4; }
    if vmask & proto::CW_BIT_GRAVITY       != 0 { vi += 4; }
    if vmask & proto::CW_WIN_GRAVITY       != 0 { vi += 4; }
    if vmask & proto::CW_BACKING_STORE     != 0 { vi += 4; }
    if vmask & proto::CW_BACKING_PLANES    != 0 { vi += 4; }
    if vmask & proto::CW_BACKING_PIXEL     != 0 { vi += 4; }
    if vmask & proto::CW_OVERRIDE_REDIRECT != 0 { override_redirect = r32(data, vi) != 0; vi += 4; }
    if vmask & proto::CW_SAVE_UNDER        != 0 { vi += 4; }
    if vmask & proto::CW_EVENT_MASK        != 0 { event_mask = r32(data, vi); vi += 4; }
    if vmask & proto::CW_DO_NOT_PROPAGATE  != 0 { vi += 4; }
    if vmask & proto::CW_COLORMAP          != 0 { vi += 4; }
    if vmask & proto::CW_CURSOR            != 0 { let _ = vi; }
    with_client(fd, |c| {
        let mut w = WindowData::new(
            if parent == 0 { proto::ROOT_WINDOW_ID } else { parent },
            x, y, width, height,
            if depth == 0 { proto::ROOT_DEPTH } else { depth },
            bw, if class == 0 { 1 } else { class },
            if visual == 0 { proto::ROOT_VISUAL } else { visual });
        w.event_mask = event_mask; w.background_pixel = bg_pixel;
        w.background_pixmap = bg_pixmap;
        w.override_redirect = override_redirect;
        if !c.resources.insert(wid, ResourceBody::Window(w)) {
            c.send_error(proto::ERR_ALLOC, wid, proto::OP_CREATE_WINDOW);
        }
    });
}

// ── ChangeWindowAttrs (2) ────────────────────────────────────────────────────

fn op_change_win_attrs(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let wid   = r32(data, 4);
    let vmask = r32(data, 8);
    with_client(fd, |c| {
        if wid == proto::ROOT_WINDOW_ID {
            // Root window has no per-client resource entry.  Track CWEventMask
            // changes in Client::root_event_mask so that deliver_property_notify
            // and op_send_event can respect the per-client root event mask.
            // Per X11 protocol §ChangeWindowAttributes, setting CWEventMask on
            // root registers the client's interest in root-window events.
            let mut vi = 12usize;
            if vmask & proto::CW_BACK_PIXMAP       != 0 { vi += 4; }
            if vmask & proto::CW_BACK_PIXEL        != 0 { vi += 4; }
            if vmask & proto::CW_BORDER_PIXMAP     != 0 { vi += 4; }
            if vmask & proto::CW_BORDER_PIXEL      != 0 { vi += 4; }
            if vmask & proto::CW_BIT_GRAVITY       != 0 { vi += 4; }
            if vmask & proto::CW_WIN_GRAVITY       != 0 { vi += 4; }
            if vmask & proto::CW_BACKING_STORE     != 0 { vi += 4; }
            if vmask & proto::CW_BACKING_PLANES    != 0 { vi += 4; }
            if vmask & proto::CW_BACKING_PIXEL     != 0 { vi += 4; }
            if vmask & proto::CW_OVERRIDE_REDIRECT != 0 { vi += 4; }
            if vmask & proto::CW_SAVE_UNDER        != 0 { vi += 4; }
            if vmask & proto::CW_EVENT_MASK        != 0 { c.root_event_mask = r32(data, vi); }
            return;
        }
        if let Some(w) = c.resources.get_window_mut(wid) {
            let mut vi = 12usize;
            // X core protocol: a new background takes effect on the next expose
            // or ClearArea, not immediately — so we only record it here.  Clear
            // `bg_painted` so the next viewable-time background paint re-applies
            // the new background (a window whose background changed has not yet
            // had THAT background painted).
            if vmask & proto::CW_BACK_PIXMAP       != 0 { w.background_pixmap = r32(data, vi); w.bg_painted = false; vi += 4; }
            if vmask & proto::CW_BACK_PIXEL        != 0 { w.background_pixel = r32(data, vi); w.background_pixmap = 0; w.bg_painted = false; vi += 4; }
            if vmask & proto::CW_BORDER_PIXMAP     != 0 { vi += 4; }
            if vmask & proto::CW_BORDER_PIXEL      != 0 { vi += 4; }
            if vmask & proto::CW_BIT_GRAVITY       != 0 { vi += 4; }
            if vmask & proto::CW_WIN_GRAVITY       != 0 { vi += 4; }
            if vmask & proto::CW_BACKING_STORE     != 0 { vi += 4; }
            if vmask & proto::CW_BACKING_PLANES    != 0 { vi += 4; }
            if vmask & proto::CW_BACKING_PIXEL     != 0 { vi += 4; }
            if vmask & proto::CW_OVERRIDE_REDIRECT != 0 { w.override_redirect = r32(data, vi) != 0; vi += 4; }
            if vmask & proto::CW_SAVE_UNDER        != 0 { vi += 4; }
            if vmask & proto::CW_EVENT_MASK        != 0 { w.event_mask = r32(data, vi); vi += 4; }
            if vmask & proto::CW_DO_NOT_PROPAGATE  != 0 { vi += 4; }
            if vmask & proto::CW_COLORMAP          != 0 { vi += 4; }
            if vmask & proto::CW_CURSOR            != 0 { let _ = vi; }
        }
    });
}

// ── GetWindowAttrs (3) ───────────────────────────────────────────────────────

fn op_get_win_attrs(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let wid = r32(data, 4);
    with_client(fd, |c| {
        // Look up window
        let info = c.resources.entries.iter()
            .filter_map(|s| s.as_ref()).find(|r| r.id == wid)
            .and_then(|r| if let ResourceBody::Window(ref w) = r.body {
                Some((w.visual, w.class, w.event_mask, w.mapped)) } else { None });
        let (visual, class, evmask, mapped) = if let Some(v) = info { v }
            else if wid == proto::ROOT_WINDOW_ID {
                (proto::ROOT_VISUAL, 1u16, 0u32, true)
            } else {
                c.send_error(proto::ERR_WINDOW, wid, proto::OP_GET_WINDOW_ATTRS); return;
            };
        let mut b = [0u8; 44];
        b[0]=1; b[1]=0; w16(&mut b,2,seq); w32(&mut b,4,3);
        w32(&mut b,8,visual); w16(&mut b,12,class);
        b[14]=1; b[15]=1;
        b[26] = if mapped { 2 } else { 0 };
        w32(&mut b,28,proto::DEFAULT_COLORMAP);
        w32(&mut b,32,evmask); w32(&mut b,36,evmask);
        c.send(&b);
    });
}

// ── DestroyWindow (4) ────────────────────────────────────────────────────────

fn op_destroy_window(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let wid = r32(data, 4);
    with_client(fd, |c| {
        if c.resources.has(wid) {
            let ev = event::encode_destroy_notify(seq, wid);
            c.send(&ev);
            c.resources.remove(wid);
        } else { c.send_error(proto::ERR_WINDOW, wid, proto::OP_DESTROY_WINDOW); }
    });
}

// ── Window viewability + exposure helpers ─────────────────────────────────────
//
// Per the X11 core protocol, a mapped window is "viewable" only if it AND all
// of its ancestors are mapped.  Exposure (Expose) events are generated when a
// window *becomes viewable*, not merely when its own MapWindow request is
// processed — a window mapped while an ancestor is still unmapped is
// "Unviewable" and gets no Expose until the ancestor maps.  These helpers let
// the map handlers obey that rule: MapNotify fires on the window's own map
// (StructureNotify), but Expose fires for the whole now-viewable subtree only
// once the window is actually viewable.

/// Snapshot of the fields needed for exposure processing, keyed by window id.
#[derive(Clone, Copy)]
struct WinInfo { id: u32, parent: u32, mapped: bool, evmask: u32,
                 x: i16, y: i16, w: u16, h: u16, bw: u16 }

/// Look up a window's exposure-relevant fields without holding a mutable borrow.
fn win_info(c: &Client, wid: u32) -> Option<WinInfo> {
    for r in c.resources.entries.iter().filter_map(|s| s.as_ref()) {
        if r.id == wid {
            if let ResourceBody::Window(ref w) = r.body {
                return Some(WinInfo { id: wid, parent: w.parent, mapped: w.mapped,
                    evmask: w.event_mask, x: w.x, y: w.y, w: w.width, h: w.height,
                    bw: w.border_width });
            }
        }
    }
    None
}

/// True if `wid` is viewable: it is mapped and every ancestor up to (and
/// including the implicit) root is mapped.  The root window has no per-client
/// resource entry and is always mapped, so reaching it (or an unknown
/// ancestor that is the root) terminates the walk successfully.  A depth cap
/// guards against malformed parent cycles.
fn is_viewable(c: &Client, wid: u32) -> bool {
    let mut cur = wid;
    for _ in 0..64 {
        if cur == proto::ROOT_WINDOW_ID { return true; }
        match win_info(c, cur) {
            Some(wi) => {
                if !wi.mapped { return false; }
                cur = wi.parent;
            }
            // Parent not in our table (e.g. reparented under the root/WM frame)
            // — treat as the always-mapped root boundary.
            None => return true,
        }
    }
    false
}

/// Run exposure processing for the subtree rooted at `root_wid`: send an Expose
/// to `root_wid` and to every descendant that has just become viewable and has
/// selected Exposure.  MapNotify is emitted separately by the caller before
/// this runs (the protocol orders MapNotify before Expose).
///
/// Returns the list of viewable, mapped windows in the subtree (root +
/// descendants).  Per the X core protocol the server paints a window's
/// background when it first becomes viewable, BEFORE delivering its Expose, so
/// the client's Expose-driven redraw lands on the initialised background rather
/// than an uninitialised (black) surface.  The caller paints these backgrounds
/// after releasing the SERVER lock — `paint_window_background` re-acquires it,
/// so it cannot run inside the `with_client` block that wraps this call.
fn expose_viewable_subtree(c: &Client, root_wid: u32, seq: u16) -> alloc::vec::Vec<u32> {
    // Collect the subtree (root + transitive descendants) from the flat table.
    let mut subtree: alloc::vec::Vec<WinInfo> = alloc::vec::Vec::new();
    if let Some(root) = win_info(c, root_wid) { subtree.push(root); }
    let mut i = 0;
    while i < subtree.len() {
        let pid = subtree[i].id;
        for r in c.resources.entries.iter().filter_map(|s| s.as_ref()) {
            if let ResourceBody::Window(ref w) = r.body {
                if w.parent == pid && !subtree.iter().any(|s| s.id == r.id) {
                    subtree.push(WinInfo { id: r.id, parent: w.parent, mapped: w.mapped,
                        evmask: w.event_mask, x: w.x, y: w.y, w: w.width, h: w.height,
                        bw: w.border_width });
                }
            }
        }
        i += 1;
    }
    let mut to_paint: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    for wi in &subtree {
        let viewable = is_viewable(c, wi.id);
        #[cfg(feature = "xeyes-test")]
        crate::serial_println!("[X11EXPOSE] subtree wid={:#x} mapped={} evmask={:#x} exposure={} viewable={}",
            wi.id, wi.mapped, wi.evmask,
            wi.evmask & proto::EVENT_MASK_EXPOSURE != 0, viewable);
        if wi.mapped && viewable {
            // Every newly-viewable window (root, container, or leaf widget such
            // as the Eyes child) needs its background painted so an Expose-driven
            // redraw has an initialised surface to draw over.  Collect it for the
            // caller's post-lock paint pass.  Exposure delivery below is a
            // separate, ExposureMask-gated decision.
            to_paint.push(wi.id);
            if wi.evmask & proto::EVENT_MASK_EXPOSURE != 0 {
                c.send(&event::encode_expose(seq, wi.id, wi.x, wi.y, wi.w, wi.h));
            }
        }
    }
    to_paint
}

/// Send a ConfigureNotify to `wid` reporting its current geometry, if it
/// selected StructureNotify.  Per the X11 core protocol map sequence, a window
/// that selected StructureNotify receives MapNotify and then, before Expose, a
/// ConfigureNotify describing its on-screen geometry.  Toolkits (libXt) use
/// this to learn the realized size of the shell before running their first
/// layout/redisplay pass; without it the widget tree can stay un-configured and
/// never paint.
fn configure_notify_if_selected(c: &Client, wid: u32, seq: u16) {
    if let Some(wi) = win_info(c, wid) {
        if wi.evmask & proto::EVENT_MASK_STRUCTURE_NOTIFY != 0 {
            c.send(&event::encode_configure_notify(seq, wid, wi.x, wi.y, wi.w, wi.h, wi.bw));
        }
    }
}

// ── MapWindow (8) ─────────────────────────────────────────────────────────────

fn op_map_window(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let wid = r32(data, 4);
    let mut to_paint: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    with_client(fd, |c| {
        let (width, height, evmask) = match c.resources.get_window_mut(wid) {
            Some(w) => {
                let dims = (w.width, w.height, w.event_mask);
                w.mapped = true;
                w.ensure_pixels(); // Allocate pixel buffer for compositor
                dims
            }
            None => { c.send_error(proto::ERR_WINDOW, wid, proto::OP_MAP_WINDOW); return; }
        };
        // StructureNotify: MapNotify fires on the window's own map.  Per the
        // X11 core protocol §MapWindow, a ConfigureNotify is NOT generated by a
        // plain MapWindow — it is sent only when mapping actually changes the
        // window's geometry (e.g. via win-gravity adjustment or a pending
        // ConfigureWindow).  A real X server's map sequence for an unmanaged,
        // unchanged-geometry window is therefore MapNotify → Expose with no
        // intervening ConfigureNotify; emitting a spurious ConfigureNotify makes
        // libXt's Shell run an extra geometry pass that can swallow the child's
        // first Expose (observed: the Eyes leaf widget never runs its
        // Expose-driven Redisplay).  See op_configure_window for the legitimate
        // ConfigureNotify path on an actual geometry change.
        if evmask & proto::EVENT_MASK_STRUCTURE_NOTIFY != 0 {
            c.send(&event::encode_map_notify(seq, wid));
        }
        // Exposure: mapping this window may have made it AND a subtree of
        // already-mapped descendants viewable for the first time.  Send Expose
        // to every window in that subtree that is now viewable and selected
        // Exposure — this is where a child mapped earlier (while this ancestor
        // was unmapped) finally gets its Expose.  The returned ids are the
        // windows that just became viewable and need their backgrounds painted.
        to_paint = expose_viewable_subtree(c, wid, seq);
        crate::serial_println!("[X11] MapWindow {:#x} {}x{}", wid, width, height);
    });
    // Paint each newly-viewable window's background now (X core protocol: the
    // server paints the background when a window becomes viewable, before its
    // Expose-driven redraw runs).  Done AFTER the with_client block above
    // because paint_window_background re-acquires the SERVER lock — calling it
    // inside would deadlock.  `full_window=true`: idempotent viewable-time paint
    // gated on `bg_painted`, so a second MapWindow over content already drawn
    // into a surface (e.g. a prior RENDER Composite or core-arc draw) is a
    // no-op.  This covers the CHILD widget windows (e.g. the xeyes Eyes child),
    // whose backgrounds were previously never painted — leaving the Eyes child
    // an uninitialised black rectangle even after its Expose drove a redraw.
    for &pwid in &to_paint {
        paint_window_background(fd, pwid, 0, 0, 0, 0, true);
    }
}

// ── MapSubwindows (9) ─────────────────────────────────────────────────────────
//
// Map every unmapped child of `parent` in bottom-to-top order, as required by
// the X11 core protocol: toolkits (libXt's XtRealizeWidget, GTK) map the
// container then call MapSubwindows to map the leaf widget windows.  Each newly
// mapped child gets its pixel buffer allocated and a MapNotify (per its event
// mask).  Expose is generated only for children that have actually become
// viewable — i.e. only when `parent` is itself viewable.  If `parent` is still
// unmapped, the children are mapped-but-Unviewable and their Expose is deferred
// until the parent maps (handled by MapWindow's subtree exposure pass).
fn op_map_subwindows(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let parent = r32(data, 4);
    let mut to_paint: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    with_client(fd, |c| {
        // Collect child ids first (avoid borrowing the resource table mutably
        // while iterating it).  Children are windows whose `parent` field
        // matches; the protocol maps them bottom-to-top, i.e. in stacking order
        // — our resource table preserves creation order which suffices here.
        let mut children: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        for r in c.resources.entries.iter().filter_map(|s| s.as_ref()) {
            if let ResourceBody::Window(ref w) = r.body {
                if w.parent == parent && !w.mapped {
                    children.push(r.id);
                }
            }
        }
        for &cid in &children {
            let (width, height, evmask) = match c.resources.get_window_mut(cid) {
                Some(w) => {
                    let dims = (w.width, w.height, w.event_mask);
                    w.mapped = true;
                    w.ensure_pixels();
                    dims
                }
                None => continue,
            };
            // StructureNotify: MapNotify (then ConfigureNotify) fires on the
            // child's own map regardless of viewability (it is genuinely now
            // mapped) — the X11 core-protocol map sequence.
            if evmask & proto::EVENT_MASK_STRUCTURE_NOTIFY != 0 {
                c.send(&event::encode_map_notify(seq, cid));
            }
            configure_notify_if_selected(c, cid, seq);
            crate::serial_println!("[X11] MapSubwindow {:#x} (parent {:#x}) {}x{} evmask={:#x}",
                cid, parent, width, height, evmask);
        }
        // Exposure: only the children that became viewable get an Expose.  If
        // the parent is unmapped they are Unviewable and Expose is deferred to
        // the parent's MapWindow.  Run the subtree pass per mapped child so
        // grandchildren are covered too.  Accumulate the viewable windows whose
        // backgrounds must be painted after the lock is released.
        for &cid in &children {
            let mut sub = expose_viewable_subtree(c, cid, seq);
            to_paint.append(&mut sub);
        }
    });
    // Paint each newly-viewable child/grandchild background (post-lock; see
    // op_map_window for the deadlock rationale).  Without this a leaf widget
    // mapped via MapSubwindows under an already-viewable parent never had its
    // background initialised, so its Expose-driven redraw drew onto a black
    // surface.
    for &pwid in &to_paint {
        paint_window_background(fd, pwid, 0, 0, 0, 0, true);
    }
}

// ── UnmapWindow (10) ──────────────────────────────────────────────────────────

fn op_unmap_window(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let wid = r32(data, 4);
    with_client(fd, |c| {
        if let Some(w) = c.resources.get_window_mut(wid) {
            w.mapped = false;
            if w.event_mask & proto::EVENT_MASK_STRUCTURE_NOTIFY != 0 {
                c.send(&event::encode_unmap_notify(seq, wid));
            }
        }
    });
}

// ── ConfigureWindow (12) ──────────────────────────────────────────────────────

fn op_configure_window(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 12 { return; }
    let wid  = r32(data, 4);
    let mask = r16(data, 8);
    with_client(fd, |c| {
        if let Some(w) = c.resources.get_window_mut(wid) {
            let mut vi = 12usize;
            if mask & proto::CW_X      != 0 { w.x = r16(data, vi) as i16; vi += 4; }
            if mask & proto::CW_Y      != 0 { w.y = r16(data, vi) as i16; vi += 4; }
            if mask & proto::CW_WIDTH  != 0 { w.width  = r16(data, vi).max(1); vi += 4; }
            if mask & proto::CW_HEIGHT != 0 { w.height = r16(data, vi).max(1); }
            let (x,y,width,height,bw,evmask) = (w.x,w.y,w.width,w.height,w.border_width,w.event_mask);
            if evmask & proto::EVENT_MASK_STRUCTURE_NOTIFY != 0 {
                c.send(&event::encode_configure_notify(seq, wid, x, y, width, height, bw));
            }
        }
    });
}

// ── GetGeometry (14) ──────────────────────────────────────────────────────────

fn op_get_geometry(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let draw = r32(data, 4);
    with_client(fd, |c| {
        // Try to find the drawable in the resource table
        let info = c.resources.entries.iter().filter_map(|s| s.as_ref())
            .find(|r| r.id == draw)
            .map(|r| match &r.body {
                ResourceBody::Window(w) => (w.width,w.height,w.depth,w.x as u16,w.y as u16,w.border_width),
                ResourceBody::Pixmap(p) => (p.width,p.height,p.depth,0u16,0u16,0u16),
                _ => (0,0,0,0,0,0),
            });
        let (w_,h_,dep,x_,y_,bw_) = info.unwrap_or_else(|| {
            if draw == proto::ROOT_WINDOW_ID {
                (proto::SCREEN_WIDTH, proto::SCREEN_HEIGHT, proto::ROOT_DEPTH, 0, 0, 0)
            } else { (0,0,0,0,0,0) }
        });
        if w_ == 0 && draw != proto::ROOT_WINDOW_ID {
            c.send_error(proto::ERR_DRAWABLE, draw, proto::OP_GET_GEOMETRY); return;
        }
        let mut b = [0u8; 32];
        b[0]=1; b[1]=dep; w16(&mut b,2,seq); w32(&mut b,8,proto::ROOT_WINDOW_ID);
        w16(&mut b,12,x_); w16(&mut b,14,y_); w16(&mut b,16,w_); w16(&mut b,18,h_); w16(&mut b,20,bw_);
        c.send(&b);
    });
}

// ── QueryTree (15) ────────────────────────────────────────────────────────────

fn op_query_tree(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let wid = r32(data, 4);
    with_client(fd, |c| {
        let ok = wid == proto::ROOT_WINDOW_ID || c.resources.has(wid);
        if !ok { c.send_error(proto::ERR_WINDOW, wid, proto::OP_QUERY_TREE); return; }
        let parent = if wid == proto::ROOT_WINDOW_ID { 0 } else { proto::ROOT_WINDOW_ID };
        let mut b = [0u8; 32];
        b[0]=1; w16(&mut b,2,seq); w32(&mut b,8,proto::ROOT_WINDOW_ID); w32(&mut b,12,parent);
        c.send(&b);
    });
}

// ── InternAtom (16) ───────────────────────────────────────────────────────────

fn op_intern_atom(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let oie  = data[1] != 0;
    let nlen = r16(data, 4) as usize;
    if data.len() < 8 + nlen { return; }
    let name = core::str::from_utf8(&data[8..8+nlen]).unwrap_or("");
    let atom = atoms::intern(name, oie);
    let mut b = [0u8; 32]; b[0]=1; w16(&mut b,2,seq); w32(&mut b,8,atom);
    with_client(fd, |c| c.send(&b));
    crate::serial_println!("[X11] InternAtom({:?}) -> {}", name, atom);
}

// ── GetAtomName (17) ──────────────────────────────────────────────────────────

fn op_get_atom_name(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let id = r32(data, 4);
    with_client(fd, |c| {
        match atoms::get_name(id) {
            None => c.send_error(proto::ERR_ATOM, id, proto::OP_GET_ATOM_NAME),
            Some(name) => {
                let nb = name.len(); let pd = proto::pad4(nb); let tot = 32+pd;
                let mut v = vec![0u8; tot];
                v[0]=1; w16(&mut v,2,seq); w32(&mut v,4,(pd/4) as u32); w16(&mut v,8,nb as u16);
                v[32..32+nb].copy_from_slice(name.as_bytes());
                c.send(&v);
            }
        }
    });
}

// ── ChangeProperty (18) ───────────────────────────────────────────────────────
//
// Per X11 protocol §ChangeProperty: after updating the property, deliver a
// PropertyNotify (28) event to every client that selected PropertyChangeMask
// (0x0040_0000) on the target window.  ICCCM §4 requires this so that window
// managers tracking WM_NAME, WM_HINTS, _NET_WM_NAME etc. learn of changes.

fn op_change_property(fd: u64, data: &[u8]) {
    if data.len() < 24 { return; }
    let mode   = data[1];
    let wid    = r32(data, 4);
    let prop   = r32(data, 8);
    let type_  = r32(data, 12);
    let fmt    = data[16];
    let nunits = r32(data, 20) as usize;
    let nbytes = nunits * (fmt as usize / 8).max(1);
    let pdata  = &data[24..data.len().min(24+nbytes)];
    if wid == proto::ROOT_WINDOW_ID {
        let mut srv = SERVER.lock();
        prop_arr_set(&mut srv.root_properties, prop, type_, fmt, pdata, mode);
    } else {
        with_client(fd, |c| {
            if let Some(w) = c.resources.get_window_mut(wid) {
                w.set_property(prop, type_, fmt, pdata, mode);
            }
        });
    }
    // Deliver PropertyNotify to all clients watching this window.
    deliver_property_notify(wid, prop, false);
}

/// Deliver a PropertyNotify event to all clients that selected
/// PropertyChangeMask on `window`.  `deleted` is true for DeleteProperty.
///
/// Per X11 protocol §ChangeProperty, PropertyNotify on the root window is
/// gated by PropertyChangeMask just like any other window.  Clients register
/// their interest by calling ChangeWindowAttributes(root, CWEventMask,
/// PropertyChangeMask), which is recorded in `Client::root_event_mask`.
fn deliver_property_notify(window: u32, atom: u32, deleted: bool) {
    let tick = crate::arch::x86_64::irq::get_ticks() as u32;
    let mut srv = SERVER.lock();
    for slot in srv.clients.iter_mut() {
        if let Some(c) = slot {
            // Check if the client has selected PropertyChangeMask on this window.
            let has_mask = if window == proto::ROOT_WINDOW_ID {
                // Root window: use the per-client root event mask set via
                // ChangeWindowAttributes(root, CWEventMask, ...).
                c.root_event_mask & proto::EVENT_MASK_PROPERTY_CHANGE != 0
            } else {
                c.resources.entries.iter()
                    .filter_map(|s| s.as_ref())
                    .find(|r| r.id == window)
                    .map(|r| match &r.body {
                        resource::ResourceBody::Window(w) =>
                            w.event_mask & proto::EVENT_MASK_PROPERTY_CHANGE != 0,
                        _ => false,
                    })
                    .unwrap_or(false)
            };
            if has_mask {
                // Per X11 protocol §11.1, every event carries the sequence
                // number of the last REQUEST received from that client — it
                // does NOT advance the request counter.  Advancing c.seq here
                // would desynchronise subsequent reply sequence numbers from
                // what the client's Xlib expects, manifesting as silent client
                // exit on the next reply.
                let ev = event::encode_property_notify(c.seq, window, atom, tick, deleted);
                unix::write(c.fd, &ev);
            }
        }
    }
}

// ── DeleteProperty (19) ──────────────────────────────────────────────────────

fn op_delete_property(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let wid  = r32(data, 4);
    let atom = r32(data, 8);
    if wid == proto::ROOT_WINDOW_ID {
        let mut srv = SERVER.lock();
        prop_arr_del(&mut srv.root_properties, atom);
    } else {
        with_client(fd, |c| { if let Some(w) = c.resources.get_window_mut(wid) { w.delete_property(atom); } });
    }
    // Deliver PropertyNotify (state=Deleted) per X11 protocol §DeleteProperty.
    deliver_property_notify(wid, atom, true);
}

// ── GetProperty reply helper ──────────────────────────────────────────────────

fn send_get_property_reply(
    fd:      u64,
    seq:     u16,
    rtype:   u32,
    offset:  usize,
    req_len: usize,
    result:  Option<(u32, u8, usize, [u8; resource::MAX_PROPERTY_DATA])>,
) {
    match result {
        None => {
            let mut b = [0u8; 32]; b[0] = 1; w16(&mut b, 2, seq);
            unix::write(fd, &b);
        }
        Some((t, f, n, raw)) => {
            if rtype != 0 && rtype != t {
                let mut b = [0u8; 32]; b[0]=1; w16(&mut b,2,seq); w32(&mut b,8,t);
                w32(&mut b,12,n as u32); unix::write(fd, &b);
                return;
            }
            let start  = offset.min(n);
            let avail  = n - start;
            let slen   = avail.min(req_len);
            let remain = avail - slen;
            let pd     = proto::pad4(slen);
            let mut rep = alloc::vec![0u8; 32 + pd];
            rep[0]=1; rep[1]=f; w16(&mut rep,2,seq); w32(&mut rep,4,(pd/4) as u32);
            w32(&mut rep,8,t); w32(&mut rep,12,remain as u32);
            w32(&mut rep,16,(slen/(f as usize/8).max(1)) as u32);
            if slen > 0 { rep[32..32+slen].copy_from_slice(&raw[start..start+slen]); }
            unix::write(fd, &rep);
        }
    }
}

// ── GetProperty (20) ─────────────────────────────────────────────────────────

fn op_get_property(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 24 { return; }
    let delete  = data[1] != 0;
    let wid     = r32(data, 4);
    let atom    = r32(data, 8);
    let rtype   = r32(data, 12);
    let offset  = r32(data, 16) as usize * 4;
    let req_len = r32(data, 20) as usize * 4;
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    crate::serial_println!("[X11GP] fd={} wid={} atom={} seq={}", fd, wid, atom, seq);

    // Root-window properties are stored in SERVER.root_properties, not per-client.
    if wid == proto::ROOT_WINDOW_ID {
        let result = if atom == 0 { None } else {
            SERVER.lock().root_properties
                .iter().filter_map(|s| s.as_ref()).find(|p| p.name == atom)
                .map(|p| {
                    let mut arr = [0u8; resource::MAX_PROPERTY_DATA];
                    arr[..p.len].copy_from_slice(&p.data[..p.len]);
                    (p.type_, p.format, p.len, arr)
                })
        };
        let client_fd_for_send = fd;
        send_get_property_reply(client_fd_for_send, seq, rtype, offset, req_len, result);
        if delete { let mut srv = SERVER.lock(); prop_arr_del(&mut srv.root_properties, atom); }
        return;
    }

    with_client(fd, |c| {
        if atom == 0 {
            let mut b = [0u8;32]; b[0]=1; w16(&mut b,2,seq);
            let wr = unix::write(c.fd, &b);
            #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
            crate::serial_println!("[X11GP] atom=0 empty reply fd={} wr={}", c.fd, wr);
            return;
        }
        let result = c.resources.get_window_mut(wid).and_then(|w| {
            w.get_property(atom).map(|p| {
                let mut arr = [0u8; resource::MAX_PROPERTY_DATA];
                arr[..p.len].copy_from_slice(&p.data[..p.len]);
                (p.type_, p.format, p.len, arr)
            })
        });
        #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
        crate::serial_println!("[X11GP] result={} wid={} atom={}", result.is_some(), wid, atom);
        match result {
            None => {
                let mut b=[0u8;32]; b[0]=1; w16(&mut b,2,seq);
                let wr = unix::write(c.fd, &b);
                #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
                crate::serial_println!("[X11GP] none-reply fd={} seq={} wr={}", c.fd, seq, wr);
            }
            Some((type_,fmt,total,raw)) => {
                if rtype != 0 && rtype != type_ {
                    let mut b=[0u8;32]; b[0]=1; w16(&mut b,2,seq); w32(&mut b,8,type_);
                    w32(&mut b,12,total as u32); c.send(&b); return;
                }
                let start    = offset.min(total);
                let avail    = total - start;
                let slen     = avail.min(req_len);
                let remain   = avail - slen;
                let pd       = proto::pad4(slen);
                let mut rep  = vec![0u8; 32+pd];
                rep[0]=1; rep[1]=fmt; w16(&mut rep,2,seq); w32(&mut rep,4,(pd/4) as u32);
                w32(&mut rep,8,type_); w32(&mut rep,12,remain as u32);
                w32(&mut rep,16,(slen/(fmt as usize/8).max(1)) as u32);
                rep[32..32+slen].copy_from_slice(&raw[start..start+slen]);
                c.send(&rep);
                if delete && remain == 0 {
                    if let Some(w) = c.resources.get_window_mut(wid) { w.delete_property(atom); }
                }
            }
        }
    });
}

// ── ListProperties (21) ─────────────────────────────────────────────────────

fn op_list_properties(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let wid = r32(data, 4);
    with_client(fd, |c| {
        let mut list = [0u32; resource::MAX_PROPERTIES]; let mut cnt = 0usize;
        if let Some(w) = c.resources.get_window_mut(wid) {
            for sl in w.properties.iter() {
                if let Some(p) = sl { list[cnt] = p.name; cnt += 1; }
            }
        }
        let bd = cnt*4; let pd = proto::pad4(bd); let tot = 32+pd;
        let mut rep = vec![0u8; tot];
        rep[0]=1; w16(&mut rep,2,seq); w32(&mut rep,4,(pd/4) as u32); w16(&mut rep,8,cnt as u16);
        for (i,&a) in list[..cnt].iter().enumerate() { w32(&mut rep, 32+i*4, a); }
        c.send(&rep);
    });
}

// ── SelectInput (25) ─────────────────────────────────────────────────────────

fn op_select_input(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let wid = r32(data, 4); let evmask = r32(data, 8);
    with_client(fd, |c| { if let Some(w) = c.resources.get_window_mut(wid) { w.event_mask = evmask; } });
}

// ── SetSelectionOwner (22) ───────────────────────────────────────────────────

fn op_set_selection_owner(fd: u64, data: &[u8], _seq: u16) {
    if data.len() < 16 { return; }
    // [4..8]=owner window, [8..12]=selection atom, [12..16]=timestamp
    let owner_win = r32(data, 4);
    let selection = r32(data, 8);
    let timestamp = r32(data, 12);
    let tick = crate::arch::x86_64::irq::get_ticks() as u32;
    let ts = if timestamp == 0 { tick } else { timestamp };

    let mut srv = SERVER.lock();
    // Find existing entry for this selection atom.
    let mut old_owner_fd = u64::MAX;
    let mut old_owner_win = 0u32;
    for slot in srv.selections.iter_mut() {
        if slot.selection == selection {
            old_owner_fd  = slot.owner_fd;
            old_owner_win = slot.owner;
            slot.owner     = owner_win;
            slot.owner_fd  = if owner_win != 0 { fd } else { u64::MAX };
            slot.timestamp = ts;
            break;
        }
    }
    // If no slot found, allocate a new one.
    if old_owner_fd == u64::MAX && owner_win != 0 {
        for slot in srv.selections.iter_mut() {
            if slot.selection == 0 {
                slot.selection = selection;
                slot.owner     = owner_win;
                slot.owner_fd  = fd;
                slot.timestamp = ts;
                break;
            }
        }
    }
    // Send SelectionClear to the previous owner if it differs.
    if old_owner_win != 0 && old_owner_win != owner_win && old_owner_fd != u64::MAX {
        let mut ev = [0u8; 32];
        ev[0] = proto::EVENT_SELECTION_CLEAR;
        w32(&mut ev, 4, ts);
        w32(&mut ev, 8, old_owner_win);
        w32(&mut ev, 12, selection);
        unix::write(old_owner_fd, &ev);
    }
}

// ── GetSelectionOwner (23) ───────────────────────────────────────────────────

fn op_get_selection_owner(fd: u64, data: &[u8], seq: u16) {
    let selection = if data.len() >= 8 { r32(data, 4) } else { 0 };
    let owner = SERVER.lock().selections.iter()
        .find(|s| s.selection == selection).map(|s| s.owner).unwrap_or(0);
    let mut b = [0u8; 32]; b[0]=1; w16(&mut b,2,seq); w32(&mut b,8,owner);
    unix::write(fd, &b);
}

// ── ConvertSelection (24) ────────────────────────────────────────────────────

fn op_convert_selection(fd: u64, data: &[u8], _seq: u16) {
    if data.len() < 24 { return; }
    let selection  = r32(data, 4);
    let target     = r32(data, 8);
    let property   = r32(data, 12);
    let requestor  = r32(data, 16);
    let timestamp  = r32(data, 20);
    let tick = crate::arch::x86_64::irq::get_ticks() as u32;
    let ts = if timestamp == 0 { tick } else { timestamp };

    let (owner_win, owner_fd) = {
        let srv = SERVER.lock();
        srv.selections.iter().find(|s| s.selection == selection)
            .map(|s| (s.owner, s.owner_fd))
            .unwrap_or((0, u64::MAX))
    };

    if owner_win == 0 || owner_fd == u64::MAX {
        // No owner — send SelectionNotify with property=None to requestor.
        let mut ev = [0u8; 32];
        ev[0] = proto::EVENT_SELECTION_NOTIFY;
        w32(&mut ev, 4, ts);
        w32(&mut ev, 8, requestor);
        w32(&mut ev, 12, selection);
        w32(&mut ev, 16, target);
        // property = 0 (None)
        unix::write(fd, &ev);
    } else {
        // Owner exists — send SelectionRequest to owner.
        let mut ev = [0u8; 32];
        ev[0] = proto::EVENT_SELECTION_REQUEST;
        w32(&mut ev, 4, ts);
        w32(&mut ev, 8, owner_win);
        w32(&mut ev, 12, requestor);
        w32(&mut ev, 16, selection);
        w32(&mut ev, 20, target);
        w32(&mut ev, 24, property);
        unix::write(owner_fd, &ev);
    }
}

// ── SendEvent (25) ───────────────────────────────────────────────────────────
//
// Per X11 protocol §SendEvent:
//   Request layout:
//     [0]    opcode (25)
//     [1]    propagate (BOOL)
//     [2-3]  length (11 4-byte units = 44 bytes total)
//     [4-7]  destination window (or 0=PointerWindow, 1=InputFocus)
//     [8-11] event-mask (SETofEVENT: which event types to deliver)
//     [12-43] event (32 bytes, the raw event packet)
//
// Server action: force the most significant bit of the event-type byte (byte 0
// of the event) to 1 (to mark it as a synthetic event), set the sequence number,
// then deliver the 32-byte event to every client that has selected any of the
// event-mask bits on the destination window.
//
// Special destination values per spec:
//   0 (PointerWindow): treat as the window containing the pointer (unimplemented
//     here — we fall back to root).
//   1 (InputFocus): deliver to the client whose input focus window matches.
//
// This is the mechanism ICCCM WM_DELETE_WINDOW uses: the WM sends a ClientMessage
// (type=WM_PROTOCOLS, data[0]=WM_DELETE_WINDOW) to the window via SendEvent.

fn op_send_event(fd: u64, data: &[u8], _seq: u16) {
    if data.len() < 44 { return; }
    let _propagate  = data[1] != 0;
    let destination = r32(data, 4);
    let event_mask  = r32(data, 8);

    // Copy the 32-byte event payload, forcing bit 7 of the type byte (synthetic).
    // ev[0] is set once here (synthetic MSB); ev[2..4] is overwritten per-client
    // (per-client sequence number) inside the delivery loop below.
    let mut ev = [0u8; 32];
    ev.copy_from_slice(&data[12..44]);
    ev[0] |= 0x80; // mark as synthetic per X11 protocol §SendEvent

    // Resolve destination: 0=PointerWindow (root fallback), 1=InputFocus.
    let dest_window = match destination {
        0 => proto::ROOT_WINDOW_ID, // PointerWindow — fall back to root
        1 => {
            // InputFocus — deliver to the server-global focused window.
            SERVER.lock().focus_window
        }
        w => {
            // Explicit XID.  Per X11 protocol §SendEvent, if the window does not
            // exist on any client, return BadWindow to the sender.
            let exists = {
                let srv = SERVER.lock();
                w == proto::ROOT_WINDOW_ID
                    || srv.clients.iter().filter_map(|s| s.as_ref())
                        .any(|c| c.resources.entries.iter()
                            .filter_map(|s| s.as_ref())
                            .any(|r| r.id == w))
            };
            if !exists {
                with_client(fd, |c| {
                    c.send_error(proto::ERR_WINDOW, w, proto::OP_SEND_EVENT);
                });
                return;
            }
            w
        }
    };

    // Deliver to every client that owns dest_window and has any of the
    // event_mask bits selected on that window.  Root delivery respects the
    // event-mask filter just like any other window (X11 protocol §SendEvent).
    let mut srv = SERVER.lock();
    for slot in srv.clients.iter_mut() {
        if let Some(c) = slot {
            // Determine whether this client receives the event.
            // event_mask==0 (NoEventMask): deliver to the window owner only,
            // unconditionally — per X11 §SendEvent, propagate=false + mask=0
            // goes to the client that created the window.
            let matches = if dest_window == proto::ROOT_WINDOW_ID {
                // Root window: apply the per-client root event mask, just as
                // any other window.  WMs register by setting their mask on root.
                if event_mask == 0 {
                    true // root always "owns" itself; deliver to all clients
                } else {
                    c.root_event_mask & event_mask != 0
                }
            } else if event_mask == 0 {
                c.resources.entries.iter()
                    .filter_map(|s| s.as_ref())
                    .any(|r| r.id == dest_window)
            } else {
                c.resources.entries.iter()
                    .filter_map(|s| s.as_ref())
                    .find(|r| r.id == dest_window)
                    .map(|r| match &r.body {
                        resource::ResourceBody::Window(w) =>
                            w.event_mask & event_mask != 0,
                        _ => false,
                    })
                    .unwrap_or(false)
            };
            if matches {
                // Per X11 protocol §11.1, events carry the sequence number
                // of the last REQUEST from the receiving client — they do
                // NOT advance the request counter.  Stamping a fresh seq
                // here would desync subsequent reply sequence numbers.
                ev[2] = (c.seq & 0xFF) as u8;
                ev[3] = (c.seq >> 8) as u8;
                unix::write(c.fd, &ev);
            }
        }
    }
}

// ── QueryPointer (38) ───────────────────────────────────────────────────────

fn op_query_pointer(fd: u64, seq: u16) {
    let mut b = [0u8;32]; b[0]=1; b[1]=1; // same-screen = True
    w16(&mut b,2,seq);
    w32(&mut b,8,proto::ROOT_WINDOW_ID);  // root window
    // child=0, root_x/root_y=center, win_x/win_y=0, mask=0
    w16(&mut b,20, proto::SCREEN_WIDTH/2);  // root-x
    w16(&mut b,22, proto::SCREEN_HEIGHT/2); // root-y
    with_client(fd, |c| c.send(&b));
}

// ── TranslateCoordinates (40) ────────────────────────────────────────────────
//
// Per X11 core protocol §TranslateCoordinates: given a point (src_x, src_y) in
// the coordinate space of src_window, return the equivalent point (dst_x, dst_y)
// in the coordinate space of dst_window, the `child` of dst_window that contains
// the point (or None), and `same_screen`.  GDK calls this through
// gdk_window_get_origin / gdk_x11_window_get_root_coords during window
// realization and pointer handling; an unanswered request (the server replying
// BadRequest) makes those return garbage coordinates.
//
// Request layout (4 words, 16 bytes):
//   [0] opcode/unused/length   [4] src_window   [8] dst_window
//   [12] src_x (CARD16)        [14] src_y (CARD16)
//
// Reply (32 bytes): byte 1 = same_screen (BOOL), word at 8 = child (WINDOW,
// 0 = None), INT16 at 16 = dst_x, INT16 at 18 = dst_y.
//
// We translate via each window's absolute (root-relative) origin: the point in
// root space is src_abs_origin + (src_x, src_y), and the result is that minus
// dst_abs_origin.  This is exact for the flat-under-root window model the
// server presents (toplevels positioned by their x/y, children offset by their
// parents'); `child` is reported as None (0), which is a valid answer when no
// mapped child of dst_window contains the point and is what GDK tolerates.

/// Absolute (root-relative) origin of a window resource, walking the parent
/// chain.  Returns (0,0) for the root window or an unknown drawable.
fn window_abs_origin(c: &Client, wid: u32) -> (i32, i32) {
    let mut ax = 0i32;
    let mut ay = 0i32;
    let mut cur = wid;
    // Bound the walk to the resource-table size to defend against a malformed
    // parent cycle; a legitimate hierarchy is at most a few levels deep.
    for _ in 0..resource::MAX_RESOURCES {
        if cur == proto::ROOT_WINDOW_ID || cur == 0 { break; }
        let found = c.resources.entries.iter().filter_map(|s| s.as_ref())
            .find(|r| r.id == cur)
            .and_then(|r| match &r.body {
                ResourceBody::Window(w) => Some((w.x as i32, w.y as i32, w.parent)),
                _ => None,
            });
        match found {
            Some((x, y, parent)) => { ax += x; ay += y; cur = parent; }
            None => break,
        }
    }
    (ax, ay)
}

fn op_translate_coordinates(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 16 { return; }
    let src_win = r32(data, 4);
    let dst_win = r32(data, 8);
    let src_x   = r16(data, 12) as i16 as i32;
    let src_y   = r16(data, 14) as i16 as i32;
    with_client(fd, |c| {
        let valid = |w: u32| w == proto::ROOT_WINDOW_ID || c.resources.has(w);
        if !valid(src_win) {
            c.send_error(proto::ERR_WINDOW, src_win, proto::OP_TRANSLATE_COORDINATES);
            return;
        }
        if !valid(dst_win) {
            c.send_error(proto::ERR_WINDOW, dst_win, proto::OP_TRANSLATE_COORDINATES);
            return;
        }
        let (sox, soy) = window_abs_origin(c, src_win);
        let (dox, doy) = window_abs_origin(c, dst_win);
        let dst_x = (sox + src_x) - dox;
        let dst_y = (soy + src_y) - doy;
        let mut b = [0u8; 32];
        b[0] = 1; b[1] = 1; // same_screen = True (single-screen server)
        w16(&mut b, 2, seq);
        // child = 0 (None) at bytes 8-11; dst-x INT16 at byte 12, dst-y INT16 at
        // byte 14 (X11 core protocol TranslateCoordinates reply encoding).
        w16(&mut b, 12, dst_x as i16 as u16);
        w16(&mut b, 14, dst_y as i16 as u16);
        c.send(&b);
    });
}

// ── GrabPointer/GrabKeyboard reply ─────────────────────────────────────────

fn op_grab_reply(fd: u64, seq: u16) {
    let mut b = [0u8;32]; b[0]=1; w16(&mut b,2,seq);
    with_client(fd, |c| c.send(&b));
}

// ── SetInputFocus (42) ──────────────────────────────────────────────────────
//
// Per X11 protocol §SetInputFocus: updates the input focus window.
// We deliver FocusOut (10) to the previously focused window and FocusIn (9)
// to the newly focused one, for every client that selected FocusChangeMask
// (0x0020_0000) on the respective window.  This satisfies the ICCCM focus
// model used by xterm, xclock, and toolkit input managers.

fn op_set_input_focus(fd: u64, data: &[u8]) {
    // data[1]  = revert-to (0=None, 1=PointerRoot, 2=Parent)
    // data[4..8] = focus window XID
    // data[8..12] = timestamp (CurrentTime = 0)
    // TODO(revert-to): ignored; falls back to root on window destroy.
    //   See X11 protocol §SetInputFocus.
    if data.len() < 8 { return; }
    let new_focus = r32(data, 4);

    // Focus is a server-global resource.  Read and update atomically so that
    // the old value and the write are consistent even with multiple clients.
    let old_focus = {
        let mut srv = SERVER.lock();
        let prev = srv.focus_window;
        srv.focus_window = new_focus;
        prev
    };

    if old_focus == new_focus { return; }

    // Deliver FocusOut to the old focus window's owner(s).
    deliver_focus_event(old_focus, false);
    // Deliver FocusIn to the new focus window's owner(s).
    deliver_focus_event(new_focus, true);
}

/// Send a FocusIn or FocusOut event to all clients that own `window` and
/// have selected FocusChangeMask on it.
fn deliver_focus_event(window: u32, focus_in: bool) {
    let tick = crate::arch::x86_64::irq::get_ticks() as u32;
    let _ = tick; // timestamp not used in focus event wire format

    let mut srv = SERVER.lock();
    for slot in srv.clients.iter_mut() {
        if let Some(c) = slot {
            let has_mask = c.resources.entries.iter()
                .filter_map(|s| s.as_ref())
                .find(|r| r.id == window)
                .map(|r| match &r.body {
                    resource::ResourceBody::Window(w) =>
                        w.event_mask & proto::EVENT_MASK_FOCUS_CHANGE != 0,
                    _ => false,
                })
                .unwrap_or(false);
            if has_mask {
                // Per X11 protocol §11.1, events carry the last-request seq.
                let ev = if focus_in {
                    event::encode_focus_in(c.seq, window)
                } else {
                    event::encode_focus_out(c.seq, window)
                };
                unix::write(c.fd, &ev);
            }
        }
    }
}

// ── GetInputFocus (43) ──────────────────────────────────────────────────────

fn op_get_input_focus(fd: u64, seq: u16) {
    let focus = SERVER.lock().focus_window;
    let mut b = [0u8;32]; b[0]=1; b[1]=1; w16(&mut b,2,seq); w32(&mut b,8,focus);
    with_client(fd, |c| c.send(&b));
}

// ── QueryKeymap (44) ────────────────────────────────────────────────────────

fn op_query_keymap(fd: u64, seq: u16) {
    let mut b = vec![0u8; 40]; b[0]=1; w16(&mut b,2,seq); w32(&mut b,4,2);
    with_client(fd, |c| c.send(&b));
}

// ── OpenFont (45) ────────────────────────────────────────────────────────────

fn op_open_font(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let fid = r32(data, 4);
    with_client(fd, |c| { c.resources.insert(fid, ResourceBody::Gc(GcData { font: FONT_ID_FIXED, ..GcData::default() })); });
}

// ── QueryFont (47) ────────────────────────────────────────────────────────────
//   Returns minimal 8x16 fixed font metrics.

fn op_query_font(fd: u64, seq: u16) {
    // reply-length field = (60-8)/4 = 13 words?  Actually the fixed part is:
    // 32-byte header + 28 bytes body = 60 total.
    // reply-length = (60-32)/4 = 7 (extra words beyond the 32-byte minimum).
    let mut b = [0u8; 60];
    b[0]=1; w16(&mut b,2,seq); w32(&mut b,4,7);
    // min-bounds charinfo at offset 8 (12 bytes)
    w16(&mut b,8,0); w16(&mut b,10,8); w16(&mut b,12,8); w16(&mut b,14,12); w16(&mut b,16,4);
    // max-bounds charinfo at offset 24
    w16(&mut b,24,0); w16(&mut b,26,8); w16(&mut b,28,8); w16(&mut b,30,12); w16(&mut b,32,4);
    w16(&mut b,40,32); w16(&mut b,42,127); // min/max char
    w16(&mut b,44,32);   // default char
    w16(&mut b,52,12);   // font-ascent
    w16(&mut b,54,4);    // font-descent
    with_client(fd, |c| c.send(&b));
}

// ── ListFonts (49) ────────────────────────────────────────────────────────────

fn op_list_fonts(fd: u64, seq: u16) {
    let nm = b"fixed"; let sl = 1+nm.len(); let pd = proto::pad4(sl);
    let tot = 32+pd; let mut rep = vec![0u8; tot];
    rep[0]=1; w16(&mut rep,2,seq); w32(&mut rep,4,(pd/4) as u32); w16(&mut rep,8,1);
    rep[32] = nm.len() as u8;
    rep[33..33+nm.len()].copy_from_slice(nm);
    with_client(fd, |c| c.send(&rep));
}

// ── CreatePixmap (53) ────────────────────────────────────────────────────────

fn op_create_pixmap(fd: u64, data: &[u8]) {
    if data.len() < 16 { return; }
    let depth = data[1]; let pid = r32(data, 4);
    let w_ = r16(data, 12).max(1); let h_ = r16(data, 14).max(1);
    with_client(fd, |c| { c.resources.insert(pid, ResourceBody::Pixmap(PixmapData::new(w_, h_, depth))); });
}

// ── FreePixmap (54) ──────────────────────────────────────────────────────────

fn op_free_pixmap(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    let pid = r32(data, 4);
    with_client(fd, |c| { c.resources.remove(pid); });
}

// ── CreateGC (55) ────────────────────────────────────────────────────────────

fn op_create_gc(fd: u64, data: &[u8]) {
    if data.len() < 16 { return; }
    let gcid = r32(data, 4); let mask = r32(data, 12);
    let mut gc = GcData::default();
    if data.len() > 16 { gc.apply_value_list(mask, &data[16..]); }
    with_client(fd, |c| { c.resources.insert(gcid, ResourceBody::Gc(gc)); });
}

// ── ChangeGC (56) ────────────────────────────────────────────────────────────

fn op_change_gc(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let gcid = r32(data, 4); let mask = r32(data, 8);
    with_client(fd, |c| {
        if let Some(gc) = c.resources.get_gc_mut(gcid) {
            if data.len() > 12 { gc.apply_value_list(mask, &data[12..]); }
        }
    });
}

// ── CopyGC (57) ──────────────────────────────────────────────────────────────

fn op_copy_gc(fd: u64, data: &[u8]) {
    if data.len() < 16 { return; }
    let src = r32(data, 4); let dst = r32(data, 8); let mask = r32(data, 12);
    with_client(fd, |c| {
        let sg = c.resources.get_gc_mut(src).map(|g| g.clone());
        if let (Some(s), Some(d)) = (sg, c.resources.get_gc_mut(dst)) {
            if mask & proto::GC_FUNCTION   != 0 { d.function   = s.function;   }
            if mask & proto::GC_FOREGROUND != 0 { d.foreground = s.foreground; }
            if mask & proto::GC_BACKGROUND != 0 { d.background = s.background; }
            if mask & proto::GC_LINE_WIDTH != 0 { d.line_width = s.line_width; }
            if mask & proto::GC_FONT       != 0 { d.font       = s.font;       }
        }
    });
}

// ── FreeGC (60) ──────────────────────────────────────────────────────────────

fn op_free_gc(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    with_client(fd, |c| { c.resources.remove(r32(data, 4)); });
}

// ── ClearArea (61) ────────────────────────────────────────────────────────────

fn op_clear_area(fd: u64, data: &[u8]) {
    if data.len() < 16 { return; }
    let draw = r32(data, 4);
    let x = r16(data, 8) as i32; let y = r16(data, 10) as i32;
    let w = r16(data, 12) as i32; let h = r16(data, 14) as i32;
    // Check if target is a pixmap — zero its region; for windows clear to background
    let is_pixmap = SERVER.lock().clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
        .map_or(false, |c| matches!(c.resources.entries.iter()
            .filter_map(|s| s.as_ref()).find(|r| r.id == draw),
            Some(r) if matches!(r.body, ResourceBody::Pixmap(_))));
    if is_pixmap {
        with_client(fd, |c| {
            if let Some(pix) = c.resources.get_pixmap_mut(draw) {
                let pw = if w == 0 { pix.width as i32 } else { w };
                let ph = if h == 0 { pix.height as i32 } else { h };
                pix.fill_rect(x, y, pw, ph, 0xFF000000); // clear to opaque black
            }
        });
    } else {
        // ClearArea on a window resets the region to the window's background,
        // honouring `background-pixmap` (tiled) or `background-pixel` (solid).
        // w/h == 0 means "to the right/bottom edge of the window" per the X core
        // protocol; paint_window_background applies that and clamps to bounds.
        // `full_window=false`: ClearArea is an explicit client-requested erase
        // and always paints the requested region (it is not the idempotent
        // viewable-time background paint).
        paint_window_background(fd, draw, x, y, w, h, false);
    }
}

// ── CopyArea (62) ────────────────────────────────────────────────────────────
//
// Copies a rectangle from src-drawable to dst-drawable.
// Supported cases:
//   pixmap → window : blit pixmap pixels to screen
//   pixmap → pixmap : pixel-copy between buffers
//   window → *      : not supported (no screen readback)

fn op_copy_area(fd: u64, data: &[u8]) {
    if data.len() < 28 { return; }
    let src_id  = r32(data, 4);
    let dst_id  = r32(data, 8);
    // gc at [12] — ignored for simple copy
    let src_x   = r16(data, 16) as i32;
    let src_y   = r16(data, 18) as i32;
    let dst_x   = r16(data, 20) as i32;
    let dst_y   = r16(data, 22) as i32;
    let width   = r16(data, 24) as i32;
    let height  = r16(data, 26) as i32;
    if width <= 0 || height <= 0 { return; }

    // Determine src and dst drawable types
    let (src_is_pixmap, dst_is_pixmap) = {
        let srv = SERVER.lock();
        let c = srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd);
        match c {
            None => return,
            Some(c) => {
                let src_pix = c.resources.entries.iter().filter_map(|s| s.as_ref())
                    .find(|r| r.id == src_id)
                    .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_)));
                let dst_pix = c.resources.entries.iter().filter_map(|s| s.as_ref())
                    .find(|r| r.id == dst_id)
                    .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_)));
                (src_pix, dst_pix)
            }
        }
    };

    match (src_is_pixmap, dst_is_pixmap) {
        (true, true) => {
            // pixmap → pixmap: copy pixels directly
            // We need to clone the src pixels to avoid borrow conflict
            let src_pixels: alloc::vec::Vec<u8> = {
                let srv = SERVER.lock();
                let c = srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd);
                match c.and_then(|c| c.resources.get_pixmap(src_id)) {
                    Some(p) => {
                        // Extract the relevant sub-rectangle
                        let sw = p.width as i32;
                        let sh = p.height as i32;
                        let x0 = src_x.max(0); let y0 = src_y.max(0);
                        let x1 = (src_x + width).min(sw);
                        let y1 = (src_y + height).min(sh);
                        let rw = (x1 - x0).max(0) as usize;
                        let rh = (y1 - y0).max(0) as usize;
                        let mut buf = alloc::vec![0u8; rw * rh * 4];
                        for row in 0..rh {
                            for col in 0..rw {
                                let so = (((y0 + row as i32) * sw + x0 + col as i32) * 4) as usize;
                                let bo = (row * rw + col) * 4;
                                // SHM-backed sources have an empty owned `Vec`;
                                // pixmap→pixmap from a live segment is not a path
                                // FF uses, so leave those pixels zero rather than
                                // index out of bounds.
                                if so + 4 > p.pixels.len() { continue; }
                                buf[bo..bo+4].copy_from_slice(&p.pixels[so..so+4]);
                            }
                        }
                        buf
                    }
                    None => return,
                }
            };
            let rw = width as u32;
            let rh = height as u32;
            with_client(fd, |c| {
                if let Some(dst) = c.resources.get_pixmap_mut(dst_id) {
                    let dw = dst.width as i32;
                    let dh = dst.height as i32;
                    let stride = rw as i32;
                    for row in 0..rh as i32 {
                        let dy = dst_y + row;
                        if dy < 0 || dy >= dh { continue; }
                        for col in 0..rw as i32 {
                            let dx = dst_x + col;
                            if dx < 0 || dx >= dw { continue; }
                            let so = ((row * stride + col) * 4) as usize;
                            let do_ = ((dy * dw + dx) * 4) as usize;
                            dst.pixels[do_..do_+4].copy_from_slice(&src_pixels[so..so+4]);
                        }
                    }
                }
            });
        }
        (true, false) => {
            // pixmap → window: copy into the window's persistent pixel buffer
            // (the compositor source of truth), NOT the transient screen
            // backbuffer.  Build a tightly packed BGRA buffer of the clipped
            // source rectangle and record the clip offset so the copy lands at
            // the correct window-local position.  Two source backings are
            // supported: a server-owned pixel `Vec`, and an MIT-SHM-backed
            // pixmap whose pixels live in an attached SysV-SHM segment (read
            // LIVE here, so the frame the client just drew is the one copied).
            let extracted = {
                let srv = SERVER.lock();
                let c = srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd);
                match c.and_then(|c| c.resources.get_pixmap(src_id)) {
                    Some(p) => {
                        let sw = p.width as i32;
                        let sh = p.height as i32;
                        let x0 = src_x.max(0); let y0 = src_y.max(0);
                        let x1 = (src_x + width).min(sw);
                        let y1 = (src_y + height).min(sh);
                        let rw = (x1 - x0).max(0) as usize;
                        let rh = (y1 - y0).max(0) as usize;
                        let mut buf = alloc::vec![0u8; rw * rh * 4];
                        let ok = if p.is_shm_backed() {
                            // Resolve the segment's kernel-readable physical base
                            // and copy the clipped rectangle from it.  Row stride
                            // is the SHM image stride (scanline-padded), not sw*4.
                            match crate::ipc::sysv_shm::segment_phys(p.shm_shmid) {
                                Some((phys_base, seg_size)) => {
                                    let stride = p.shm_stride as usize;
                                    let base = phys_base as usize + p.shm_offset as usize;
                                    // Last byte the loop touches must lie inside the
                                    // segment (guards against a truncated/detached
                                    // segment between CreatePixmap and CopyArea).
                                    let last = (y0 + rh as i32 - 1).max(0) as usize * stride
                                        + (x0 + rw as i32 - 1).max(0) as usize * 4 + 4;
                                    if rw == 0 || rh == 0
                                        || (p.shm_offset as u64 + last as u64) > seg_size {
                                        false
                                    } else {
                                        // SAFETY: `phys_base` is the identity-mapped,
                                        // kernel-readable base of a physically
                                        // contiguous SysV segment (see
                                        // sysv_shm::shmget); the bound check above
                                        // keeps every read inside the segment.
                                        for row in 0..rh {
                                            for col in 0..rw {
                                                let so = base
                                                    + (y0 + row as i32) as usize * stride
                                                    + (x0 + col as i32) as usize * 4;
                                                let bo = (row * rw + col) * 4;
                                                let px = unsafe {
                                                    core::slice::from_raw_parts(so as *const u8, 4)
                                                };
                                                buf[bo..bo+4].copy_from_slice(px);
                                            }
                                        }
                                        true
                                    }
                                }
                                None => false,
                            }
                        } else {
                            // Server-owned pixmap: source stride is sw*4.
                            if rw == 0 || rh == 0 { false } else {
                                for row in 0..rh {
                                    for col in 0..rw {
                                        let so = (((y0 + row as i32) * sw + x0 + col as i32) * 4) as usize;
                                        let bo = (row * rw + col) * 4;
                                        if so + 4 > p.pixels.len() { continue; }
                                        buf[bo..bo+4].copy_from_slice(&p.pixels[so..so+4]);
                                    }
                                }
                                true
                            }
                        };
                        // Window-local destination shifts by the amount the
                        // source origin was clipped (x0 - src_x, y0 - src_y).
                        if ok { Some((buf, rw as i32, rh as i32, x0 - src_x, y0 - src_y)) }
                        else { None }
                    }
                    None => None,
                }
            };
            let (pixels, rw, rh, off_x, off_y) = match extracted {
                Some(v) => v,
                None => return,
            };
            // CopyArea is a plain copy (RENDER_OP_SRC) of opaque pixels.
            window_composite_pixels(
                fd, dst_id,
                dst_x + off_x, dst_y + off_y, rw, rh,
                &pixels, rw, rh, proto::RENDER_OP_SRC);
        }
        _ => {} // window→* not supported
    }
}

// ── PolyFillRectangle (70) ───────────────────────────────────────────────────

fn op_poly_fill_rect(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let draw = r32(data, 4); let gcid = r32(data, 8);

    let (fg, is_pixmap) = {
        let srv = SERVER.lock();
        let c = srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd);
        match c {
            None => return,
            Some(c) => {
                let fg = c.resources.entries.iter().filter_map(|s| s.as_ref())
                    .find(|r| r.id == gcid)
                    .and_then(|r| if let ResourceBody::Gc(ref g) = r.body { Some(g.foreground) } else { None })
                    .unwrap_or(0);
                let is_pix = c.resources.entries.iter().filter_map(|s| s.as_ref())
                    .find(|r| r.id == draw)
                    .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_)));
                (fg, is_pix)
            }
        }
    };

    if is_pixmap {
        // Draw rectangles into the pixmap's pixel buffer
        let color = 0xFF000000 | (fg & 0x00FFFFFF); // set full alpha
        let mut i = 12usize;
        while i + 8 <= data.len() {
            let rx = r16(data, i) as i32; let ry = r16(data, i+2) as i32;
            let rw = r16(data, i+4) as i32; let rh = r16(data, i+6) as i32;
            i += 8;
            with_client(fd, |c| {
                if let Some(pix) = c.resources.get_pixmap_mut(draw) {
                    pix.fill_rect(rx, ry, rw, rh, color);
                }
            });
        }
    } else {
        // Draw into the window's pixel buffer for compositor + direct to screen
        let color_bgra = {
            let r = ((fg >> 16) & 0xFF) as u8;
            let g = ((fg >> 8) & 0xFF) as u8;
            let b = (fg & 0xFF) as u8;
            [b, g, r, 0xFF]
        };
        let mut i = 12usize;
        while i + 8 <= data.len() {
            let rx = r16(data, i) as i32; let ry = r16(data, i+2) as i32;
            let rw = r16(data, i+4) as i32; let rh = r16(data, i+6) as i32;
            i += 8;
            // Write to the window's pixel buffer
            with_client(fd, |c| {
                if let Some(w) = c.resources.get_window_mut(draw) {
                    w.ensure_pixels();
                    let ww = w.width as i32;
                    let wh = w.height as i32;
                    for py in ry.max(0)..((ry + rh).min(wh)) {
                        for px in rx.max(0)..((rx + rw).min(ww)) {
                            let off = ((py * ww + px) * 4) as usize;
                            if off + 3 < w.pixels.len() {
                                w.pixels[off..off+4].copy_from_slice(&color_bgra);
                            }
                        }
                    }
                }
            });
        }
    }
}

// ── Geometry ops (PolyPoint/Line/Segment/Rectangle/Arc/FillArc) ───────────────
//
// All share the same request prologue: [4-7] drawable, [8-11] gc, then a list
// of op-specific coordinate records.  Each rasterises into the drawable's
// pixel buffer (window or pixmap) via the `resource::raster` software
// rasteriser, using the GC's foreground colour.  The compositor re-blits every
// window's `pixels` each frame, so no explicit dirty flag is needed.

/// Resolve the GC foreground (as 0x00RRGGBB) and whether `draw` is a pixmap.
fn gc_fg_and_target(fd: u64, draw: u32, gcid: u32) -> Option<(u32, bool)> {
    let srv = SERVER.lock();
    let c = srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)?;
    let fg = c.resources.entries.iter().filter_map(|s| s.as_ref())
        .find(|r| r.id == gcid)
        .and_then(|r| if let ResourceBody::Gc(ref g) = r.body { Some(g.foreground) } else { None })
        .unwrap_or(0);
    let is_pix = c.resources.entries.iter().filter_map(|s| s.as_ref())
        .find(|r| r.id == draw)
        .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_)));
    Some((fg & 0x00FF_FFFF, is_pix))
}

/// Run `f(pixels, width, height)` against the pixel buffer of drawable `draw`,
/// allocating the window buffer if needed.  `f` is the rasteriser body.
fn with_drawable_pixels<F: FnMut(&mut [u8], i32, i32)>(fd: u64, draw: u32, is_pix: bool, mut f: F) {
    with_client(fd, |c| {
        if is_pix {
            if let Some(p) = c.resources.get_pixmap_mut(draw) {
                let (w, h) = (p.width as i32, p.height as i32);
                f(&mut p.pixels, w, h);
            }
        } else if let Some(w) = c.resources.get_window_mut(draw) {
            w.ensure_pixels();
            let (ww, wh) = (w.width as i32, w.height as i32);
            f(&mut w.pixels, ww, wh);
        }
    });
}

// PolyFillArc (71): list of ARC {x:i16,y:i16,w:u16,h:u16,a1:i16,a2:i16} (12 B).
fn op_poly_fill_arc(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let draw = r32(data, 4); let gcid = r32(data, 8);
    let (fg, is_pix) = match gc_fg_and_target(fd, draw, gcid) { Some(v) => v, None => return };
    #[cfg(feature = "xeyes-test")]
    crate::serial_println!("[X11DRAW] PolyFillArc draw={:#x} is_pixmap={} fg={:#x} narcs={}",
        draw, is_pix, fg, (data.len().saturating_sub(12)) / 12);
    let mut i = 12usize;
    while i + 12 <= data.len() {
        let ax = r16(data, i) as i16 as i32;
        let ay = r16(data, i + 2) as i16 as i32;
        let aw = r16(data, i + 4) as i32;
        let ah = r16(data, i + 6) as i32;
        let a1 = r16(data, i + 8) as i16 as i32;
        let a2 = r16(data, i + 10) as i16 as i32;
        i += 12;
        with_drawable_pixels(fd, draw, is_pix, |px, w, h| {
            resource::raster::fill_arc(px, w, h, ax, ay, aw, ah, a1, a2, fg);
        });
    }
}

// PolyArc (68): same ARC record list, outline stroke.
fn op_poly_arc(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let draw = r32(data, 4); let gcid = r32(data, 8);
    let (fg, is_pix) = match gc_fg_and_target(fd, draw, gcid) { Some(v) => v, None => return };
    let mut i = 12usize;
    while i + 12 <= data.len() {
        let ax = r16(data, i) as i16 as i32;
        let ay = r16(data, i + 2) as i16 as i32;
        let aw = r16(data, i + 4) as i32;
        let ah = r16(data, i + 6) as i32;
        let a1 = r16(data, i + 8) as i16 as i32;
        let a2 = r16(data, i + 10) as i16 as i32;
        i += 12;
        with_drawable_pixels(fd, draw, is_pix, |px, w, h| {
            resource::raster::stroke_arc(px, w, h, ax, ay, aw, ah, a1, a2, fg);
        });
    }
}

// PolySegment (70): list of SEGMENT {x1:i16,y1:i16,x2:i16,y2:i16} (8 B).
fn op_poly_segment(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let draw = r32(data, 4); let gcid = r32(data, 8);
    let (fg, is_pix) = match gc_fg_and_target(fd, draw, gcid) { Some(v) => v, None => return };
    let mut i = 12usize;
    while i + 8 <= data.len() {
        let x1 = r16(data, i) as i16 as i32;
        let y1 = r16(data, i + 2) as i16 as i32;
        let x2 = r16(data, i + 4) as i16 as i32;
        let y2 = r16(data, i + 6) as i16 as i32;
        i += 8;
        with_drawable_pixels(fd, draw, is_pix, |px, w, h| {
            resource::raster::line(px, w, h, x1, y1, x2, y2, fg);
        });
    }
}

// PolyLine (65): polyline of POINT {x:i16,y:i16} (4 B); coordinate-mode in
// data[1] (0=Origin, 1=Previous).  Connected segments between consecutive pts.
fn op_poly_line(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let relative = data[1] == 1;
    let draw = r32(data, 4); let gcid = r32(data, 8);
    let (fg, is_pix) = match gc_fg_and_target(fd, draw, gcid) { Some(v) => v, None => return };
    let mut pts: alloc::vec::Vec<(i32, i32)> = alloc::vec::Vec::new();
    let mut i = 12usize;
    let (mut cx, mut cy) = (0i32, 0i32);
    let mut first = true;
    while i + 4 <= data.len() {
        let px = r16(data, i) as i16 as i32;
        let py = r16(data, i + 2) as i16 as i32;
        i += 4;
        if relative && !first { cx += px; cy += py; } else { cx = px; cy = py; }
        first = false;
        pts.push((cx, cy));
    }
    with_drawable_pixels(fd, draw, is_pix, |buf, w, h| {
        for win in pts.windows(2) {
            resource::raster::line(buf, w, h, win[0].0, win[0].1, win[1].0, win[1].1, fg);
        }
    });
}

// PolyPoint (64): list of POINT {x:i16,y:i16} (4 B).
fn op_poly_point(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let relative = data[1] == 1;
    let draw = r32(data, 4); let gcid = r32(data, 8);
    let (fg, is_pix) = match gc_fg_and_target(fd, draw, gcid) { Some(v) => v, None => return };
    let mut i = 12usize;
    let (mut cx, mut cy) = (0i32, 0i32);
    let mut first = true;
    while i + 4 <= data.len() {
        let px = r16(data, i) as i16 as i32;
        let py = r16(data, i + 2) as i16 as i32;
        i += 4;
        if relative && !first { cx += px; cy += py; } else { cx = px; cy = py; }
        first = false;
        let (dx, dy) = (cx, cy);
        with_drawable_pixels(fd, draw, is_pix, |buf, w, h| {
            resource::raster::plot(buf, w, h, dx, dy, fg);
        });
    }
}

// PolyRectangle (67): list of RECTANGLE {x:i16,y:i16,w:u16,h:u16} (8 B) — outline.
fn op_poly_rectangle(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let draw = r32(data, 4); let gcid = r32(data, 8);
    let (fg, is_pix) = match gc_fg_and_target(fd, draw, gcid) { Some(v) => v, None => return };
    let mut i = 12usize;
    while i + 8 <= data.len() {
        let rx = r16(data, i) as i16 as i32;
        let ry = r16(data, i + 2) as i16 as i32;
        let rw = r16(data, i + 4) as i32;
        let rh = r16(data, i + 6) as i32;
        i += 8;
        with_drawable_pixels(fd, draw, is_pix, |buf, w, h| {
            resource::raster::line(buf, w, h, rx, ry, rx + rw, ry, fg);
            resource::raster::line(buf, w, h, rx, ry + rh, rx + rw, ry + rh, fg);
            resource::raster::line(buf, w, h, rx, ry, rx, ry + rh, fg);
            resource::raster::line(buf, w, h, rx + rw, ry, rx + rw, ry + rh, fg);
        });
    }
}

// ── PutImage (72) ────────────────────────────────────────────────────────────

fn op_put_image(fd: u64, data: &[u8]) {
    if data.len() < 24 { return; }
    let fmt    = data[1]; let draw = r32(data, 4);
    let width  = r16(data, 12) as u32; let height = r16(data, 14) as u32;
    let dx     = r16(data, 16) as i32; let dy = r16(data, 18) as i32;
    let depth  = data[21];
    if fmt != proto::IMAGE_FORMAT_ZPIXMAP || depth < 24 { return; }
    let px_len = (width * height * 4) as usize;
    if data.len() < 24 + px_len { return; }

    // Determine if target is a pixmap or a window
    let is_pixmap = {
        let srv = SERVER.lock();
        srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
            .map_or(false, |c| c.resources.entries.iter().filter_map(|s| s.as_ref())
                .find(|r| r.id == draw)
                .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_))))
    };

    if is_pixmap {
        let pixels = &data[24..24+px_len];
        with_client(fd, |c| {
            if let Some(pix) = c.resources.get_pixmap_mut(draw) {
                let pw = pix.width as i32;
                let ph = pix.height as i32;
                for row in 0..height as i32 {
                    let py = dy + row;
                    if py < 0 || py >= ph { continue; }
                    for col in 0..width as i32 {
                        let px = dx + col;
                        if px < 0 || px >= pw { continue; }
                        let so = ((row * width as i32 + col) * 4) as usize;
                        let do_ = ((py * pw + px) * 4) as usize;
                        pix.pixels[do_..do_+4].copy_from_slice(&pixels[so..so+4]);
                    }
                }
            }
        });
    } else {
        // PutImage into a window writes the window's persistent pixel buffer
        // (compositor source of truth), not the transient screen backbuffer.
        // ZPixmap data is a packed width×height BGRA image; a plain copy.
        window_composite_pixels(
            fd, draw, dx, dy, width as i32, height as i32,
            &data[24..24 + px_len], width as i32, height as i32,
            proto::RENDER_OP_SRC);
    }
}

// ── ImageText8 (76) ──────────────────────────────────────────────────────────

fn op_image_text8(fd: u64, data: &[u8]) {
    if data.len() < 16 { return; }
    let nc = data[1] as usize; let draw = r32(data, 4); let gcid = r32(data, 8);
    let tx = r16(data, 12) as i32; let ty = r16(data, 14) as i32;
    if data.len() < 16+nc { return; }
    let text = core::str::from_utf8(&data[16..16+nc]).unwrap_or("");
    let (fg,bg) = SERVER.lock().clients.iter_mut().filter_map(|s| s.as_mut()).find(|c| c.fd == fd)
        .and_then(|c| c.resources.get_gc_mut(gcid).map(|g| (g.foreground,g.background)))
        .unwrap_or((0,0xFFFFFF));
    // ImageText8 into a window writes the window's persistent pixel buffer
    // (compositor source of truth), not the transient screen backbuffer.
    // Coordinates are window-local; w.pixels is the window-local surface.
    window_draw_text_pixels(fd, draw, tx, ty, text, fg & 0xFFFFFF, bg & 0xFFFFFF);
}

/// Return the (x,y) screen-space origin of a window resource, or (0,0).
/// Retained for window→screen coordinate mapping; window-destination draw ops
/// now render into the window-local `w.pixels` surface and no longer need it.
#[allow(dead_code)]
fn window_origin(fd: u64, draw: u32) -> (i32, i32) {
    SERVER.lock().clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
        .and_then(|c| {
            for sl in c.resources.entries.iter() {
                if let Some(r) = sl {
                    if r.id == draw {
                        if let ResourceBody::Window(ref w) = r.body {
                            return Some((w.x as i32, w.y as i32));
                        }
                    }
                }
            }
            None
        })
        .unwrap_or((0, 0))
}

// ── AllocColor (84) ──────────────────────────────────────────────────────────

fn op_alloc_color(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 16 { return; }
    let r_ = (r16(data,8)  >> 8) as u32;
    let g_ = (r16(data,10) >> 8) as u32;
    let b_ = (r16(data,12) >> 8) as u32;
    let px = (r_ << 16) | (g_ << 8) | b_;
    let mut b = [0u8;32]; b[0]=1; w16(&mut b,2,seq);
    w16(&mut b,8,(r_ as u16)<<8); w16(&mut b,10,(g_ as u16)<<8); w16(&mut b,12,(b_ as u16)<<8);
    w32(&mut b,16,px);
    with_client(fd, |c| c.send(&b));
}

// ── QueryColors (91) ─────────────────────────────────────────────────────────

fn op_query_colors(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let n = (data.len()-8)/4; let bd = n*8; let pd = proto::pad4(bd);
    let mut rep = vec![0u8; 32+pd];
    rep[0]=1; w16(&mut rep,2,seq); w32(&mut rep,4,(pd/4) as u32); w16(&mut rep,8,n as u16);
    for i in 0..n {
        let px = r32(data, 8+i*4);
        let r_ = ((px>>16)&0xFF) as u16; let g_ = ((px>>8)&0xFF) as u16; let b_ = (px&0xFF) as u16;
        let base = 32+i*8;
        w16(&mut rep,base,r_<<8); w16(&mut rep,base+2,g_<<8); w16(&mut rep,base+4,b_<<8);
    }
    with_client(fd, |c| c.send(&rep));
}

// ── QueryExtension (98) ──────────────────────────────────────────────────────

fn op_query_extension(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let nlen = r16(data, 4) as usize;
    let name = if data.len() >= 8+nlen { core::str::from_utf8(&data[8..8+nlen]).unwrap_or("") } else { "" };
    let mut b = [0u8;32]; b[0]=1; w16(&mut b,2,seq);
    // Per X11 core protocol §QueryExtension, the reply carries
    // [8]=present, [9]=major_opcode, [10]=first_event, [11]=first_error.
    // first_event/first_error MUST be the extension's real base codes (or 0 when
    // the extension defines no events/errors); see proto.rs for the rationale —
    // clients key their event-dispatch maps on first_event.
    match name {
        // MIT-SHM is advertised: `op_shm` implements a real ShmPutImage that
        // reads pixels from the attached SysV segment's physical backing and
        // composites them into the destination window (the same path as the core
        // XPutImage).  Per the MIT-SHM protocol spec a client that sees present=1
        // routes large framebuffer presents through ShmPutImage, avoiding the
        // per-frame request-body copy that XPutImage incurs.
        "MIT-SHM"   => { b[8]=1; b[9]=proto::SHM_MAJOR_OPCODE;     b[10]=proto::SHM_FIRST_EVENT;   b[11]=proto::SHM_FIRST_ERROR; }
        // GLX: we perform the GLX handshake only (QueryVersion, Get{Visual,FB}Configs,
        // Create/Destroy/MakeCurrent context bookkeeping, IsDirect=true, the
        // Query*String requests).  With the Mesa software path the OpenGL
        // rendering runs client-side (direct), so the server sees no GL stream.
        "GLX"       => { b[8]=1; b[9]=proto::GLX_MAJOR_OPCODE;     b[10]=proto::GLX_FIRST_EVENT;   b[11]=proto::GLX_FIRST_ERROR; }
        "BIG-REQUESTS"   => { b[8]=1; b[9]=proto::BIGREQ_MAJOR_OPCODE;    b[10]=0;                            b[11]=0; }
        "XKEYBOARD"      => { b[8]=1; b[9]=proto::XKEYBOARD_MAJOR_OPCODE; b[10]=proto::XKEYBOARD_FIRST_EVENT; b[11]=proto::XKEYBOARD_FIRST_ERROR; }
        "SHAPE"     => { b[8]=1; b[9]=proto::SHAPE_MAJOR_OPCODE;   b[10]=proto::SHAPE_FIRST_EVENT;  b[11]=proto::SHAPE_FIRST_ERROR; }
        "RENDER"    => { b[8]=1; b[9]=proto::RENDER_MAJOR_OPCODE;  b[10]=proto::RENDER_FIRST_EVENT; b[11]=proto::RENDER_FIRST_ERROR; }
        "XFIXES"    => { b[8]=1; b[9]=proto::XFIXES_MAJOR_OPCODE;  b[10]=proto::XFIXES_FIRST_EVENT; b[11]=proto::XFIXES_FIRST_ERROR; }
        "DAMAGE"    => { b[8]=1; b[9]=proto::DAMAGE_MAJOR_OPCODE;  b[10]=proto::DAMAGE_FIRST_EVENT; b[11]=proto::DAMAGE_FIRST_ERROR; }
        "XTEST"     => { b[8]=1; b[9]=proto::XTEST_MAJOR_OPCODE;   b[10]=0;                         b[11]=0; }
        "XInputExtension" | "XI" | "XInput" => {
            b[8]=1; b[9]=proto::XINPUT_MAJOR_OPCODE; b[10]=proto::XINPUT_FIRST_EVENT; b[11]=proto::XINPUT_FIRST_ERROR;
        }
        "DPMS"      => { b[8]=1; b[9]=proto::DPMS_MAJOR_OPCODE;    b[10]=0;                       b[11]=0; }
        "SYNC"      => { b[8]=1; b[9]=proto::SYNC_MAJOR_OPCODE;    b[10]=proto::SYNC_FIRST_EVENT; b[11]=proto::SYNC_FIRST_ERROR; }
        "COMPOSITE" => { b[8]=1; b[9]=proto::COMPOSITE_MAJOR_OPCODE; b[10]=0;                     b[11]=0; }
        "RANDR" | "RandR" => { b[8]=1; b[9]=proto::RANDR_MAJOR_OPCODE; b[10]=proto::RANDR_FIRST_EVENT; b[11]=proto::RANDR_FIRST_ERROR; }
        _           => {} // not present
    }
    with_client(fd, |c| c.send(&b));
}

// ── ListExtensions (99) ──────────────────────────────────────────────────────

fn op_list_extensions(fd: u64, seq: u16) {
    // Keep this list in sync with `op_query_extension`.  MIT-SHM and GLX are now
    // advertised (real ShmPutImage + GLX handshake respectively).
    let names: &[&[u8]] = &[
        b"BIG-REQUESTS", b"XKEYBOARD", b"SHAPE", b"RENDER",
        b"XFIXES", b"DAMAGE", b"XTEST", b"XInputExtension",
        b"DPMS", b"SYNC", b"COMPOSITE", b"RANDR",
        b"MIT-SHM", b"GLX",
    ];
    let mut body: Vec<u8> = vec![];
    for &n in names { body.push(n.len() as u8); body.extend_from_slice(n); }
    let pd = proto::pad4(body.len()); while body.len() < pd { body.push(0); }
    let mut rep = vec![0u8; 32+pd];
    rep[0]=1; rep[1] = names.len() as u8; w16(&mut rep,2,seq); w32(&mut rep,4,(pd/4) as u32);
    rep[32..32+body.len()].copy_from_slice(&body);
    with_client(fd, |c| c.send(&rep));
}

// ── GetKeyboardMapping (101) ──────────────────────────────────────────────────

fn op_get_keyboard_mapping(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let first = data[4] as usize; let cnt = data[5] as usize;
    let kpm = 2usize; let bd = cnt*kpm*4;
    let mut rep = vec![0u8; 32+bd];
    rep[0]=1; rep[1]=kpm as u8; w16(&mut rep,2,seq); w32(&mut rep,4,(bd/4) as u32);
    for i in 0..cnt {
        let (u,s) = kc2ksym((first+i) as u8);
        w32(&mut rep, 32+i*kpm*4,   u);
        w32(&mut rep, 32+i*kpm*4+4, s);
    }
    with_client(fd, |c| c.send(&rep));
}

fn kc2ksym(kc: u8) -> (u32, u32) {
    let c: (u8, u8) = match kc {
        10=>(b'1',b'!'), 11=>(b'2',b'@'), 12=>(b'3',b'#'), 13=>(b'4',b'$'),
        14=>(b'5',b'%'), 15=>(b'6',b'^'), 16=>(b'7',b'&'), 17=>(b'8',b'*'),
        18=>(b'9',b'('), 19=>(b'0',b')'), 20=>(b'-',b'_'), 21=>(b'=',b'+'),
        24=>(b'q',b'Q'), 25=>(b'w',b'W'), 26=>(b'e',b'E'), 27=>(b'r',b'R'),
        28=>(b't',b'T'), 29=>(b'y',b'Y'), 30=>(b'u',b'U'), 31=>(b'i',b'I'),
        32=>(b'o',b'O'), 33=>(b'p',b'P'), 38=>(b'a',b'A'), 39=>(b's',b'S'),
        40=>(b'd',b'D'), 41=>(b'f',b'F'), 42=>(b'g',b'G'), 43=>(b'h',b'H'),
        44=>(b'j',b'J'), 45=>(b'k',b'K'), 46=>(b'l',b'L'), 52=>(b'z',b'Z'),
        53=>(b'x',b'X'), 54=>(b'c',b'C'), 55=>(b'v',b'V'), 56=>(b'b',b'B'),
        57=>(b'n',b'N'), 58=>(b'm',b'M'), 65=>(b' ',b' '),
        _=>(0,0),
    };
    (c.0 as u32, c.1 as u32)
}

// ── GetModifierMapping (119) ──────────────────────────────────────────────────

fn op_get_modifier_mapping(fd: u64, seq: u16) {
    let kpm = 2usize; let len = 8*kpm;
    let mut rep = vec![0u8; 32+len];
    rep[0]=1; rep[1]=kpm as u8; w16(&mut rep,2,seq); w32(&mut rep,4,(len/4) as u32);
    let map: [[u8;2];8] = [[50,62],[66,0],[37,105],[64,108],[133,0],[0,0],[134,0],[0,0]];
    for (i,row) in map.iter().enumerate() {
        for (j,&k) in row.iter().enumerate() { rep[32+i*kpm+j] = k; }
    }
    with_client(fd, |c| c.send(&rep));
}

// ── SetModifierMapping (118) ───────────────────────────────────────────────────

fn op_set_modifier_mapping(fd: u64, seq: u16) {
    let mut b = [0u8;32]; b[0]=1; b[1]=0; w16(&mut b,2,seq);
    with_client(fd, |c| c.send(&b));
}

// ── SetPointerMapping (116) ───────────────────────────────────────────────────

fn op_set_pointer_mapping(fd: u64, seq: u16) {
    let mut b = [0u8;32]; b[0]=1; w16(&mut b,2,seq);
    with_client(fd, |c| c.send(&b));
}

// ── GetPointerMapping (117) ───────────────────────────────────────────────────

fn op_get_pointer_mapping(fd: u64, seq: u16) {
    let mut b = [0u8;36]; b[0]=1; b[1]=3; w16(&mut b,2,seq);
    b[32]=1; b[33]=2; b[34]=3;
    with_client(fd, |c| c.send(&b[..36]));
}

// ═════════════════════════════════════════════════════════════════════════════
// RENDER extension (major opcode 68)
// ═════════════════════════════════════════════════════════════════════════════

fn op_render(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    match data[1] {
        proto::RENDER_QUERY_VERSION       => op_render_query_version(fd, data, seq),
        proto::RENDER_QUERY_PICT_FORMATS  => op_render_query_pict_formats(fd, seq),
        proto::RENDER_CREATE_PICTURE      => op_render_create_picture(fd, data),
        proto::RENDER_CHANGE_PICTURE      => {} // no-op: we don't track picture attrs
        proto::RENDER_FREE_PICTURE        => op_render_free_picture(fd, data),
        proto::RENDER_COMPOSITE           => op_render_composite(fd, data),
        proto::RENDER_CREATE_GLYPH_SET    => op_render_create_glyphset(fd, data),
        proto::RENDER_FREE_GLYPH_SET      => op_render_free_glyphset(fd, data),
        proto::RENDER_ADD_GLYPHS          => op_render_add_glyphs(fd, data),
        proto::RENDER_FREE_GLYPHS         => op_render_free_glyphs(fd, data),
        proto::RENDER_COMPOSITE_GLYPHS8   => op_render_composite_glyphs(fd, data, 1),
        proto::RENDER_COMPOSITE_GLYPHS16  => op_render_composite_glyphs(fd, data, 2),
        proto::RENDER_COMPOSITE_GLYPHS32  => op_render_composite_glyphs(fd, data, 4),
        proto::RENDER_FILL_RECTANGLES     => op_render_fill_rectangles(fd, data),
        _                                 => {}
    }
}

// ── RenderQueryVersion (minor 0) ──────────────────────────────────────────────
//
// Request:  [4-7] client-major, [8-11] client-minor
// Reply:    [8-11] server-major=0, [12-15] server-minor=11

fn op_render_query_version(fd: u64, _data: &[u8], seq: u16) {
    let mut b = [0u8; 32];
    b[0] = 1; w16(&mut b, 2, seq);
    // length = 0 (no extra bytes beyond the 32-byte header)
    w32(&mut b, 8,  0); // major = 0
    w32(&mut b, 12, 11); // minor = 11  (RENDER 0.11)
    with_client(fd, |c| c.send(&b));
}

// ── RenderQueryPictFormats (minor 1) ──────────────────────────────────────────
//
// Returns 3 formats (ARGB32, RGB24, A8), 1 screen, 2 depths, 1 visual.
//
// Wire layout after the 32-byte reply header:
//   3 × PictFormInfo (28 bytes each) = 84 bytes
//   1 × PictScreen   (24 + depths)
//     2 × PictDepth:
//       depth=32: 8 bytes header, 0 visuals
//       depth=24: 8 bytes header, 1 × PictVisual (8 bytes)
//   Total screen = 24 + 8 + 16 = 48 bytes
// Grand total extra = 84 + 48 = 132 bytes; length field = 132/4 = 33.

fn op_render_query_pict_formats(fd: u64, seq: u16) {
    // Build the variable-length body
    let mut body: Vec<u8> = Vec::with_capacity(132);

    // ── 3 PictFormInfo entries (28 bytes each) ────────────────────────────
    // Helper: append one format entry
    let mut push_fmt = |buf: &mut Vec<u8>, id: u32, depth: u8,
                         rs: u16, rm: u16, gs: u16, gm: u16,
                         bs: u16, bm: u16, as_: u16, am: u16| {
        let b = id.to_le_bytes(); buf.extend_from_slice(&b);
        buf.push(1);     // type = Direct
        buf.push(depth);
        buf.push(0); buf.push(0); // pad
        buf.extend_from_slice(&rs.to_le_bytes());
        buf.extend_from_slice(&rm.to_le_bytes());
        buf.extend_from_slice(&gs.to_le_bytes());
        buf.extend_from_slice(&gm.to_le_bytes());
        buf.extend_from_slice(&bs.to_le_bytes());
        buf.extend_from_slice(&bm.to_le_bytes());
        buf.extend_from_slice(&as_.to_le_bytes());
        buf.extend_from_slice(&am.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // colormap = 0
    };

    // ARGB32 (depth=32): alpha[31:24] red[23:16] green[15:8] blue[7:0]
    push_fmt(&mut body, proto::PICT_FORMAT_ARGB32, 32,
             16, 0xFF, 8, 0xFF, 0, 0xFF, 24, 0xFF);
    // RGB24 (depth=24): no alpha, red[23:16] green[15:8] blue[7:0]
    push_fmt(&mut body, proto::PICT_FORMAT_RGB24,  24,
             16, 0xFF, 8, 0xFF, 0, 0xFF,  0, 0x00);
    // A8 (depth=8): alpha[7:0] only
    push_fmt(&mut body, proto::PICT_FORMAT_A8,      8,
              0, 0x00, 0, 0x00, 0, 0x00,  0, 0xFF);

    // ── 1 PictScreen (root window, 2 depths) ─────────────────────────────
    // Header: root, colormap, white-pixel, black-pixel, root-depth-idx, num-depths
    body.extend_from_slice(&(proto::ROOT_WINDOW_ID as u32).to_le_bytes());
    body.extend_from_slice(&(proto::DEFAULT_COLORMAP as u32).to_le_bytes());
    body.extend_from_slice(&proto::WHITE_PIXEL.to_le_bytes());
    body.extend_from_slice(&proto::BLACK_PIXEL.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes()); // root-depth-idx = 1 (depth 24 = index 1)
    body.extend_from_slice(&2u32.to_le_bytes()); // num-depths = 2

    // Depth 32: 0 visuals
    body.push(32); body.push(0);  // depth, pad
    body.extend_from_slice(&0u16.to_le_bytes()); // num-visuals = 0
    body.extend_from_slice(&0u32.to_le_bytes()); // pad

    // Depth 24: 1 visual
    body.push(24); body.push(0);  // depth, pad
    body.extend_from_slice(&1u16.to_le_bytes()); // num-visuals = 1
    body.extend_from_slice(&0u32.to_le_bytes()); // pad
    // PictVisual: visual-id, format
    body.extend_from_slice(&(proto::ROOT_VISUAL as u32).to_le_bytes());
    body.extend_from_slice(&proto::PICT_FORMAT_RGB24.to_le_bytes());

    // ── Reply header (32 bytes) ───────────────────────────────────────────
    let length = (body.len() / 4) as u32; // extra CARD32s beyond 32-byte header
    let mut rep = vec![0u8; 32 + body.len()];
    rep[0] = 1;
    w16(&mut rep, 2, seq);
    w32(&mut rep, 4, length);
    w32(&mut rep, 8,  3);  // num-formats
    w32(&mut rep, 12, 1);  // num-screens
    w32(&mut rep, 16, 2);  // num-depths
    w32(&mut rep, 20, 1);  // num-visuals
    w32(&mut rep, 24, 0);  // num-subpixels
    rep[32..32 + body.len()].copy_from_slice(&body);
    with_client(fd, |c| c.send(&rep));
}

// ── RenderCreatePicture (minor 4) ─────────────────────────────────────────────
//
// Request: [4-7] pic-id, [8-11] drawable, [12-15] format, [16-19] value-mask

fn op_render_create_picture(fd: u64, data: &[u8]) {
    if data.len() < 20 { return; }
    let pic_id   = r32(data, 4);
    let drawable = r32(data, 8);
    let format   = r32(data, 12);
    with_client(fd, |c| {
        c.resources.insert(pic_id, ResourceBody::Picture(PictureData { drawable, format }));
    });
}

// ── RenderFreePicture (minor 7) ───────────────────────────────────────────────

fn op_render_free_picture(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    let pic_id = r32(data, 4);
    with_client(fd, |c| { c.resources.remove(pic_id); });
}

// ── RenderComposite (minor 8) ─────────────────────────────────────────────────
//
// Request:
//   [4]     op (PictOp)
//   [8-11]  src picture
//   [12-15] mask picture (0 = no mask — mask ignored for now)
//   [16-19] dst picture
//   [20-21] src-x, [22-23] src-y
//   [24-25] mask-x (ignored), [26-27] mask-y (ignored)
//   [28-29] dst-x, [30-31] dst-y
//   [32-33] width, [34-35] height

fn op_render_composite(fd: u64, data: &[u8]) {
    if data.len() < 36 { return; }
    let op     = data[4];
    let src_id = r32(data, 8);
    let dst_id = r32(data, 16);
    let src_x  = r16(data, 20) as i32;
    let src_y  = r16(data, 22) as i32;
    let dst_x  = r16(data, 28) as i32;
    let dst_y  = r16(data, 30) as i32;
    let width  = r16(data, 32) as i32;
    let height = r16(data, 34) as i32;
    if width <= 0 || height <= 0 { return; }

    // Resolve picture → drawable IDs
    let (src_draw, dst_draw) = {
        let srv = SERVER.lock();
        let c = match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd) {
            Some(c) => c, None => return,
        };
        let src_draw = c.resources.picture_drawable(src_id).unwrap_or(src_id);
        let dst_draw = c.resources.picture_drawable(dst_id).unwrap_or(dst_id);
        (src_draw, dst_draw)
    };

    // Determine drawable types
    let (src_is_pixmap, dst_is_pixmap) = {
        let srv = SERVER.lock();
        let c = match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd) {
            Some(c) => c, None => return,
        };
        let sp = c.resources.entries.iter().filter_map(|s| s.as_ref())
            .find(|r| r.id == src_draw)
            .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_)));
        let dp = c.resources.entries.iter().filter_map(|s| s.as_ref())
            .find(|r| r.id == dst_draw)
            .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_)));
        (sp, dp)
    };
    #[cfg(feature = "xeyes-test")]
    crate::serial_println!("[X11RENDER] Composite op={} src_pic={:#x}->draw={:#x}(pix={}) dst_pic={:#x}->draw={:#x}(pix={}) dst_xy=({},{}) wh=({},{})",
        op, src_id, src_draw, src_is_pixmap, dst_id, dst_draw, dst_is_pixmap,
        dst_x, dst_y, width, height);

    // Clone src pixels (needed to avoid simultaneous mutable borrow of client)
    let src_pixels: alloc::vec::Vec<u8> = if src_is_pixmap {
        let srv = SERVER.lock();
        let c = match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd) {
            Some(c) => c, None => return,
        };
        match c.resources.get_pixmap(src_draw) {
            Some(p) => p.pixels.clone(),
            None    => return,
        }
    } else {
        return; // window → * not supported as src
    };

    // Get src dimensions
    let (src_w, src_h) = {
        let srv = SERVER.lock();
        let c = match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd) {
            Some(c) => c, None => return,
        };
        match c.resources.get_pixmap(src_draw) {
            Some(p) => (p.width as i32, p.height as i32),
            None    => return,
        }
    };

    if dst_is_pixmap {
        with_client(fd, |c| {
            if let Some(dst) = c.resources.get_pixmap_mut(dst_draw) {
                let dw = dst.width as i32;
                let dh = dst.height as i32;
                for row in 0..height {
                    let sy = src_y + row;
                    let dy = dst_y + row;
                    if sy < 0 || sy >= src_h || dy < 0 || dy >= dh { continue; }
                    for col in 0..width {
                        let sx = src_x + col;
                        let dx = dst_x + col;
                        if sx < 0 || sx >= src_w || dx < 0 || dx >= dw { continue; }
                        let so = ((sy * src_w + sx) * 4) as usize;
                        let do_ = ((dy * dw + dx) * 4) as usize;
                        let sa = src_pixels[so + 3] as u32;
                        match op {
                            proto::RENDER_OP_SRC | proto::RENDER_OP_CLEAR => {
                                dst.pixels[do_..do_+4].copy_from_slice(&src_pixels[so..so+4]);
                            }
                            proto::RENDER_OP_OVER | _ => {
                                if sa == 255 {
                                    dst.pixels[do_..do_+4].copy_from_slice(&src_pixels[so..so+4]);
                                } else if sa > 0 {
                                    let ia = 255 - sa;
                                    dst.pixels[do_]     = ((src_pixels[so]     as u32 * sa + dst.pixels[do_]     as u32 * ia) / 255) as u8;
                                    dst.pixels[do_ + 1] = ((src_pixels[so + 1] as u32 * sa + dst.pixels[do_ + 1] as u32 * ia) / 255) as u8;
                                    dst.pixels[do_ + 2] = ((src_pixels[so + 2] as u32 * sa + dst.pixels[do_ + 2] as u32 * ia) / 255) as u8;
                                    dst.pixels[do_ + 3] = (sa + dst.pixels[do_ + 3] as u32 * ia / 255) as u8;
                                }
                            }
                        }
                    }
                }
            }
        });
    } else {
        // dst is a window — composite into the window's persistent pixel buffer
        // (compositor source of truth), preserving the PictOp.  Build a packed
        // width×height BGRA buffer (alpha carried from the source picture) so
        // the OVER blend in window_composite_pixels has correct per-pixel alpha.
        let mut out = alloc::vec![0u8; (width * height * 4) as usize];
        for row in 0..height {
            let sy = src_y + row;
            if sy < 0 || sy >= src_h { continue; }
            for col in 0..width {
                let sx = src_x + col;
                if sx < 0 || sx >= src_w { continue; }
                let so = ((sy * src_w + sx) * 4) as usize;
                let oo = ((row * width + col) * 4) as usize;
                out[oo..oo+4].copy_from_slice(&src_pixels[so..so+4]);
            }
        }
        window_composite_pixels(
            fd, dst_draw, dst_x, dst_y, width, height,
            &out, width, height, op);
    }
}

// ── RenderFillRectangles (minor 26) ──────────────────────────────────────────
//
// Request:
//   [4]     op (PictOp)
//   [8-11]  dst picture
//   [12-13] color-red (CARD16)
//   [14-15] color-green (CARD16)
//   [16-17] color-blue (CARD16)
//   [18-19] color-alpha (CARD16)
//   [20+]   rectangles: (x:i16, y:i16, w:u16, h:u16) × N

fn op_render_fill_rectangles(fd: u64, data: &[u8]) {
    if data.len() < 20 { return; }
    let op     = data[4];
    let dst_id = r32(data, 8);
    // Colors are 16-bit (0–65535); take the high byte for 8-bit BGRA
    let cr = (r16(data, 12) >> 8) as u8;
    let cg = (r16(data, 14) >> 8) as u8;
    let cb = (r16(data, 16) >> 8) as u8;
    let ca = (r16(data, 18) >> 8) as u8;
    // ARGB color for fill_rect: 0xAARRGGBB
    let color = ((ca as u32) << 24) | ((cr as u32) << 16) | ((cg as u32) << 8) | (cb as u32);

    // Resolve picture → drawable
    let dst_draw = {
        let srv = SERVER.lock();
        let c = match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd) {
            Some(c) => c, None => return,
        };
        c.resources.picture_drawable(dst_id).unwrap_or(dst_id)
    };

    let is_pixmap = {
        let srv = SERVER.lock();
        srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
            .map_or(false, |c| c.resources.entries.iter().filter_map(|s| s.as_ref())
                .find(|r| r.id == dst_draw)
                .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_))))
    };

    let mut i = 20usize;
    while i + 8 <= data.len() {
        let rx = r16(data, i) as i16 as i32;
        let ry = r16(data, i+2) as i16 as i32;
        let rw = r16(data, i+4) as i32;
        let rh = r16(data, i+6) as i32;
        i += 8;

        if is_pixmap {
            let fill_color = match op {
                proto::RENDER_OP_CLEAR => 0u32,
                _ => color,
            };
            with_client(fd, |c| {
                if let Some(pix) = c.resources.get_pixmap_mut(dst_draw) {
                    pix.fill_rect(rx, ry, rw, rh, fill_color);
                }
            });
        } else {
            // RENDER fill into a window writes the window's persistent pixel
            // buffer (compositor source of truth), not the screen backbuffer.
            // CLEAR yields fully transparent black; any other op fills the
            // solid colour with its alpha.
            let bgra = match op {
                proto::RENDER_OP_CLEAR => [0u8, 0, 0, 0],
                _ => [cb, cg, cr, ca],
            };
            window_fill_pixels(fd, dst_draw, rx, ry, rw, rh, bgra);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// MIT-SHM extension (major opcode 65)
// ═════════════════════════════════════════════════════════════════════════════

fn op_shm(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    match minor {
        proto::SHM_QUERY_VERSION => {
            // ShmQueryVersionReply (MIT-SHM §ShmQueryVersion): shared_pixmaps=1,
            // major=1, minor=2.  Advertising shared_pixmaps=true tells the client
            // it may back a Pixmap directly with an attached segment via
            // ShmCreatePixmap; clients (e.g. nsShmImage's gUseShmPixmaps path)
            // then present with CreatePixmap → CopyArea(pixmap → window) instead
            // of ShmPutImage.  Both present paths are now implemented server-side.
            let mut b = [0u8; 32];
            b[0] = 1; b[1] = 1; // shared_pixmaps = true
            w16(&mut b, 2, seq);
            w16(&mut b, 8, 1); w16(&mut b, 10, 2); // version 1.2
            b[16] = 2; // pixmap_format = ZPixmap
            with_client(fd, |c| c.send(&b));
        }
        proto::SHM_ATTACH    => op_shm_attach(fd, data),
        proto::SHM_DETACH    => op_shm_detach(fd, data),
        proto::SHM_PUT_IMAGE => op_shm_put_image(fd, data),
        // SHM_GET_IMAGE: return unimplemented error
        proto::SHM_GET_IMAGE => {
            with_client(fd, |c| c.send_error(proto::ERR_IMPLEMENTATION, 0, proto::SHM_MAJOR_OPCODE));
        }
        proto::SHM_CREATE_PIXMAP => op_shm_create_pixmap(fd, data),
        _ => {}
    }
}

// ShmAttach request (MIT-SHM protocol §ShmAttach):
//   [4..8]   shmseg  (X resource id chosen by the client for this attachment)
//   [8..12]  shmid   (SysV shmid the client created via shmget)
//   [12]     read_only BOOL
fn op_shm_attach(fd: u64, data: &[u8]) {
    if data.len() < 13 { return; }
    let shmseg = r32(data, 4);
    let shmid  = r32(data, 8);
    let mut tbl = SHM_ATTACH.lock();
    // Replace an existing record for this shmseg, else take a free slot.
    let idx = tbl.iter().position(|a| a.shmseg == shmseg)
        .or_else(|| tbl.iter().position(|a| a.shmseg == 0));
    if let Some(i) = idx {
        tbl[i] = ShmAttach { shmseg, shmid, fd };
    }
}

// ShmDetach request: [4..8] shmseg.
fn op_shm_detach(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    let shmseg = r32(data, 4);
    let mut tbl = SHM_ATTACH.lock();
    if let Some(slot) = tbl.iter_mut().find(|a| a.shmseg == shmseg && a.fd == fd) {
        *slot = ShmAttach::empty();
    }
}

/// Resolve a `shmseg` X resource id (owned by `fd`) to its SysV `shmid`.
fn shm_lookup(fd: u64, shmseg: u32) -> Option<u32> {
    let tbl = SHM_ATTACH.lock();
    tbl.iter()
        .find(|a| a.shmseg == shmseg && a.fd == fd && a.shmseg != 0)
        .map(|a| a.shmid)
}

// ShmCreatePixmap request (MIT-SHM protocol §ShmCreatePixmap, 28 bytes):
//   [0]      reqType        [1]  shmReqType (=5)   [2..4]  length
//   [4..8]   pid            (new Pixmap X resource id)
//   [8..12]  drawable       (a drawable on the target screen; only used to
//                            pick the screen/depth — pixels come from the segment)
//   [12..14] width          [14..16] height
//   [16]     depth          [17..20] pad
//   [20..24] shmseg         (the attached MIT-SHM segment id)
//   [24..28] offset         (byte offset of the pixel origin within the segment)
//
// Creates a Pixmap RESOURCE whose pixel backing IS the attached SysV-SHM
// segment: no server-owned pixel buffer is allocated.  The client draws each
// frame directly into the segment and then `CopyArea`s the pixmap to a window;
// `op_copy_area` reads the segment's LIVE bytes at copy time.  The row stride is
// the scanline-padded byte width — for depth 24/32 at 32 bits-per-pixel this is
// `width * 4` (4-byte scanline pad makes the pad a no-op at 32 bpp).
fn op_shm_create_pixmap(fd: u64, data: &[u8]) {
    if data.len() < 28 { return; }
    let pid    = r32(data, 4);
    let width  = r16(data, 12);
    let height = r16(data, 14);
    let depth  = data[16];
    let shmseg = r32(data, 20);
    let offset = r32(data, 24);

    if width == 0 || height == 0 { return; }
    // Only the 32-bpp ZPixmap depths the server composites are honoured; the
    // CopyArea reader assumes a 4-byte BGRA pixel.
    if depth < 24 { return; }

    // The shmseg must be a live attachment owned by this client; resolve it to a
    // SysV shmid and validate the requested image region fits in the segment
    // before creating the resource (so a later CopyArea never reads out of range).
    let shmid = match shm_lookup(fd, shmseg) { Some(id) => id, None => return };
    let (_phys_base, seg_size) = match crate::ipc::sysv_shm::segment_phys(shmid) {
        Some(v) => v, None => return,
    };
    let stride  = width as u64 * 4;
    let img_len = stride * height as u64;
    if (offset as u64).saturating_add(img_len) > seg_size { return; }

    with_client(fd, |c| {
        c.resources.insert(
            pid,
            ResourceBody::Pixmap(PixmapData::new_shm_backed(
                width, height, depth, shmid, offset, stride as u32)),
        );
    });
}

// ShmPutImage request (MIT-SHM protocol §ShmPutImage):
//   [4..8]   drawable
//   [8..12]  gc
//   [12..14] total_width   [14..16] total_height  (dims of the image in shm)
//   [16..18] src_x         [18..20] src_y
//   [20..22] src_width     [22..24] src_height
//   [24..26] dst_x         [26..28] dst_y
//   [28]     depth   [29] format   [30] send_event  [31] pad
//   [32..36] shmseg
//   [36..40] offset        (byte offset of the image base within the segment)
//
// The pixel data lives in the attached SysV segment, so the server reads it
// directly from the segment's physical backing and composites the requested
// sub-rectangle into the destination window — mirroring `op_put_image`'s
// window-buffer write so the compositor's source-of-truth surface is updated.
fn op_shm_put_image(fd: u64, data: &[u8]) {
    if data.len() < 40 { return; }
    let draw   = r32(data, 4);
    let total_w = r16(data, 12) as i32;
    let total_h = r16(data, 14) as i32;
    let src_x   = r16(data, 16) as i32;
    let src_y   = r16(data, 18) as i32;
    let src_w   = r16(data, 20) as i32;
    let src_h   = r16(data, 22) as i32;
    let dst_x   = r16(data, 24) as i32;
    let dst_y   = r16(data, 26) as i32;
    let depth   = data[28];
    let format  = data[29];
    let shmseg  = r32(data, 32);
    let offset  = r32(data, 36) as u64;

    // Only ZPixmap, depth ≥ 24 (BGRA32) is composited; other formats are ignored
    // (the same conservative guard as core PutImage).
    if format != proto::IMAGE_FORMAT_ZPIXMAP || depth < 24 { return; }
    if total_w <= 0 || total_h <= 0 || src_w <= 0 || src_h <= 0 { return; }

    let shmid = match shm_lookup(fd, shmseg) { Some(id) => id, None => return };
    let (phys_base, seg_size) = match crate::ipc::sysv_shm::segment_phys(shmid) {
        Some(v) => v, None => return,
    };

    // The image occupies total_w*total_h*4 bytes from `offset`.  Validate the
    // whole image region (plus the sub-rectangle's last byte) fits in the
    // segment before reading any physical memory.
    let stride  = total_w as u64 * 4;
    let img_len = stride * total_h as u64;
    if offset.saturating_add(img_len) > seg_size { return; }
    // Sub-rectangle must lie inside the image.
    if src_x < 0 || src_y < 0
        || src_x + src_w > total_w || src_y + src_h > total_h { return; }

    // SAFETY: `phys_base` is the identity-mapped, kernel-readable base of a
    // physically-contiguous SysV segment (see sysv_shm::shmget).  The bounds
    // checks above guarantee `[offset, offset+img_len)` is within the segment,
    // so the slice never reads past the backing pages.
    let src: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (phys_base + offset) as *const u8,
            img_len as usize,
        )
    };

    // Composite the sub-rectangle (src_x,src_y,src_w,src_h) of the shm image
    // into the window at (dst_x,dst_y).  The source slice is the full image
    // (stride = total_w*4); `window_composite_pixels` indexes rows from the
    // slice origin, so offset into the sub-rectangle's first row/col here.
    let sub_origin = (src_y as u64 * stride + src_x as u64 * 4) as usize;
    if sub_origin >= src.len() { return; }
    window_composite_pixels(
        fd, draw, dst_x, dst_y, src_w, src_h,
        &src[sub_origin..], total_w, src_h, proto::RENDER_OP_SRC);
}

// ═════════════════════════════════════════════════════════════════════════════
// GLX extension (major opcode 146)
//
// Public reference: "OpenGL Graphics System: A Specification — GLX Extension"
// and the GLX Protocol Encoding.  With the Mesa software path (the drisw loader +
// llvmpipe) the GL rendering runs CLIENT-SIDE in the application's own address
// space (direct rendering); the X server only answers the handshake/bookkeeping
// requests so the client driver can bind a GL context to its window.  Presents
// arrive over the core protocol (PutImage) or MIT-SHM (ShmPutImage), not GLX.
// ═════════════════════════════════════════════════════════════════════════════

// The single TrueColor depth-24 visual the server advertises is ROOT_VISUAL=32.
// We expose two GLX configs over it: a single-buffered and a double-buffered
// RGBA config, so glXChooseVisual succeeds whether or not the client requests
// GLX_DOUBLEBUFFER (glxtest tries single-buffer first, then double-buffer).

fn op_glx(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    match data[1] {
        proto::GLX_QUERY_VERSION          => op_glx_query_version(fd, data, seq),
        proto::GLX_GET_VISUAL_CONFIGS     => op_glx_get_visual_configs(fd, seq),
        proto::GLX_GET_FB_CONFIGS         => op_glx_get_fb_configs(fd, seq),
        proto::GLX_CREATE_CONTEXT         => op_glx_create_context(fd, data, 4),
        proto::GLX_CREATE_NEW_CONTEXT     => op_glx_create_context(fd, data, 4),
        proto::GLX_CREATE_CONTEXT_ATTRIBS_ARB => op_glx_create_context(fd, data, 4),
        proto::GLX_DESTROY_CONTEXT        => op_glx_destroy_context(fd, data),
        proto::GLX_MAKE_CURRENT           => op_glx_make_current(fd, data, seq),
        proto::GLX_MAKE_CONTEXT_CURRENT   => op_glx_make_current(fd, data, seq),
        proto::GLX_IS_DIRECT              => op_glx_is_direct(fd, seq),
        proto::GLX_QUERY_SERVER_STRING    => op_glx_query_server_string(fd, data, seq),
        proto::GLX_QUERY_EXTENSIONS_STRING=> op_glx_query_extensions_string(fd, seq),
        proto::GLX_QUERY_CONTEXT          => op_glx_query_context(fd, data, seq),
        proto::GLX_GET_DRAWABLE_ATTRIBUTES=> op_glx_get_drawable_attributes(fd, seq),
        proto::GLX_CHANGE_DRAWABLE_ATTRIBUTES => {} // no reply; accept
        proto::GLX_CREATE_WINDOW | proto::GLX_DESTROY_WINDOW |
        proto::GLX_CREATE_PIXMAP | proto::GLX_DESTROY_PIXMAP |
        proto::GLX_CREATE_GLX_PIXMAP | proto::GLX_DESTROY_GLX_PIXMAP |
        proto::GLX_CREATE_PBUFFER | proto::GLX_DESTROY_PBUFFER |
        proto::GLX_USE_X_FONT | proto::GLX_COPY_CONTEXT => {} // bookkeeping; no reply
        // ClientInfo / SetClientInfo*ARB / WaitGL / WaitX / SwapBuffers: requests
        // that carry no reply.  With direct rendering SwapBuffers is a client-side
        // present (the client uses core PutImage / ShmPutImage), so we accept and
        // ignore.  RenderLarge / Render likewise never reach us under direct GL.
        proto::GLX_CLIENT_INFO | proto::GLX_SET_CLIENT_INFO_ARB |
        proto::GLX_SET_CLIENT_INFO_2ARB | proto::GLX_WAIT_GL |
        proto::GLX_WAIT_X | proto::GLX_SWAP_BUFFERS |
        proto::GLX_RENDER | proto::GLX_RENDER_LARGE => {}
        _ => {}
    }
}

// GLXQueryVersion reply: [8..12]=major, [12..16]=minor.  We support GLX 1.4.
fn op_glx_query_version(fd: u64, _data: &[u8], seq: u16) {
    let mut b = [0u8; 32];
    b[0] = 1; w16(&mut b, 2, seq);
    w32(&mut b, 8, 1);  // major = 1
    w32(&mut b, 12, 4); // minor = 4
    with_client(fd, |c| c.send(&b));
}

// Append the 18 leading positional CARD32 fields of a GLX 1.2 visual-config
// block, in the order the client unmarshals them (GLX Protocol Encoding §
// GetVisualConfigs): visualID, X visual class, rgba-flag, R/G/B/A bits,
// accum R/G/B/A bits, doubleBuffer, stereo, rgbBits, depthBits, stencilBits,
// auxBuffers, level.
fn push_visual_config(body: &mut Vec<u8>, double_buffer: bool) {
    let fields: [u32; 18] = [
        proto::ROOT_VISUAL,                  // visualID
        proto::VISUAL_CLASS_TRUECOLOR as u32,// X visual class (TrueColor=4)
        1,                                   // rgba flag (true)
        8, 8, 8, 0,                          // red, green, blue, alpha bits
        0, 0, 0, 0,                          // accum red/green/blue/alpha
        double_buffer as u32,                // doubleBuffer
        0,                                   // stereo
        24,                                  // rgbBits (total colour bits)
        24,                                  // depthBits
        8,                                   // stencilBits
        0,                                   // auxBuffers
        0,                                   // level
    ];
    for v in fields { body.extend_from_slice(&v.to_le_bytes()); }
}

// GLXGetVisualConfigs reply (GLX Protocol Encoding §GetVisualConfigs):
//   [8..12]  numVisuals
//   [12..16] numProps  (CARD32 words per visual)
//   body     numVisuals * numProps CARD32
// length field = (numVisuals * numProps).
fn op_glx_get_visual_configs(fd: u64, seq: u16) {
    let num_visuals = 2u32;
    let num_props   = 18u32; // 18 positional fields, no trailing tag/value pairs
    let mut body: Vec<u8> = Vec::with_capacity((num_visuals * num_props * 4) as usize);
    push_visual_config(&mut body, false); // single-buffered
    push_visual_config(&mut body, true);  // double-buffered
    let words = (num_visuals * num_props) as usize;
    let mut rep = vec![0u8; 32 + words * 4];
    rep[0] = 1; w16(&mut rep, 2, seq); w32(&mut rep, 4, words as u32);
    w32(&mut rep, 8, num_visuals); w32(&mut rep, 12, num_props);
    rep[32..32 + body.len()].copy_from_slice(&body);
    with_client(fd, |c| c.send(&rep));
}

// Append one fully-tagged GLX 1.3 fbconfig as (tag, value) CARD32 pairs.  All
// fields are tagged (the client reads them with tagged_only=TRUE).
fn push_fbconfig(body: &mut Vec<u8>, fbconfig_id: u32, double_buffer: bool) {
    let pairs: [(u32, u32); 23] = [
        (proto::GLX_TOK_FBCONFIG_ID,    fbconfig_id),
        (proto::GLX_TOK_VISUAL_ID,      proto::ROOT_VISUAL),
        (proto::GLX_TOK_X_VISUAL_TYPE,  proto::GLX_VAL_TRUE_COLOR),
        (proto::GLX_TOK_RENDER_TYPE,    proto::GLX_VAL_RGBA_BIT),
        (proto::GLX_TOK_DRAWABLE_TYPE,  proto::GLX_VAL_WINDOW_BIT
                                         | proto::GLX_VAL_PIXMAP_BIT),
        (proto::GLX_TOK_X_RENDERABLE,   1),
        (proto::GLX_TOK_RGBA,           1),
        (proto::GLX_TOK_CONFIG_CAVEAT,  proto::GLX_VAL_NONE),
        (proto::GLX_TOK_BUFFER_SIZE,    24),
        (proto::GLX_TOK_LEVEL,          0),
        (proto::GLX_TOK_DOUBLEBUFFER,   double_buffer as u32),
        (proto::GLX_TOK_STEREO,         0),
        (proto::GLX_TOK_AUX_BUFFERS,    0),
        (proto::GLX_TOK_RED_SIZE,       8),
        (proto::GLX_TOK_GREEN_SIZE,     8),
        (proto::GLX_TOK_BLUE_SIZE,      8),
        (proto::GLX_TOK_ALPHA_SIZE,     0),
        (proto::GLX_TOK_DEPTH_SIZE,     24),
        (proto::GLX_TOK_STENCIL_SIZE,   8),
        (proto::GLX_TOK_ACCUM_RED,      0),
        (proto::GLX_TOK_ACCUM_GREEN,    0),
        (proto::GLX_TOK_ACCUM_BLUE,     0),
        (proto::GLX_TOK_ACCUM_ALPHA,    0),
    ];
    for (tag, val) in pairs {
        body.extend_from_slice(&tag.to_le_bytes());
        body.extend_from_slice(&val.to_le_bytes());
    }
}

// GLXGetFBConfigs reply (GLX Protocol Encoding §GetFBConfigs):
//   [8..12]  numFBConfigs
//   [12..16] numAttribs  (number of (tag,value) PAIRS per fbconfig)
//   body     numFBConfigs * numAttribs * 2 CARD32
// length field = (numFBConfigs * numAttribs * 2).
fn op_glx_get_fb_configs(fd: u64, seq: u16) {
    let num_fbconfigs = 2u32;
    let num_attribs   = 23u32; // pairs per fbconfig (matches push_fbconfig)
    let mut body: Vec<u8> = Vec::with_capacity((num_fbconfigs * num_attribs * 8) as usize);
    push_fbconfig(&mut body, 0x21, false); // single-buffered, fbconfig id 0x21
    push_fbconfig(&mut body, 0x22, true);  // double-buffered, fbconfig id 0x22
    let words = (num_fbconfigs * num_attribs * 2) as usize;
    let mut rep = vec![0u8; 32 + words * 4];
    rep[0] = 1; w16(&mut rep, 2, seq); w32(&mut rep, 4, words as u32);
    w32(&mut rep, 8, num_fbconfigs); w32(&mut rep, 12, num_attribs);
    rep[32..32 + body.len()].copy_from_slice(&body);
    with_client(fd, |c| c.send(&rep));
}

// GLXCreateContext / GLXCreateNewContext / GLXCreateContextAttribsARB: the
// context XID is the first request word at `id_off`.  No reply.  We just record
// the XID so DestroyContext / QueryContext can validate it.
fn op_glx_create_context(fd: u64, data: &[u8], id_off: usize) {
    if data.len() < id_off + 4 { return; }
    let xid = r32(data, id_off);
    if xid == 0 { return; }
    let mut tbl = GLX_CONTEXTS.lock();
    let idx = tbl.iter().position(|c| c.xid == xid)
        .or_else(|| tbl.iter().position(|c| c.xid == 0));
    if let Some(i) = idx {
        tbl[i] = GlxContext { xid, fd };
    }
}

// GLXDestroyContext: [4..8]=context XID.  No reply.
fn op_glx_destroy_context(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    let xid = r32(data, 4);
    let mut tbl = GLX_CONTEXTS.lock();
    if let Some(slot) = tbl.iter_mut().find(|c| c.xid == xid && c.fd == fd) {
        *slot = GlxContext::empty();
    }
}

// GLXMakeCurrent / GLXMakeContextCurrent reply: [8..12]=context_tag.  Per the
// GLX encoding the tag is an opaque non-zero handle the client echoes back in
// later requests (and which we never interpret under direct rendering).  We
// return a stable non-zero tag.
fn op_glx_make_current(fd: u64, _data: &[u8], seq: u16) {
    let mut b = [0u8; 32];
    b[0] = 1; w16(&mut b, 2, seq);
    w32(&mut b, 8, 1); // context_tag = 1 (non-zero, opaque)
    with_client(fd, |c| c.send(&b));
}

// GLXIsDirect reply: [8]=is_direct BOOL.  We answer true so the client binds the
// local software driver (llvmpipe) and renders directly, rather than tunnelling
// an indirect GL command stream over the wire (which we do not implement).
fn op_glx_is_direct(fd: u64, seq: u16) {
    let mut b = [0u8; 32];
    b[0] = 1; w16(&mut b, 2, seq);
    b[8] = 1; // is_direct = true
    with_client(fd, |c| c.send(&b));
}

// GLXQueryContext reply: [8..12]=numAttribs (pairs), then numAttribs*2 CARD32.
// We report the context's fbconfig id and render type so the client's
// glXQueryContext succeeds.  Body is 2 (tag,value) pairs.
fn op_glx_query_context(fd: u64, _data: &[u8], seq: u16) {
    let pairs: [(u32, u32); 2] = [
        (proto::GLX_TOK_FBCONFIG_ID, 0x22),
        (proto::GLX_TOK_RENDER_TYPE, proto::GLX_VAL_RGBA_BIT),
    ];
    let n = pairs.len() as u32;
    let words = (n * 2) as usize;
    let mut rep = vec![0u8; 32 + words * 4];
    rep[0] = 1; w16(&mut rep, 2, seq); w32(&mut rep, 4, words as u32);
    w32(&mut rep, 8, n);
    let mut off = 32;
    for (tag, val) in pairs {
        w32(&mut rep, off, tag); w32(&mut rep, off + 4, val); off += 8;
    }
    with_client(fd, |c| c.send(&rep));
}

// GLXGetDrawableAttributes reply (GLX Protocol Encoding §GetDrawableAttributes):
//   [8..12]  numAttribs (number of (attrib,value) CARD32 PAIRS)
//   body     numAttribs*2 CARD32 at [32..]
// We return an empty attribute list (numAttribs=0); the client then uses its
// defaults.  Issuing a reply (rather than silently dropping the request) is
// essential — the request expects one, and a missing reply would wedge the
// client's request queue.
fn op_glx_get_drawable_attributes(fd: u64, seq: u16) {
    let mut b = [0u8; 32];
    b[0] = 1; w16(&mut b, 2, seq);
    // length = 0, numAttribs = 0 (both already zero-filled).
    with_client(fd, |c| c.send(&b));
}

// GLXQueryServerString request: [8..12]=name (GLX_VENDOR/VERSION/EXTENSIONS).
// Reply: [12..16]=n (string length including the trailing NUL), string at [32..].
// length = pad4(n)/4.
fn op_glx_query_server_string(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 12 { return; }
    let name = r32(data, 8);
    let s: &[u8] = match name {
        proto::GLX_STRING_VENDOR  => b"Xastryx",
        proto::GLX_STRING_VERSION => b"1.4",
        // No server GL extensions are advertised over the wire — under direct
        // rendering the client driver (Mesa) provides its own extension string.
        proto::GLX_STRING_EXTENSIONS => b"",
        _ => b"",
    };
    glx_send_string(fd, seq, s);
}

// GLXQueryExtensionsString reply: same shape as QueryServerString (n at [12..16],
// string at [32..]).  Empty: Mesa's direct driver supplies its own extensions.
fn op_glx_query_extensions_string(fd: u64, seq: u16) {
    glx_send_string(fd, seq, b"");
}

// Shared encoder for the GLX *String replies: n at [12..16] counts the NUL.
fn glx_send_string(fd: u64, seq: u16, s: &[u8]) {
    let n = s.len() + 1; // include trailing NUL
    let pd = proto::pad4(n);
    let mut rep = vec![0u8; 32 + pd];
    rep[0] = 1; w16(&mut rep, 2, seq); w32(&mut rep, 4, (pd / 4) as u32);
    w32(&mut rep, 12, n as u32);
    rep[32..32 + s.len()].copy_from_slice(s);
    // trailing NUL already zero-filled
    with_client(fd, |c| c.send(&rep));
}

// ═════════════════════════════════════════════════════════════════════════════
// BIG-REQUESTS extension (major opcode 133)
//
// The entire extension is a single negotiation round-trip:
//   Client → BigReqEnable (minor 0, 4-byte request)
//   Server → BigReqEnableReply: 32 bytes, b[8..12] = new max request length
//            in 4-byte units.
//
// After this exchange the client may send requests whose 16-bit length field
// is 0; in that case the next four bytes carry the real (32-bit) length.
// We acknowledge the negotiation and advertise 4 MiB, but we do not yet
// handle 32-bit lengths in the dispatcher — requests that large aren't needed
// for GTK/Firefox init.
// ═════════════════════════════════════════════════════════════════════════════

fn op_bigreq(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    if minor == proto::BIGREQ_ENABLE {
        // BigReqEnableReply: b[8..12] = maximum request length in 4-byte units.
        let mut b = [0u8; 32];
        b[0] = 1; // reply
        w16(&mut b, 2, seq);
        // length field (b[4..8]) = 0 — the reply body fits in the 32-byte header.
        w32(&mut b, 8, proto::BIGREQ_MAX_REQUEST_LEN);
        with_client(fd, |c| c.send(&b));
    }
    // No other opcodes are defined for BIG-REQUESTS; ignore anything else.
}

// ═════════════════════════════════════════════════════════════════════════════
// XFIXES extension (major opcode 69)
// ═════════════════════════════════════════════════════════════════════════════

fn op_xfixes(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    match minor {
        proto::XFIXES_QUERY_VERSION => {
            // XFixesQueryVersionReply: major=5, minor=0 (CARD32 each)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 8,  5); // major_version
            w32(&mut b, 12, 0); // minor_version
            with_client(fd, |c| c.send(&b));
        }
        // All other XFIXES ops (hide/show cursor, region ops) are side-effect only
        _ => {}
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// DAMAGE extension (major opcode 70)
// ═════════════════════════════════════════════════════════════════════════════

fn op_damage(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    match minor {
        proto::DAMAGE_QUERY_VERSION => {
            // DamageQueryVersionReply: major=1, minor=1 (CARD32 each)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 8,  1); // major_version
            w32(&mut b, 12, 1); // minor_version
            with_client(fd, |c| c.send(&b));
        }
        // Create/Destroy/Subtract/Add: stub accept
        proto::DAMAGE_CREATE | proto::DAMAGE_DESTROY |
        proto::DAMAGE_SUBTRACT | proto::DAMAGE_ADD => {}
        _ => {}
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// XInputExtension / XI2 (major opcode 72)
// ═════════════════════════════════════════════════════════════════════════════

fn op_xinput(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    crate::serial_println!("[X11/XI] minor={} len={}", minor, data.len());
    match minor {
        // ── XI v1 (subset commonly issued by libXi during device discovery) ───
        proto::XI_V1_GET_EXTENSION_VERSION => {
            // XGetExtensionVersionReply: present=1, server_major=2, server_minor=3
            // Reply layout per X Input Extension Protocol §3.1
            // (32-byte fixed reply, no trailing data).
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w16(&mut b, 8,  2);   // server_major
            w16(&mut b, 10, 3);   // server_minor
            b[12] = 1;            // present
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_V1_LIST_INPUT_DEVICES => {
            // Minimal: report 2 devices (virtual core pointer + virtual core
            // keyboard) with NO input classes attached.  Reply shape per
            // X Input Extension §3.2: 32-byte header (ndevices, then variable
            // device array, then variable classes, then variable names).
            //
            // Reply byte 1 = ndevices.
            // Reply qword 8.. = (variable) — empty in our minimal impl since
            // ndevices=0 means many clients short-circuit without inspecting
            // the variable part.  This is sufficient for xeyes which only
            // cares about XI2 device list (via XIQueryDevice) when XI2 is
            // available — and we advertise XI2 via XIQueryVersion above.
            let mut b = [0u8; 32];
            b[0] = 1; b[1] = 0;   // ndevices = 0
            w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_V1_OPEN_DEVICE => {
            // OpenDeviceReply: ndevices_classes=0 (32-byte fixed).
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_V1_GET_DEVICE_FOCUS => {
            // GetDeviceFocusReply: focus=PointerRoot, time=0, revert_to=None
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 8,  1); // focus = PointerRoot (id 1)
            w32(&mut b, 12, 0); // time
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_V1_QUERY_DEVICE_STATE => {
            // QueryDeviceStateReply: num_classes=0.  Per X Input Extension
            // §3.30 the variable trailer carries InputClass records; an empty
            // list means "device exists but reports no axes/keys at this
            // moment" — acceptable for a tracking client.
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_V1_CLOSE_DEVICE => {} // no reply

        // ── XI2 ────────────────────────────────────────────────────────────────
        proto::XI_QUERY_VERSION => {
            // XIQueryVersionReply: major=2, minor=3 (CARD16 each)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w16(&mut b, 8,  2); // major_version
            w16(&mut b, 10, 3); // minor_version
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_QUERY_POINTER => {
            // XIQueryPointerReply: 56-byte fixed header.
            // Per XInput2 protocol §3.1: root, child, root_x/y, win_x/y (all
            // FP1616), mods, group, buttons_len.  Report pointer at (0,0)
            // on the root window with no buttons pressed.
            let mut b = [0u8; 56];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 4, 6);  // reply_length = 6 four-byte units (56-32=24)
            w32(&mut b, 8,  proto::ROOT_WINDOW_ID); // root
            w32(&mut b, 12, 0);                     // child = None
            // root_x = root_y = win_x = win_y = 0 (FP1616 zero)
            // mods (16) + group (4) + buttons_len (4) = remaining zeroes.
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_GET_CLIENT_POINTER => {
            // XIGetClientPointerReply: set=true, device_id = 2 (virtual core ptr)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            b[8] = 1;          // set
            w16(&mut b, 10, 2); // device_id (per XI2 reply layout)
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_SELECT_EVENTS => {} // no reply
        proto::XI_QUERY_DEVICE => {
            // XIQueryDeviceReply: num_devices=0 trailing data.
            // Per XInput2 protocol §4.4: 32-byte header followed by
            // num_devices XIDeviceInfo records.  Reporting zero devices is
            // a legal reply; clients fall back to assuming the core
            // pointer/keyboard are present (which our XI v1 ListInputDevices
            // and core protocol QueryPointer also imply).
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            // reply_length=0 (32-byte fixed), num_devices=0.
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_GET_FOCUS => {
            // XIGetFocusReply: focus=PointerRoot.
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 8, 1); // focus = PointerRoot
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_LIST_PROPERTIES => {
            // XIListPropertiesReply: num_properties=0 (32-byte fixed).
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_GET_PROPERTY => {
            // XIGetPropertyReply: type=0 (None), bytes_after=0, num_items=0.
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_GET_SELECTED_EVENTS => {
            // XIGetSelectedEventsReply: num_masks=0 (32-byte fixed).
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        _ => {
            // Unknown XInputExtension minor.  Treat as a no-reply request
            // (best-effort; the alternative is a BadRequest error which
            // many toolkits handle worse than silence).
            #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
            crate::serial_println!("[X11/XI] unhandled minor={} (no reply)", minor);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// COMPOSITE extension (major opcode 75)
// ═════════════════════════════════════════════════════════════════════════════

fn op_composite(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    match minor {
        proto::COMPOSITE_QUERY_VERSION => {
            // CompositeQueryVersionReply: major=0, minor=4 (CARD32 each)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 8,  0); // major_version
            w32(&mut b, 12, 4); // minor_version
            with_client(fd, |c| c.send(&b));
        }
        proto::COMPOSITE_GET_OVERLAY_WINDOW => {
            // Return root window id as the overlay window
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 8, proto::ROOT_WINDOW_ID);
            with_client(fd, |c| c.send(&b));
        }
        // All other Composite ops: redirect/unredirect, name pixmap — side-effect only
        _ => {}
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// XTEST extension (major opcode 71)
// ═════════════════════════════════════════════════════════════════════════════

fn op_xtest(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    match minor {
        0 => {
            // XTestGetVersionReply: server_major=2 (CARD8 at b[1]), server_minor=2 (CARD16 at b[8])
            let mut b = [0u8; 32];
            b[0] = 1; b[1] = 2; // server_major_version
            w16(&mut b, 2, seq);
            w16(&mut b, 8, 2); // server_minor_version
            with_client(fd, |c| c.send(&b));
        }
        1 => {
            // XTestCompareCursor: return Same = true
            let mut b = [0u8; 32];
            b[0] = 1; b[1] = 1; // same = true
            w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        // FakeInput (2) / GrabControl (3): side-effect only
        _ => {}
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SYNC extension (major opcode 74)
// ═════════════════════════════════════════════════════════════════════════════

fn op_sync_ext(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    match minor {
        0 => {
            // SyncInitializeReply: major=3 (CARD8 at b[8]), minor=1 (CARD8 at b[9])
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            b[8] = 3; b[9] = 1; // version 3.1
            with_client(fd, |c| c.send(&b));
        }
        // All SYNC counter/alarm/fence operations: stub accept
        _ => {}
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// XKEYBOARD extension (major opcode 135)
// ═════════════════════════════════════════════════════════════════════════════

fn op_xkeyboard(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    #[cfg(any(feature = "firefox-test-core", feature = "xeyes-test"))]
    crate::serial_println!("[X11XKB] minor={} seq={} len={}", minor, seq, data.len());
    // XKB request minor-opcodes per the X Keyboard Extension Protocol
    // Specification §New Requests (X.Org kbproto; the canonical X_kb* numbering
    // also published in X11/extensions/XKB.h):
    //   0  UseExtension*        1  SelectEvents       3  Bell
    //   4  GetState*            5  LatchLockState     6  GetControls*
    //   7  SetControls          8  GetMap*            9  SetMap
    //   10 GetCompatMap*        11 SetCompatMap       12 GetIndicatorState*
    //   13 GetIndicatorMap*     14 SetIndicatorMap    15 GetNamedIndicator*
    //   16 SetNamedIndicator    17 GetNames*          18 SetNames
    //   19 GetGeometry*         20 SetGeometry        21 PerClientFlags*
    //   22 ListComponents*      23 GetKbdByName*      24 GetDeviceInfo*
    //   25 SetDeviceInfo        101 SetDebuggingFlags*
    // Starred (*) opcodes generate a 32-byte reply the client BLOCKS on; the
    // others are request-only (no reply).  Sending a reply for a no-reply
    // opcode — or, worse, withholding a reply for a reply opcode — desyncs the
    // client's request/reply sequence accounting and wedges its event loop.
    // GTK/GDK issues GetMap(8), GetNames(17) and PerClientFlags(21) during
    // keymap initialization inside gdk_display_open(), so each MUST be
    // answered or the toplevel is never realized.  We return well-formed but
    // empty (no-components) replies — sufficient for a software-rendered,
    // no-physical-keyboard display.
    match minor {
        0 => {
            // XkbUseExtension: report the extension as NOT supported for the
            // client's requested version (the `supported` BOOL in byte 1 is 0).
            //
            // Per the X Keyboard Extension Protocol Specification §UseExtension,
            // a client (libX11's XkbQueryExtension / XkbUseExtension) that sees
            // supported=0 falls back to the *core* keyboard protocol — it stops
            // issuing XkbGetMap and instead builds its keymap from
            // GetKeyboardMapping(101) + GetModifierMapping(119), both of which
            // this server answers with a complete, non-empty map (see
            // op_get_keyboard_mapping / op_get_modifier_mapping).  GDK mirrors
            // this: gdkkeys-x11 sets use_xkb=FALSE and uses the core path.
            //
            // We deliberately do NOT try to synthesize a full XkbGetMap reply.
            // A *complete* XKB client map (key types, the per-keycode
            // key_sym_map array, modifier maps) is required for correctness:
            // libX11's XkbKeysymToModifiers walks
            //   xkb->map->key_sym_map[kc] -> ->kt_index -> xkb->map->types[...]
            // and dereferences those arrays unconditionally.  An "empty"
            // (present=0) GetMap reply leaves them NULL, so the very next
            // GTK keymap query faults on a NULL deref (NULL+4).  Reporting the
            // extension unsupported routes the client onto the core protocol
            // we already serve correctly, avoiding a large, fragile XKB map
            // serializer for a display that has no physical keyboard.
            //
            // serverMajor/serverMinor still report a valid version (1.0) so
            // the negotiation itself is well-formed.
            let mut b = [0u8; 32];
            b[0] = 1; b[1] = 0; w16(&mut b, 2, seq);
            w16(&mut b, 8, 1); w16(&mut b, 10, 0);
            with_client(fd, |c| c.send(&b));
        }
        4 => {
            // XkbGetState: return zeroed state (no modifiers, group 0)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            // mods, base_mods, latched_mods, locked_mods = 0
            // group=0, locked_group=0, base_group=0, latched_group=0
            // ptr_btn_state=0, compat_state=0, etc.
            with_client(fd, |c| c.send(&b));
        }
        8 => {
            // XkbGetMap (opcode 8): send an empty map reply.
            // 32-byte reply header: type=1, deviceID, seq, length=0 (no
            // trailing map components since present=0).  Per the XKB protocol
            // the reply carries minKeyCode/maxKeyCode then a `present` bitmask
            // selecting which map components follow; present=0 means the body
            // is exactly the 32-byte header.
            //   b[8]  minKeyCode   b[9]  maxKeyCode
            //   b[10..12] present (CARD16) = 0 → no components → length=0
            let mut b = [0u8; 32]; b[0] = 1; b[1] = 1; w16(&mut b, 2, seq);
            b[8] = 8; b[9] = 255; // min/max keycode
            // present=0 (b[10..12]) → no map components → length stays 0
            with_client(fd, |c| c.send(&b));
        }
        17 => {
            // XkbGetNames (opcode 17): reply with which=0 (no name components).
            // The reply MUST have the correct format or the client reads beyond
            // the 32-byte header, desynchronizing the request stream.
            // Reply: type=1, deviceID, seq, length=0
            //   b[8..12]  = which (CARD32) = 0 → no name components follow
            //   b[12]=minKeyCode, b[13]=maxKeyCode, then nTypes/groupNames/...
            let mut b = [0u8; 32]; b[0] = 1; b[1] = 1; w16(&mut b, 2, seq);
            // which=0 at offset 8 (all zeros) → client reads 0 extra bytes
            b[12] = 8;  // minKeyCode
            b[13] = 255; // maxKeyCode
            with_client(fd, |c| c.send(&b));
        }
        21 => {
            // XkbPerClientFlags (opcode 21): reply echoing the (now-zero)
            // supported/value flag set.  GDK uses this to enable
            // detectable-autorepeat; an empty 32-byte reply (all flags 0) is a
            // valid "nothing changed" response and unblocks the caller.
            let mut b = [0u8; 32]; b[0] = 1; b[1] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        6 | 10 | 12 | 13 | 15 | 19 | 22 | 23 | 24 | 101 => {
            // Remaining reply-generating opcodes:
            //   6  GetControls     10 GetCompatMap     12 GetIndicatorState
            //   13 GetIndicatorMap 15 GetNamedIndicator 19 GetGeometry
            //   22 ListComponents  23 GetKbdByName     24 GetDeviceInfo
            //   101 SetDebuggingFlags
            // Each blocks the client on a 32-byte reply; for a stub keyboard a
            // minimal header with no trailing data (length=0) is a well-formed
            // "empty / not-found / defaults" reply.  GetGeometry's `found`
            // (b[1]) is left 0 = no geometry, which clients tolerate.
            let mut b = [0u8; 32]; b[0] = 1; b[1] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        // Request-only opcodes (1 SelectEvents, 3 Bell, 5 LatchLockState,
        // 7 SetControls, 9 SetMap, 11 SetCompatMap, 14 SetIndicatorMap,
        // 16 SetNamedIndicator, 18 SetNames, 20 SetGeometry, 25 SetDeviceInfo):
        // no reply — sending one would desync the client.  Ignore.
        _ => {}
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// DPMS extension (major opcode 73)
// ═════════════════════════════════════════════════════════════════════════════

fn op_dpms(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 4 { return; }
    let minor = data[1];
    match minor {
        0 => {
            // DPMSGetVersion: server_major=2, server_minor=0 (CARD16 each at b[8..12])
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w16(&mut b, 8, 2); w16(&mut b, 10, 0);
            with_client(fd, |c| c.send(&b));
        }
        1 => {
            // DPMSCapable: return capable=true
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            b[8] = 1; // capable = true
            with_client(fd, |c| c.send(&b));
        }
        2 => {
            // DPMSGetTimeouts: standby=0, suspend=0, off=0 (all disabled)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        7 => {
            // DPMSInfo: power_level=DPMSModeOn(0), state=enabled
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w16(&mut b, 8, 0); // power_level = DPMSModeOn
            b[10] = 1; // state = enabled
            with_client(fd, |c| c.send(&b));
        }
        // SetTimeouts(3), Enable(4), Disable(5), ForceLevel(6): side-effect only
        _ => {}
    }
}

// ── RandR extension (major opcode 143) ───────────────────────────────────────
// Minimal RandR 1.6 stub sufficient for Firefox to enumerate screen outputs.

fn op_randr(fd: u64, data: &[u8], seq: u16) {
    if data.is_empty() { return; }
    let minor = data[1];
    match minor {
        0 => {
            // QueryVersion: return 1.6
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 8, 1);  // major = 1
            w32(&mut b, 12, 6); // minor = 6
            with_client(fd, |c| c.send(&b));
        }
        2 => {
            // GetScreenInfo: single config (1920x1080 @ 60 Hz)
            //  Return a minimal RRGetScreenInfoReply with one size entry.
            let mut b = [0u8; 96];
            b[0] = 1; w16(&mut b, 2, seq);
            w32(&mut b, 4, (96-32)/4);  // length in 4-byte units
            w32(&mut b, 8, 0x1000001);  // root window
            w32(&mut b, 12, 0x1000001); // timestamp
            w16(&mut b, 16, 1920);      // width
            w16(&mut b, 18, 1080);      // height
            w16(&mut b, 20, 0);         // current rate
            w16(&mut b, 22, 0);         // current config
            w16(&mut b, 24, 0);         // nSizes=0 (simplified)
            w16(&mut b, 26, 0);         // nRates=0
            with_client(fd, |c| c.send(&b));
        }
        5 => {
            // GetScreenResources: return empty resources reply
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        6 => {
            // GetOutputInfo: ENOENT — no outputs
            // Return error instead of reply (callers handle gracefully)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        24 => {
            // GetScreenResourcesCurrent: empty
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        _ => {
            // Unknown RandR minor: return empty reply
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
    }
}

// ── SHAPE extension ──────────────────────────────────────────────────────────

fn op_shape(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 2 { return; }
    let minor = data[1];
    match minor {
        0 => {
            // ShapeQueryVersion: return 1.1
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w16(&mut b, 8, 1);  // major = 1
            w16(&mut b, 10, 1); // minor = 1
            with_client(fd, |c| c.send(&b));
        }
        // ShapeMask(1), ShapeCombine(2), ShapeOffset(3), ShapeQueryExtents(5),
        // ShapeSelectInput(6), ShapeInputSelected(7), ShapeGetRectangles(8) —
        // none require a reply except QueryExtents(5), InputSelected(7), GetRectangles(8).
        5 => {
            // ShapeQueryExtents: bounding/clip shaped = false, empty extents
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            // b[1]=bounded, b[2]=clipped (both 0 = not shaped)
            with_client(fd, |c| c.send(&b));
        }
        7 => {
            // ShapeInputSelected: enabled=0
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        8 => {
            // ShapeGetRectangles: nrects=0
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            // w32 nrects=0 already zeroed
            with_client(fd, |c| c.send(&b));
        }
        _ => {
            // ShapeMask/ShapeCombine/ShapeOffset/ShapeSelectInput — no reply
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// RENDER GlyphSet handlers (minor opcodes 17–25)
// ═════════════════════════════════════════════════════════════════════════════

// ── RenderCreateGlyphSet (minor 17) ──────────────────────────────────────────
// Request: [4-7] gsid, [8-11] format
fn op_render_create_glyphset(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let gsid   = r32(data, 4);
    let format = r32(data, 8);
    with_client(fd, |c| {
        let gs = GlyphSet { format, glyphs: alloc::vec::Vec::new() };
        c.resources.insert(gsid, ResourceBody::GlyphSet(alloc::boxed::Box::new(gs)));
    });
}

// ── RenderFreeGlyphSet (minor 19) ────────────────────────────────────────────
// Request: [4-7] gsid
fn op_render_free_glyphset(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    with_client(fd, |c| { c.resources.remove(r32(data, 4)); });
}

// ── RenderAddGlyphs (minor 20) ───────────────────────────────────────────────
// Request: [4-7] gsid, [8-11] nglyphs,
//          [12..] glyph IDs (u32 × N), then GlyphInfo × N (12 bytes each),
//          then pixel data (A8, each glyph padded to 4-byte boundary).
fn op_render_add_glyphs(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let gsid    = r32(data, 4);
    let nglyphs = r32(data, 8) as usize;
    if nglyphs == 0 { return; }
    let ids_off    = 12;
    let infos_off  = ids_off + nglyphs * 4;
    let pixels_off = infos_off + nglyphs * 12;
    if data.len() < pixels_off { return; }

    // Collect IDs and GlyphInfos first (avoid holding mutable borrow)
    let mut ids:   alloc::vec::Vec<u32>       = alloc::vec::Vec::with_capacity(nglyphs);
    let mut infos: alloc::vec::Vec<GlyphInfo>  = alloc::vec::Vec::with_capacity(nglyphs);
    for i in 0..nglyphs {
        ids.push(r32(data, ids_off + i * 4));
        let b = infos_off + i * 12;
        if data.len() < b + 12 { break; }
        infos.push(GlyphInfo {
            width:  r16(data, b),
            height: r16(data, b + 2),
            x_off:  r16(data, b + 4) as i16,
            y_off:  r16(data, b + 6) as i16,
            x_adv:  r16(data, b + 8) as i16,
            y_adv:  r16(data, b + 10) as i16,
        });
    }
    let n = infos.len();

    // Collect pixel data
    let mut pixel_bufs: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::with_capacity(n);
    let mut pix_cur = pixels_off;
    for i in 0..n {
        let nbytes = (infos[i].width as usize) * (infos[i].height as usize); // A8 = 1B/pixel
        let nbytes_aligned = (nbytes + 3) & !3;
        let pixels = if data.len() >= pix_cur + nbytes {
            data[pix_cur..pix_cur + nbytes].to_vec()
        } else {
            alloc::vec![0u8; nbytes]
        };
        pix_cur += nbytes_aligned;
        pixel_bufs.push(pixels);
    }

    with_client(fd, |c| {
        if let Some(gs) = c.resources.get_glyphset_mut(gsid) {
            for i in 0..n {
                let gid = ids[i];
                let info = infos[i];
                let pixels = pixel_bufs[i].clone();
                if let Some(pos) = gs.glyphs.iter().position(|(id, _, _)| *id == gid) {
                    gs.glyphs[pos] = (gid, info, pixels);
                } else {
                    gs.glyphs.push((gid, info, pixels));
                }
            }
        }
    });
}

// ── RenderFreeGlyphs (minor 22) ──────────────────────────────────────────────
// Request: [4-7] gsid, [8..] glyph IDs (u32 each)
fn op_render_free_glyphs(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    let gsid = r32(data, 4);
    with_client(fd, |c| {
        if let Some(gs) = c.resources.get_glyphset_mut(gsid) {
            let mut off = 8;
            while off + 4 <= data.len() {
                let gid = r32(data, off);
                gs.glyphs.retain(|(id, _, _)| *id != gid);
                off += 4;
            }
        }
    });
}

// ── RenderCompositeGlyphs8/16/32 (minor 23/24/25) ────────────────────────────
//
// Request (elem_size = 1/2/4 for Glyphs8/16/32):
//   [4]     PictOp
//   [8-11]  src Picture
//   [12-15] dst Picture
//   [16-19] mask-format (0 = None)
//   [20-23] GlyphSet ID
//   [24-25] src-x (i16) — initial pen x
//   [26-27] src-y (i16) — initial pen y
//   [28+]   item list (GlyphElt or GlyphSetElt elements)
//
// GlyphElt:    count(1) pad(3) dx(i16) dy(i16)  glyph_ids[count × elem_size]
//              padded to 4-byte boundary (glyph_ids portion)
// GlyphSetElt: 0xFF(1)  pad(3) new_gsid(4)
fn op_render_composite_glyphs(fd: u64, data: &[u8], elem_size: u8) {
    if data.len() < 28 { return; }
    let op     = data[4];
    let src_id = r32(data, 8);
    let dst_id = r32(data, 12);
    let mut cur_gsid = r32(data, 20);
    let init_x = r16(data, 24) as i16 as i32;
    let init_y = r16(data, 26) as i16 as i32;

    // Phase 1: collect glyph render commands + src color + dst drawable
    // Each cmd: (alpha_pixels: Vec<u8>, glyph_w: u16, glyph_h: u16, dst_x: i32, dst_y: i32)
    let mut cmds: alloc::vec::Vec<(alloc::vec::Vec<u8>, u16, u16, i32, i32)> = alloc::vec::Vec::new();
    let (src_bgra, dst_draw) = {
        let srv = SERVER.lock();
        let c = match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd) {
            Some(c) => c,
            None    => return,
        };
        // src Picture → read 1×1 solid-color pixmap as BGRA bytes
        let src_draw = c.resources.picture_drawable(src_id).unwrap_or(src_id);
        let src_bgra = if let Some(p) = c.resources.get_pixmap(src_draw) {
            if p.pixels.len() >= 4 {
                [p.pixels[0], p.pixels[1], p.pixels[2], p.pixels[3]]
            } else { [0u8, 0, 0, 255] }
        } else { [0u8, 0, 0, 255] }; // opaque black fallback

        let dst_draw = c.resources.picture_drawable(dst_id).unwrap_or(dst_id);

        // Parse item list
        let mut pen_x = init_x;
        let mut pen_y = init_y;
        let mut pos   = 28usize;
        while pos < data.len() {
            if data.len() - pos < 4 { break; }
            let count = data[pos] as usize;
            pos += 4; // count + 3 pad bytes

            if count == 0 { break; } // invalid / end-of-stream

            if count == 0xFF {
                // GlyphSetElt: change active GlyphSet
                if data.len() - pos < 4 { break; }
                cur_gsid = r32(data, pos);
                pos += 4;
                continue;
            }

            // GlyphElt: dx, dy, then glyph IDs
            if data.len() - pos < 4 { break; }
            let dx = r16(data, pos) as i16 as i32; pos += 2;
            let dy = r16(data, pos) as i16 as i32; pos += 2;
            pen_x += dx;
            pen_y += dy;

            let ids_bytes   = count * elem_size as usize;
            let ids_padded  = (ids_bytes + 3) & !3;
            if data.len() - pos < ids_padded { break; }

            if let Some(gs) = c.resources.get_glyphset(cur_gsid) {
                for i in 0..count {
                    let gid: u32 = match elem_size {
                        1 => if pos + i     < data.len() { data[pos + i]            as u32 } else { 0 },
                        2 => if pos + i*2+1 < data.len() { r16(data, pos + i*2)     as u32 } else { 0 },
                        _ => if pos + i*4+3 < data.len() { r32(data, pos + i*4)           } else { 0 },
                    };
                    if let Some((_, info, alpha)) = gs.glyphs.iter().find(|(id, _, _)| *id == gid) {
                        let gx = pen_x + info.x_off as i32;
                        let gy = pen_y + info.y_off as i32;
                        cmds.push((alpha.clone(), info.width, info.height, gx, gy));
                        pen_x += info.x_adv as i32;
                        pen_y += info.y_adv as i32;
                    }
                }
            }
            pos += ids_padded;
        }
        (src_bgra, dst_draw)
    };

    if cmds.is_empty() { return; }
    let _ = op; // Porter-Duff op; treat all as OVER for glyph rendering

    // Phase 2: composite glyphs into dst
    let dst_is_pix = {
        let srv = SERVER.lock();
        let c = match srv.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd) {
            Some(c) => c, None => return,
        };
        c.resources.entries.iter().filter_map(|s| s.as_ref())
            .find(|r| r.id == dst_draw)
            .map_or(false, |r| matches!(r.body, ResourceBody::Pixmap(_)))
    };

    if dst_is_pix {
        with_client(fd, |c| {
            if let Some(dst) = c.resources.get_pixmap_mut(dst_draw) {
                let dw = dst.width  as i32;
                let dh = dst.height as i32;
                for (alpha, gw, gh, gx, gy) in &cmds {
                    for row in 0..(*gh as i32) {
                        let dy = gy + row;
                        if dy < 0 || dy >= dh { continue; }
                        for col in 0..(*gw as i32) {
                            let dx = gx + col;
                            if dx < 0 || dx >= dw { continue; }
                            let ai = (row * *gw as i32 + col) as usize;
                            if ai >= alpha.len() { continue; }
                            let a  = alpha[ai] as u32;
                            if a == 0 { continue; }
                            let ia = 255 - a;
                            let do_ = ((dy * dw + dx) * 4) as usize;
                            // Porter-Duff OVER: src_color × a + dst × (1-a)
                            dst.pixels[do_]   = ((src_bgra[0] as u32 * a + dst.pixels[do_]   as u32 * ia) / 255) as u8;
                            dst.pixels[do_+1] = ((src_bgra[1] as u32 * a + dst.pixels[do_+1] as u32 * ia) / 255) as u8;
                            dst.pixels[do_+2] = ((src_bgra[2] as u32 * a + dst.pixels[do_+2] as u32 * ia) / 255) as u8;
                            dst.pixels[do_+3] = (a + dst.pixels[do_+3] as u32 * ia / 255) as u8;
                        }
                    }
                }
            }
        });
    } else {
        // Window destination — composite glyphs into the window's persistent
        // pixel buffer (compositor source of truth), not the screen backbuffer.
        // Find bounding box of all glyphs
        let (mut min_x, mut min_y, mut max_x, mut max_y) =
            (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
        for (_, gw, gh, gx, gy) in &cmds {
            min_x = min_x.min(*gx);
            min_y = min_y.min(*gy);
            max_x = max_x.max(gx + *gw as i32);
            max_y = max_y.max(gy + *gh as i32);
        }
        if min_x >= max_x || min_y >= max_y { return; }
        let bw = (max_x - min_x) as usize;
        let bh = (max_y - min_y) as usize;
        if bw > 4096 || bh > 4096 { return; } // sanity check
        // Build BGRA buffer (transparent background = 0x00 → let compositor blend)
        let mut out = alloc::vec![0u8; bw * bh * 4];
        for (alpha, gw, gh, gx, gy) in &cmds {
            for row in 0..(*gh as i32) {
                for col in 0..(*gw as i32) {
                    let ai = (row * *gw as i32 + col) as usize;
                    if ai >= alpha.len() { continue; }
                    let a = alpha[ai] as u32;
                    if a == 0 { continue; }
                    let ia  = 255 - a;
                    let ox  = (gx - min_x + col) as usize;
                    let oy  = (gy - min_y + row) as usize;
                    if ox >= bw || oy >= bh { continue; }
                    let oo  = (oy * bw + ox) * 4;
                    out[oo]   = ((src_bgra[0] as u32 * a + out[oo]   as u32 * ia) / 255) as u8;
                    out[oo+1] = ((src_bgra[1] as u32 * a + out[oo+1] as u32 * ia) / 255) as u8;
                    out[oo+2] = ((src_bgra[2] as u32 * a + out[oo+2] as u32 * ia) / 255) as u8;
                    out[oo+3] = (a + out[oo+3] as u32 * ia / 255) as u8;
                }
            }
        }
        window_composite_pixels(
            fd, dst_draw, min_x, min_y, bw as i32, bh as i32,
            &out, bw as i32, bh as i32, proto::RENDER_OP_OVER);
    }
}
