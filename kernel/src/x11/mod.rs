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
    fd:           u64,
    seq:          u16,
    setup_done:   bool,
    focus_window: u32,
    resources:    Box<ResourceTable>,
}

impl Client {
    fn new(fd: u64) -> Self {
        Client { fd, seq: 0, setup_done: false,
                 focus_window: proto::ROOT_WINDOW_ID,
                 resources: Box::new(ResourceTable::new()) }
    }
    fn next_seq(&mut self) -> u16 { self.seq = self.seq.wrapping_add(1); self.seq }
    fn send(&self, data: &[u8])   {
        #[cfg(feature = "firefox-test")]
        if data.len() >= 4 && data[0] == 1 {
            // Reply: log fd, seq, reply_length, total_bytes
            let seq = u16::from_le_bytes([data[2], data[3]]);
            let extra = if data.len() >= 8 { u32::from_le_bytes([data[4], data[5], data[6], data[7]]) } else { 0 };
            crate::serial_println!("[X11REPLY] fd={} seq={} reply_len={} total={}",
                self.fd, seq, extra, data.len());
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
}
impl Server {
    const fn new() -> Self {
        Server {
            initialized:     false,
            listen_fd:       0,
            clients:         [const { None }; MAX_CLIENTS],
            root_properties: [const { None }; resource::MAX_PROPERTIES],
            selections:      [SelectionOwner::empty(); MAX_SELECTIONS],
        }
    }
}
unsafe impl Send for Server {}
static SERVER: Mutex<Server> = Mutex::new(Server::new());

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
    let fd = unix::create();
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
        // Intern the EWMH atoms we support.
        let net_supported            = atoms::intern("_NET_SUPPORTED",                false);
        let net_wm_state             = atoms::intern("_NET_WM_STATE",                 false);
        let net_wm_state_fullscreen  = atoms::intern("_NET_WM_STATE_FULLSCREEN",      false);
        let net_wm_state_max_vert    = atoms::intern("_NET_WM_STATE_MAXIMIZED_VERT",  false);
        let net_wm_state_max_horiz   = atoms::intern("_NET_WM_STATE_MAXIMIZED_HORIZ", false);
        let net_wm_state_hidden      = atoms::intern("_NET_WM_STATE_HIDDEN",          false);
        let net_active_window        = atoms::intern("_NET_ACTIVE_WINDOW",            false);
        let net_wm_name              = atoms::intern("_NET_WM_NAME",                  false);
        let net_wm_window_type       = atoms::intern("_NET_WM_WINDOW_TYPE",           false);
        // Pack the supported-atom list as 32-bit LE values.
        let supported = [
            net_wm_state, net_wm_state_fullscreen, net_wm_state_max_vert,
            net_wm_state_max_horiz, net_wm_state_hidden, net_active_window,
            net_wm_name, net_wm_window_type,
        ];
        let mut buf = [0u8; 64];
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
    for slot in srv.clients.iter_mut() {
        if let Some(c) = slot {
            let fw = c.focus_window;
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
    for slot in srv.clients.iter_mut() {
        if let Some(c) = slot {
            let fw = c.focus_window;
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

/// Collect all mapped X11 client windows for compositor rendering.
/// Returns a Vec of snapshots (copies pixel data to avoid holding locks).
pub fn get_mapped_windows() -> Vec<X11WindowSnapshot> {
    if !X11_INITIALIZED.load(Ordering::Acquire) { return Vec::new(); }
    let srv = SERVER.lock();
    let mut result = Vec::new();
    for slot in srv.clients.iter() {
        if let Some(client) = slot {
            for (_rid, body) in client.resources.iter_all() {
                if let resource::ResourceBody::Window(ref w) = body {
                    if w.mapped && !w.pixels.is_empty() && w.width > 0 && w.height > 0 {
                        result.push(X11WindowSnapshot {
                            x: w.x,
                            y: w.y,
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
                unix::close(dead_fds[i]);
            }
        }
    }

    let mut pending = [u64::MAX; MAX_CLIENTS];
    { let s = SERVER.lock();
      for (i, sl) in s.clients.iter().enumerate() {
          if let Some(c) = sl {
              let hd = unix::has_data(c.fd);
              #[cfg(feature = "firefox-test")]
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
    #[cfg(feature = "firefox-test")]
    crate::serial_println!("[X11SVC] fd={} read {} bytes", fd, n);
    let setup = {
        let s = SERVER.lock();
        s.clients.iter().filter_map(|s| s.as_ref()).find(|c| c.fd == fd)
         .map(|c| c.setup_done).unwrap_or(false)
    };
    if !setup { handle_setup(fd, data); return; }
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let rlen = r16(data, off + 2) as usize;
        if rlen == 0 { break; }
        let end = off + rlen * 4;
        if end > data.len() { break; }
        handle_request(fd, &data[off..end]);
        off = end;
    }
}

// ── Setup ─────────────────────────────────────────────────────────────────────

fn handle_setup(fd: u64, data: &[u8]) {
    if data.len() < 12       { send_fail(fd, b"truncated"); return; }
    if data[0] != 0x6C       { send_fail(fd, b"big-endian not supported"); return; }
    if r16(data,2) != 11     { send_fail(fd, b"unsupported protocol"); return; }
    #[cfg(feature = "firefox-test")]
    {
        let n_auth = r16(data, 6) as usize;
        let d_auth = r16(data, 8) as usize;
        crate::serial_println!("[X11] setup: byte_order={:#x} maj={} min={} n_auth={} d_auth={} total_client={}",
            data[0], r16(data,2), r16(data,4), n_auth, d_auth, data.len());
    }
    let reply = build_setup_ok();
    #[cfg(feature = "firefox-test")]
    {
        crate::serial_println!("[X11] setup_ok len={} hdr={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} additional_units={} n_screens={} n_formats={}",
            reply.len(), reply[0], reply[1], reply[2], reply[3], reply[4], reply[5], reply[6], reply[7],
            r16(&reply,6), reply[28], reply[29]);
        crate::serial_println!("[X11] setup_ok res_base={:#x} res_mask={:#x} vendor_len={} max_req={}",
            r32(&reply,12), r32(&reply,16), r16(&reply,24), r16(&reply,26));
    }
    let n_written = unix::write(fd, &reply);
    #[cfg(feature = "firefox-test")]
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
    #[cfg(feature = "firefox-test")]
    {
        static X11_REQ_N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        let n = X11_REQ_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n < 200 {
            crate::serial_println!("[X11] req#{} op={} len={}", n, opcode, data.len());
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
        proto::OP_MAP_WINDOW            => op_map_window(fd, data, seq),
        proto::OP_UNMAP_WINDOW          => op_unmap_window(fd, data, seq),
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
        proto::OP_SEND_EVENT            => {} // no reply — client routes event to window, no-op
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
        proto::OP_POLY_FILL_RECTANGLE   => op_poly_fill_rect(fd, data),
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
            #[cfg(feature = "firefox-test")]
            crate::serial_println!("[X11] unknown opcode={} len={}", opcode, data.len());
            with_client(fd, |c| c.send_error(proto::ERR_REQUEST, 0, opcode));
        }
    }
}

fn with_client<F: FnOnce(&mut Client)>(fd: u64, f: F) {
    let mut srv = SERVER.lock();
    if let Some(c) = srv.clients.iter_mut().filter_map(|s| s.as_mut()).find(|c| c.fd == fd) { f(c); }
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
    let mut event_mask = 0u32; let mut bg_pixel = 0u32;
    let mut override_redirect = false;
    let mut vi = 32usize;
    if vmask & proto::CW_BACK_PIXMAP       != 0 { vi += 4; }
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
        if let Some(w) = c.resources.get_window_mut(wid) {
            let mut vi = 12usize;
            if vmask & proto::CW_BACK_PIXMAP       != 0 { vi += 4; }
            if vmask & proto::CW_BACK_PIXEL        != 0 { w.background_pixel = r32(data, vi); vi += 4; }
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

// ── MapWindow (8) ─────────────────────────────────────────────────────────────

fn op_map_window(fd: u64, data: &[u8], seq: u16) {
    if data.len() < 8 { return; }
    let wid = r32(data, 4);
    with_client(fd, |c| {
        if let Some(w) = c.resources.get_window_mut(wid) {
            let (x,y,width,height,evmask) = (w.x, w.y, w.width, w.height, w.event_mask);
            w.mapped = true;
            w.ensure_pixels(); // Allocate pixel buffer for compositor
            if evmask & proto::EVENT_MASK_STRUCTURE_NOTIFY != 0 {
                c.send(&event::encode_map_notify(seq, wid));
            }
            if evmask & proto::EVENT_MASK_EXPOSURE != 0 {
                c.send(&event::encode_expose(seq, wid, x, y, width, height));
            }
            crate::serial_println!("[X11] MapWindow {:#x} {}x{}+{},{}", wid, width, height, x, y);
        } else { c.send_error(proto::ERR_WINDOW, wid, proto::OP_MAP_WINDOW); }
    });
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
            if let Some(w) = c.resources.get_window_mut(wid) { w.set_property(prop, type_, fmt, pdata, mode); }
        });
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
    #[cfg(feature = "firefox-test")]
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
            #[cfg(feature = "firefox-test")]
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
        #[cfg(feature = "firefox-test")]
        crate::serial_println!("[X11GP] result={} wid={} atom={}", result.is_some(), wid, atom);
        match result {
            None => {
                let mut b=[0u8;32]; b[0]=1; w16(&mut b,2,seq);
                let wr = unix::write(c.fd, &b);
                #[cfg(feature = "firefox-test")]
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

// ── GrabPointer/GrabKeyboard reply ─────────────────────────────────────────

fn op_grab_reply(fd: u64, seq: u16) {
    let mut b = [0u8;32]; b[0]=1; w16(&mut b,2,seq);
    with_client(fd, |c| c.send(&b));
}

// ── SetInputFocus (42) ──────────────────────────────────────────────────────

fn op_set_input_focus(fd: u64, data: &[u8]) {
    if data.len() < 8 { return; }
    let focus = r32(data, 4);
    with_client(fd, |c| c.focus_window = focus);
}

// ── GetInputFocus (43) ──────────────────────────────────────────────────────

fn op_get_input_focus(fd: u64, seq: u16) {
    let focus = SERVER.lock().clients.iter().filter_map(|s| s.as_ref())
        .find(|c| c.fd == fd).map(|c| c.focus_window).unwrap_or(proto::ROOT_WINDOW_ID);
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
        let (wx, wy) = window_origin(fd, draw);
        let pw = if w == 0 { proto::SCREEN_WIDTH as i32 } else { w };
        let ph = if h == 0 { proto::SCREEN_HEIGHT as i32 } else { h };
        crate::gdi::fill_rect_screen(wx + x, wy + y, pw, ph, 0x000000);
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
            // pixmap → window: blit to screen
            let pixels: alloc::vec::Vec<u8> = {
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
                        for row in 0..rh {
                            for col in 0..rw {
                                let so = (((y0 + row as i32) * sw + x0 + col as i32) * 4) as usize;
                                let bo = (row * rw + col) * 4;
                                buf[bo..bo+4].copy_from_slice(&p.pixels[so..so+4]);
                            }
                        }
                        buf
                    }
                    None => return,
                }
            };
            let (wx, wy) = window_origin(fd, dst_id);
            crate::gdi::blit_pixels_screen(
                wx + dst_x, wy + dst_y,
                width as u32, height as u32, &pixels);
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
        let (wx, wy) = window_origin(fd, draw);
        crate::gdi::blit_pixels_screen(wx+dx, wy+dy, width, height, &data[24..24+px_len]);
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
    let (wx, wy) = window_origin(fd, draw);
    crate::gdi::draw_text_screen(wx+tx, wy+ty, text, fg & 0xFFFFFF, bg & 0xFFFFFF);
}

/// Return the (x,y) screen-space origin of a window resource, or (0,0).
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
    match name {
        "MIT-SHM"        => { b[8]=1; b[9]=proto::SHM_MAJOR_OPCODE;    b[10]=0; b[11]=0; }
        "BIG-REQUESTS"   => { b[8]=1; b[9]=proto::BIGREQ_MAJOR_OPCODE; b[10]=0; b[11]=0; }
        "XKEYBOARD"      => { b[8]=1; b[9]=proto::XKEYBOARD_MAJOR_OPCODE; b[10]=0; b[11]=0; }
        "SHAPE"     => { b[8]=1; b[9]=proto::SHAPE_MAJOR_OPCODE;   b[10]=0; b[11]=0; }
        "RENDER"    => { b[8]=1; b[9]=proto::RENDER_MAJOR_OPCODE;  b[10]=0; b[11]=0; }
        "XFIXES"    => { b[8]=1; b[9]=proto::XFIXES_MAJOR_OPCODE;  b[10]=0; b[11]=0; }
        "DAMAGE"    => { b[8]=1; b[9]=proto::DAMAGE_MAJOR_OPCODE;  b[10]=0; b[11]=0; }
        "XTEST"     => { b[8]=1; b[9]=proto::XTEST_MAJOR_OPCODE;   b[10]=0; b[11]=0; }
        "XInputExtension" | "XI" | "XInput" => {
            b[8]=1; b[9]=proto::XINPUT_MAJOR_OPCODE; b[10]=0; b[11]=0;
        }
        "DPMS"      => { b[8]=1; b[9]=proto::DPMS_MAJOR_OPCODE;    b[10]=0; b[11]=0; }
        "SYNC"      => { b[8]=1; b[9]=proto::SYNC_MAJOR_OPCODE;    b[10]=0; b[11]=0; }
        "COMPOSITE" => { b[8]=1; b[9]=proto::COMPOSITE_MAJOR_OPCODE; b[10]=0; b[11]=0; }
        "RANDR" | "RandR" => { b[8]=1; b[9]=proto::RANDR_MAJOR_OPCODE; b[10]=0; b[11]=0; }
        _           => {} // not present
    }
    with_client(fd, |c| c.send(&b));
}

// ── ListExtensions (99) ──────────────────────────────────────────────────────

fn op_list_extensions(fd: u64, seq: u16) {
    let names: &[&[u8]] = &[
        b"MIT-SHM", b"BIG-REQUESTS", b"XKEYBOARD", b"SHAPE", b"RENDER",
        b"XFIXES", b"DAMAGE", b"XTEST", b"XInputExtension",
        b"DPMS", b"SYNC", b"COMPOSITE", b"RANDR",
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
        // dst is a window — blit to screen
        // Build the output BGRA buffer
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
        let (wx, wy) = window_origin(fd, dst_draw);
        crate::gdi::blit_pixels_screen(wx + dst_x, wy + dst_y, width as u32, height as u32, &out);
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
            let (wx, wy) = window_origin(fd, dst_draw);
            let rgb = ((cr as u32) << 16) | ((cg as u32) << 8) | (cb as u32);
            crate::gdi::fill_rect_screen(wx + rx, wy + ry, rw, rh, rgb);
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
            // ShmQueryVersionReply: shared_pixmaps=0, major=1, minor=2
            let mut b = [0u8; 32];
            b[0] = 1; b[1] = 0; // shared_pixmaps = false
            w16(&mut b, 2, seq);
            w16(&mut b, 8, 1); w16(&mut b, 10, 2); // version 1.2
            b[16] = 2; // pixmap_format = ZPixmap
            with_client(fd, |c| c.send(&b));
        }
        // SHM_ATTACH / SHM_DETACH: side-effect, accept silently
        proto::SHM_ATTACH | proto::SHM_DETACH => {}
        // SHM_PUT_IMAGE: stub — no real shared memory backing
        proto::SHM_PUT_IMAGE => {}
        // SHM_GET_IMAGE: return unimplemented error
        proto::SHM_GET_IMAGE => {
            with_client(fd, |c| c.send_error(proto::ERR_IMPLEMENTATION, 0, proto::SHM_MAJOR_OPCODE));
        }
        // SHM_CREATE_PIXMAP: accept, treated as no-op
        proto::SHM_CREATE_PIXMAP => {}
        _ => {}
    }
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
    match minor {
        proto::XI_QUERY_VERSION => {
            // XIQueryVersionReply: major=2, minor=3 (CARD16 each)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w16(&mut b, 8,  2); // major_version
            w16(&mut b, 10, 3); // minor_version
            with_client(fd, |c| c.send(&b));
        }
        proto::XI_GET_CLIENT_POINTER => {
            // XIGetClientPointerReply: device_id = 2 (default pointer)
            let mut b = [0u8; 32];
            b[0] = 1; w16(&mut b, 2, seq);
            w16(&mut b, 8, 2); // device_id
            with_client(fd, |c| c.send(&b));
        }
        // XI_SELECT_EVENTS: side-effect only
        proto::XI_SELECT_EVENTS => {}
        _ => {}
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
    #[cfg(feature = "firefox-test")]
    crate::serial_println!("[X11XKB] minor={} seq={} len={}", minor, seq, data.len());
    // XKB minor opcodes that need replies:
    // 0=UseExtension, 4=GetState, 6=GetControls, 9=ListComponents,
    // 10=GetMap, 17=GetCompatMap, 21=GetNames, 24=GetDeviceInfo, 31=SetDebuggingFlags
    // No-reply: 1=SelectEvents, 3=DeviceBell, 5=SetControls, 7=LockControls, 11=SetMap, etc.
    match minor {
        0 => {
            // XkbUseExtension: supported=1, serverMajor=1, serverMinor=0
            let mut b = [0u8; 32];
            b[0] = 1; b[1] = 1; w16(&mut b, 2, seq);
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
        6 | 31 => {
            // XkbGetControls / SetDebuggingFlags: send empty 32-byte reply
            let mut b = [0u8; 32]; b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        10 => {
            // XkbGetMap: send empty map reply.
            // Reply header: type=1, deviceID=0, seq, length=0
            // minKeyCode at b[8], maxKeyCode at b[9] (8..255 typical)
            // present=0 (no components), firstType=0, nTypes=0, ...
            let mut b = [0u8; 32]; b[0] = 1; w16(&mut b, 2, seq);
            b[8] = 8; b[9] = 255; // min/max keycode
            // present=0 → no map components → length stays 0
            with_client(fd, |c| c.send(&b));
        }
        21 => {
            // XkbGetNames: send reply with which=0 (no name components).
            // The reply MUST have the correct format or Xlib reads beyond
            // the 32-byte header, desynchronizing the XCB stream.
            // Reply: type=1, deviceID=0, seq, length=0
            //   b[8..12]  = which (CARD32) = 0 → no name components
            //   b[12..16] = minKeyCode, maxKeyCode, nTypes, groupNames
            //   b[16..20] = virtualMods, firstKey, nKeys, indicators
            //   b[20..24] = nKTLevels, ...
            let mut b = [0u8; 32]; b[0] = 1; w16(&mut b, 2, seq);
            // which=0 at offset 8 (all zeros) → Xlib reads 0 extra bytes
            b[12] = 8;  // minKeyCode
            b[13] = 255; // maxKeyCode
            with_client(fd, |c| c.send(&b));
        }
        9 | 17 | 24 => {
            // XkbListComponents / GetCompatMap / GetDeviceInfo:
            // Send minimal reply with length=0 (no extra data).
            let mut b = [0u8; 32]; b[0] = 1; w16(&mut b, 2, seq);
            with_client(fd, |c| c.send(&b));
        }
        // No-reply opcodes (1=SelectEvents, 3=DeviceBell, 5=SetControls, etc.): ignore
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
        // Window destination — blit composite to screen framebuffer
        let (wx, wy) = window_origin(fd, dst_draw);
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
        crate::gdi::blit_pixels_screen(wx + min_x, wy + min_y, bw as u32, bh as u32, &out);
    }
}
