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
use resource::{ResourceBody, ResourceTable, WindowData, PixmapData, GcData, PictureData};

/// Set to true once `init()` completes. Checked in `poll()` without taking
/// the SERVER mutex so the fast path (not yet initialized) is zero-cost.
static X11_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────────────
const MAX_CLIENTS:      usize = 8;
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
    fn send(&self, data: &[u8])   { unix::write(self.fd, data); }
    fn send_error(&self, code: u8, bad_id: u32, opcode: u8) {
        let mut p = [0u8; 32];
        p[0] = 0; p[1] = code;
        w16(&mut p, 2, self.seq);
        w32(&mut p, 4, bad_id);
        p[10] = opcode;
        self.send(&p);
    }
}

// ── Server state ─────────────────────────────────────────────────────────────

struct Server {
    initialized: bool,
    listen_fd:   u64,
    clients:     [Option<Client>; MAX_CLIENTS],
}
impl Server { const fn new() -> Self { Server { initialized: false, listen_fd: 0, clients: [const { None }; MAX_CLIENTS] } } }
unsafe impl Send for Server {}
static SERVER: Mutex<Server> = Mutex::new(Server::new());

// ── Wire helpers ─────────────────────────────────────────────────────────────

#[inline] fn r16(b: &[u8], o: usize) -> u16  { proto::read_u16le(b, o) }
#[inline] fn r32(b: &[u8], o: usize) -> u32  { proto::read_u32le(b, o) }
#[inline] fn w16(b: &mut [u8], o: usize, v: u16) { proto::write_u16le(b, o, v); }
#[inline] fn w32(b: &mut [u8], o: usize, v: u32) { proto::write_u32le(b, o, v); }

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
    SERVER.lock().listen_fd = fd;
    SERVER.lock().initialized = true;
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

    let mut pending = [u64::MAX; MAX_CLIENTS];
    { let s = SERVER.lock();
      for (i, sl) in s.clients.iter().enumerate() {
          if let Some(c) = sl { if unix::has_data(c.fd) { pending[i] = c.fd; } }
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
    unix::write(fd, &build_setup_ok());
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
        proto::OP_SELECT_INPUT          => op_select_input(fd, data),
        proto::OP_GRAB_POINTER          => op_grab_reply(fd, seq),
        proto::OP_UNGRAB_POINTER        => {}
        proto::OP_GRAB_BUTTON           => {}
        proto::OP_UNGRAB_BUTTON         => {}
        proto::OP_GRAB_KEYBOARD         => op_grab_reply(fd, seq),
        proto::OP_UNGRAB_KEYBOARD       => {}
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
        _ => { with_client(fd, |c| c.send_error(proto::ERR_REQUEST, 0, opcode)); }
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
    let mut vi = 32usize;
    if vmask & proto::CW_BACK_PIXMAP != 0 { vi += 4; }
    if vmask & proto::CW_BACK_PIXEL  != 0 { bg_pixel = r32(data, vi); vi += 4; }
    if vmask & proto::CW_BORDER_PIXMAP != 0 { vi += 4; }
    if vmask & proto::CW_BORDER_PIXEL  != 0 { vi += 4; }
    if vmask & proto::CW_EVENT_MASK    != 0 { event_mask = r32(data, vi); }
    with_client(fd, |c| {
        let mut w = WindowData::new(
            if parent == 0 { proto::ROOT_WINDOW_ID } else { parent },
            x, y, width, height,
            if depth == 0 { proto::ROOT_DEPTH } else { depth },
            bw, if class == 0 { 1 } else { class },
            if visual == 0 { proto::ROOT_VISUAL } else { visual });
        w.event_mask = event_mask; w.background_pixel = bg_pixel;
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
            if vmask & proto::CW_BACK_PIXMAP != 0 { vi += 4; }
            if vmask & proto::CW_BACK_PIXEL  != 0 { w.background_pixel = r32(data, vi); vi += 4; }
            if vmask & proto::CW_BORDER_PIXMAP != 0 { vi += 4; }
            if vmask & proto::CW_BORDER_PIXEL  != 0 { vi += 4; }
            if vmask & proto::CW_EVENT_MASK    != 0 { w.event_mask = r32(data, vi); }
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
    with_client(fd, |c| {
        if let Some(w) = c.resources.get_window_mut(wid) { w.set_property(prop, type_, fmt, pdata, mode); }
    });
}

// ── DeleteProperty (19) ──────────────────────────────────────────────────────

fn op_delete_property(fd: u64, data: &[u8]) {
    if data.len() < 12 { return; }
    let wid  = r32(data, 4);
    let atom = r32(data, 8);
    with_client(fd, |c| { if let Some(w) = c.resources.get_window_mut(wid) { w.delete_property(atom); } });
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
    with_client(fd, |c| {
        if atom == 0 {
            let mut b = [0u8;32]; b[0]=1; w16(&mut b,2,seq); c.send(&b); return;
        }
        let result = c.resources.get_window_mut(wid).and_then(|w| {
            w.get_property(atom).map(|p| {
                let mut arr = [0u8; resource::MAX_PROPERTY_DATA];
                arr[..p.len].copy_from_slice(&p.data[..p.len]);
                (p.type_, p.format, p.len, arr)
            })
        });
        match result {
            None => { let mut b=[0u8;32]; b[0]=1; w16(&mut b,2,seq); c.send(&b); }
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
        // Draw directly to screen via window coordinates
        let (wx, wy) = window_origin(fd, draw);
        let mut i = 12usize;
        while i + 8 <= data.len() {
            let rx = r16(data, i) as i32; let ry = r16(data, i+2) as i32;
            let rw = r16(data, i+4) as i32; let rh = r16(data, i+6) as i32;
            i += 8;
            crate::gdi::fill_rect_screen(wx+rx, wy+ry, rw, rh, fg & 0x00FFFFFF);
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
        "MIT-SHM"   => { b[8]=1; b[9]=65; b[10]=65; }
        "XKEYBOARD" => { b[8]=1; b[9]=66; b[10]=67; }
        "SHAPE"     => { b[8]=1; b[9]=67; b[10]=68; }
        "RENDER"    => { b[8]=1; b[9]=proto::RENDER_MAJOR_OPCODE; b[10]=0; b[11]=0; }
        _           => {}
    }
    with_client(fd, |c| c.send(&b));
}

// ── ListExtensions (99) ──────────────────────────────────────────────────────

fn op_list_extensions(fd: u64, seq: u16) {
    let names: &[&[u8]] = &[b"MIT-SHM", b"XKEYBOARD", b"SHAPE", b"RENDER"];
    let mut body: Vec<u8> = vec![];
    for &n in names { body.push(n.len() as u8); body.extend_from_slice(n); }
    let pd = proto::pad4(body.len()); while body.len() < pd { body.push(0); }
    let mut rep = vec![0u8; 32+pd];
    rep[0]=1; w16(&mut rep,2,seq); w32(&mut rep,4,(pd/4) as u32); rep[8] = names.len() as u8;
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
        proto::RENDER_QUERY_VERSION      => op_render_query_version(fd, data, seq),
        proto::RENDER_QUERY_PICT_FORMATS => op_render_query_pict_formats(fd, seq),
        proto::RENDER_CREATE_PICTURE     => op_render_create_picture(fd, data),
        proto::RENDER_CHANGE_PICTURE     => {} // no-op: we don't track picture attrs
        proto::RENDER_FREE_PICTURE       => op_render_free_picture(fd, data),
        proto::RENDER_COMPOSITE          => op_render_composite(fd, data),
        proto::RENDER_FILL_RECTANGLES    => op_render_fill_rectangles(fd, data),
        _                                => {}
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

// ── RenderFillRectangles (minor 22) ──────────────────────────────────────────
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
