//! Orbit — The AstryxOS Kernel Shell
//!
//! A feature-rich interactive shell providing system management,
//! file manipulation, process control, and networking commands.
//! Supports full line editing, history navigation, tab completion,
//! Ctrl+C/L shortcuts, and ANSI color output.

extern crate alloc;

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use crate::drivers::keyboard::KeyEvent;

/// Maximum command history entries.
const HISTORY_SIZE: usize = 32;
/// Maximum command line length.
const MAX_CMD_LEN: usize = 512;

/// Shell state.
struct ShellState {
    cwd: String,
    history: Vec<String>,
    history_idx: usize,
    /// Line editing buffer.
    line_buf: Vec<u8>,
    /// Cursor position within line_buf.
    cursor: usize,
    /// Column where the prompt ends (where input starts).
    prompt_col: usize,
    /// Saved line while navigating history.
    saved_line: Option<String>,
}

/// ANSI color escape sequences for colored output.
mod color {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
}

/// All known command names for tab completion.
const COMMANDS: &[&str] = &[
    "help", "info", "uname", "uptime", "mem", "heap", "clear", "cls",
    "echo", "pwd", "cd", "ls", "cat", "mkdir", "touch", "rm", "write",
    "append", "stat", "tree", "mv", "ln", "readlink", "chmod", "sync",
    "ps", "threads", "sched", "kill",
    "spawn", "priority", "cpus",
    "ifconfig", "ip", "ping", "ping6", "netstats", "nslookup", "resolve",
    "pipe", "history", "hexdump", "date", "whoami", "hostname", "motd",
    "panic", "reboot", "shutdown", "halt", "dns", "dhcp",
    "ob", "reg", "devmgr", "procfs", "perf", "exec",
    "beep", "play", "volume", "audio", "usb",
];

impl ShellState {
    fn new() -> Self {
        ShellState {
            cwd: String::from("/"),
            history: Vec::new(),
            history_idx: 0,
            line_buf: Vec::new(),
            cursor: 0,
            prompt_col: 0,
            saved_line: None,
        }
    }

    fn push_history(&mut self, cmd: &str) {
        if cmd.is_empty() { return; }
        if self.history.last().map_or(true, |last| last != cmd) {
            self.history.push(String::from(cmd));
            if self.history.len() > HISTORY_SIZE {
                self.history.remove(0);
            }
        }
        self.history_idx = self.history.len();
    }

    /// Clear the current input line from the display and reset buffer.
    fn clear_input_line(&mut self) {
        if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
            console.hide_cursor();
            // Move cursor to prompt start
            let (_, row) = console.cursor_pos();
            console.set_cursor_pos(self.prompt_col, row);
            // Clear from prompt to end of line
            console.clear_line_from_cursor();
        }
        self.line_buf.clear();
        self.cursor = 0;
    }

    /// Redraw the entire input line from prompt_col.
    fn redraw_input(&self) {
        if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
            console.hide_cursor();
            let (_, row) = console.cursor_pos();
            console.set_cursor_pos(self.prompt_col, row);
            console.clear_line_from_cursor();
            // Draw the line content
            if let Ok(text) = core::str::from_utf8(&self.line_buf) {
                for ch in text.chars() {
                    console.put_char(ch);
                }
            }
            // Position cursor at the correct location
            console.set_cursor_pos(self.prompt_col + self.cursor, row);
            console.show_cursor();
        }
    }

    /// Replace current line with new text and redraw.
    fn replace_line(&mut self, new_text: &str) {
        self.clear_input_line();
        self.line_buf.extend_from_slice(new_text.as_bytes());
        self.cursor = self.line_buf.len();
        self.redraw_input();
    }
}

/// Convert a serial (UART) input byte into a shell KeyEvent.
///
/// Handles plain ASCII, CR/LF, backspace/DEL, and ANSI escape sequences
/// for arrow keys, Home, End, Delete, etc.
fn serial_byte_to_key_event(byte: u8) -> Option<KeyEvent> {
    // Simple state machine for ANSI escape sequences via serial.
    // We use a tiny static buffer since escape sequences arrive byte-by-byte.
    static mut ESC_STATE: u8 = 0; // 0=normal, 1=got ESC, 2=got ESC [
    static mut ESC_PARAM: u8 = 0;

    unsafe {
        match ESC_STATE {
            0 => match byte {
                0x1B => { ESC_STATE = 1; None } // ESC
                0x0D | 0x0A => Some(KeyEvent::Enter),    // CR or LF
                0x08 | 0x7F => Some(KeyEvent::Backspace), // BS or DEL
                0x09 => Some(KeyEvent::Tab),
                0x01..=0x1A => {
                    // Ctrl+A through Ctrl+Z
                    let ch = (byte + b'a' - 1) as char;
                    Some(KeyEvent::Ctrl(ch))
                }
                0x20..=0x7E => Some(KeyEvent::Char(byte as char)),
                _ => None,
            },
            1 => {
                // After ESC
                if byte == b'[' {
                    ESC_STATE = 2;
                    ESC_PARAM = 0;
                    None
                } else {
                    ESC_STATE = 0;
                    Some(KeyEvent::Escape)
                }
            }
            2 => {
                // After ESC [
                ESC_STATE = 0;
                match byte {
                    b'A' => Some(KeyEvent::ArrowUp),
                    b'B' => Some(KeyEvent::ArrowDown),
                    b'C' => Some(KeyEvent::ArrowRight),
                    b'D' => Some(KeyEvent::ArrowLeft),
                    b'H' => Some(KeyEvent::Home),
                    b'F' => Some(KeyEvent::End),
                    b'0'..=b'9' => {
                        // Numeric parameter (e.g. ESC[3~ for Delete)
                        ESC_PARAM = byte - b'0';
                        ESC_STATE = 3;
                        None
                    }
                    _ => None,
                }
            }
            3 => {
                // After ESC [ <digit>
                ESC_STATE = 0;
                if byte == b'~' {
                    match ESC_PARAM {
                        1 => Some(KeyEvent::Home),
                        3 => Some(KeyEvent::Delete),
                        4 => Some(KeyEvent::End),
                        5 => Some(KeyEvent::PageUp),
                        6 => Some(KeyEvent::PageDown),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => { ESC_STATE = 0; None }
        }
    }
}

/// Launch the Orbit shell — never returns.
pub fn launch() -> ! {
    let mut state = ShellState::new();

    // Enable interrupts for keyboard input.
    crate::hal::enable_interrupts();

    // ── Network warmup ────────────────────────────────────────────
    // QEMU's SLIRP user-mode networking needs several seconds after boot
    // before it reliably delivers ARP replies.  Send periodic ARP probes
    // for up to 6 seconds, polling between each.  Even if warmup times
    // out, the probes prime SLIRP so subsequent ARP resolutions succeed.
    {
        let start = crate::arch::x86_64::irq::get_ticks();
        let gateway = crate::net::gateway_ip();
        let max_ticks: u64 = 600; // 6 seconds at 100 Hz
        let probe_interval: u64 = 50; // 500 ms between probes
        let mut last_probe: u64 = 0;

        while crate::arch::x86_64::irq::get_ticks() - start < max_ticks {
            let elapsed = crate::arch::x86_64::irq::get_ticks() - start;
            if elapsed - last_probe >= probe_interval || last_probe == 0 {
                crate::net::arp::send_request(gateway);
                last_probe = elapsed;
            }
            crate::net::poll();
            if crate::net::arp::lookup(gateway).is_some() {
                break;
            }
            crate::hal::halt();
        }
    }

    // Print welcome banner with colors.
    orbit_color_println!(color::BRIGHT_CYAN, "Orbit Shell v0.2 — AstryxOS");
    orbit_color_println!(color::CYAN, "Type 'help' for available commands.\n");

    print_prompt(&mut state);

    loop {
        let mut had_input = false;

        // ── Drain ALL pending PS/2 scancodes in one burst ──────────
        while let Some(scancode) = crate::arch::x86_64::irq::read_scancode() {
            if let Some(event) = crate::drivers::keyboard::process_scancode(scancode) {
                handle_key_event(&mut state, event);
                had_input = true;
            }
        }

        // ── Drain ALL pending serial bytes ─────────────────────────
        while let Some(byte) = crate::drivers::serial::try_read_byte() {
            if let Some(event) = serial_byte_to_key_event(byte) {
                handle_key_event(&mut state, event);
                had_input = true;
            }
        }

        if had_input {
            // One async display flush after ALL pending input is processed.
            crate::drivers::vmware_svga::display_notify();
        } else {
            // While idle, poll the network and blink cursor.
            crate::net::poll();

            // Blink cursor
            let ticks = crate::arch::x86_64::irq::get_ticks();
            let toggled = if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                console.blink_cursor(ticks)
            } else {
                false
            };
            if toggled {
                crate::drivers::vmware_svga::display_notify();
            }

            crate::hal::halt();
        }
    }
}

// ==================== Public GUI Terminal API ====================

/// State for a GUI-embedded orbit shell instance.
/// This is separate from the hardware shell so both can coexist.
pub struct GuiShellState {
    inner: ShellState,
}

impl GuiShellState {
    /// Create a new GUI shell state with CWD = "/".
    pub fn new() -> Self {
        Self { inner: ShellState::new() }
    }

    /// Get the current working directory.
    pub fn cwd(&self) -> &str {
        &self.inner.cwd
    }

    /// Get command history.
    pub fn history(&self) -> &[String] {
        &self.inner.history
    }

    /// Execute a command line and return the captured output as a string.
    /// All `orbit_println!` / `kprintln!` output is redirected to the
    /// returned string instead of the hardware console.
    pub fn execute_capture(&mut self, line: &str) -> String {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            self.inner.push_history(trimmed);
        }
        crate::drivers::console::begin_capture();
        execute(&mut self.inner, trimmed);
        crate::drivers::console::end_capture()
    }

    /// Get tab-completion candidates for a partial line.
    pub fn complete(&self, partial: &str) -> Vec<String> {
        let parts: Vec<&str> = partial.split_whitespace().collect();

        if parts.is_empty() || (parts.len() == 1 && !partial.ends_with(' ')) {
            let prefix = if parts.is_empty() { "" } else { parts[0] };
            COMMANDS.iter()
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| String::from(*cmd))
                .collect()
        } else {
            let arg = if partial.ends_with(' ') { "" } else { parts.last().unwrap_or(&"") };
            let (dir, prefix) = split_path_for_completion(&self.inner.cwd, arg);
            if let Ok(entries) = crate::vfs::readdir(&dir) {
                entries.into_iter()
                    .filter(|(name, _)| name.starts_with(prefix))
                    .map(|(name, ftype)| {
                        if ftype == crate::vfs::FileType::Directory {
                            alloc::format!("{}/", name)
                        } else {
                            name
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }
    }
}

// ==================== End Public GUI Terminal API ====================

/// Handle a single key event in the shell.
fn handle_key_event(state: &mut ShellState, event: KeyEvent) {
    match event {
        KeyEvent::Enter => {
            if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                console.hide_cursor();
            }
            crate::kprintln!();
            let cmd_str = core::str::from_utf8(&state.line_buf).unwrap_or("").trim();
            let cmd_copy = String::from(cmd_str);
            if !cmd_copy.is_empty() {
                state.push_history(&cmd_copy);
                execute(state, &cmd_copy);
            }
            state.line_buf.clear();
            state.cursor = 0;
            state.saved_line = None;
            print_prompt(state);
        }

        KeyEvent::Backspace => {
            if state.cursor > 0 {
                state.cursor -= 1;
                state.line_buf.remove(state.cursor);
                state.redraw_input();
            }
        }

        KeyEvent::Delete => {
            if state.cursor < state.line_buf.len() {
                state.line_buf.remove(state.cursor);
                state.redraw_input();
            }
        }

        KeyEvent::ArrowLeft => {
            if state.cursor > 0 {
                state.cursor -= 1;
                if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                    console.hide_cursor();
                    let (col, row) = console.cursor_pos();
                    if col > 0 {
                        console.set_cursor_pos(col - 1, row);
                    }
                    console.show_cursor();
                }
            }
        }

        KeyEvent::ArrowRight => {
            if state.cursor < state.line_buf.len() {
                state.cursor += 1;
                if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                    console.hide_cursor();
                    let (col, row) = console.cursor_pos();
                    console.set_cursor_pos(col + 1, row);
                    console.show_cursor();
                }
            }
        }

        KeyEvent::ArrowUp => {
            // Navigate history backward
            if !state.history.is_empty() && state.history_idx > 0 {
                if state.history_idx == state.history.len() {
                    // Save current line
                    let current = String::from(
                        core::str::from_utf8(&state.line_buf).unwrap_or("")
                    );
                    state.saved_line = Some(current);
                }
                state.history_idx -= 1;
                let entry = state.history[state.history_idx].clone();
                state.replace_line(&entry);
            }
        }

        KeyEvent::ArrowDown => {
            // Navigate history forward
            if state.history_idx < state.history.len() {
                state.history_idx += 1;
                if state.history_idx == state.history.len() {
                    // Restore saved line
                    let saved = state.saved_line.take().unwrap_or_default();
                    state.replace_line(&saved);
                } else {
                    let entry = state.history[state.history_idx].clone();
                    state.replace_line(&entry);
                }
            }
        }

        KeyEvent::Home => {
            state.cursor = 0;
            if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                console.hide_cursor();
                let (_, row) = console.cursor_pos();
                console.set_cursor_pos(state.prompt_col, row);
                console.show_cursor();
            }
        }

        KeyEvent::End => {
            state.cursor = state.line_buf.len();
            if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                console.hide_cursor();
                let (_, row) = console.cursor_pos();
                console.set_cursor_pos(state.prompt_col + state.line_buf.len(), row);
                console.show_cursor();
            }
        }

        KeyEvent::Ctrl('c') => {
            // Cancel current line
            crate::kprintln!("^C");
            state.line_buf.clear();
            state.cursor = 0;
            state.saved_line = None;
            state.history_idx = state.history.len();
            print_prompt(state);
        }

        KeyEvent::Ctrl('l') => {
            // Clear screen
            if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                console.clear();
            }
            print_prompt(state);
            // Redraw current input
            state.redraw_input();
        }

        KeyEvent::Ctrl('a') => {
            // Move to start of line
            state.cursor = 0;
            if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                console.hide_cursor();
                let (_, row) = console.cursor_pos();
                console.set_cursor_pos(state.prompt_col, row);
                console.show_cursor();
            }
        }

        KeyEvent::Ctrl('e') => {
            // Move to end of line
            state.cursor = state.line_buf.len();
            if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                console.hide_cursor();
                let (_, row) = console.cursor_pos();
                console.set_cursor_pos(state.prompt_col + state.line_buf.len(), row);
                console.show_cursor();
            }
        }

        KeyEvent::Ctrl('u') => {
            // Kill line (clear from cursor to start)
            state.line_buf.drain(..state.cursor);
            state.cursor = 0;
            state.redraw_input();
        }

        KeyEvent::Ctrl('k') => {
            // Kill from cursor to end
            state.line_buf.truncate(state.cursor);
            state.redraw_input();
        }

        KeyEvent::Ctrl('w') => {
            // Delete previous word
            if state.cursor > 0 {
                let mut pos = state.cursor;
                // Skip trailing spaces
                while pos > 0 && state.line_buf[pos - 1] == b' ' {
                    pos -= 1;
                }
                // Skip word characters
                while pos > 0 && state.line_buf[pos - 1] != b' ' {
                    pos -= 1;
                }
                state.line_buf.drain(pos..state.cursor);
                state.cursor = pos;
                state.redraw_input();
            }
        }

        KeyEvent::Tab => {
            // Tab completion
            let line = core::str::from_utf8(&state.line_buf).unwrap_or("").to_string();
            tab_complete(state, &line);
        }

        KeyEvent::Char(ch) => {
            if state.line_buf.len() < MAX_CMD_LEN - 1 {
                state.line_buf.insert(state.cursor, ch as u8);
                state.cursor += 1;
                // If inserting at end, just draw the character
                if state.cursor == state.line_buf.len() {
                    if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
                        console.hide_cursor();
                        console.put_char(ch);
                        console.show_cursor();
                    }
                } else {
                    // Inserting in the middle — redraw from cursor
                    state.redraw_input();
                }
            }
        }

        _ => {} // Ignore unhandled keys
    }
}

/// Tab completion for commands and file paths.
fn tab_complete(state: &mut ShellState, line: &str) {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.is_empty() || (parts.len() == 1 && !line.ends_with(' ')) {
        // Complete command name
        let prefix = if parts.is_empty() { "" } else { parts[0] };
        let matches: Vec<&&str> = COMMANDS.iter()
            .filter(|cmd| cmd.starts_with(prefix))
            .collect();

        if matches.len() == 1 {
            let completion = matches[0];
            state.replace_line(&alloc::format!("{} ", completion));
        } else if matches.len() > 1 {
            // Show all matches
            crate::kprintln!();
            for m in &matches {
                crate::kprint!("{}  ", m);
            }
            crate::kprintln!();
            print_prompt(state);
            state.redraw_input();
        }
    } else {
        // Complete file path (last argument)
        let arg = if line.ends_with(' ') { "" } else { parts.last().unwrap_or(&"") };
        let (dir, prefix) = split_path_for_completion(&state.cwd, arg);

        if let Ok(entries) = crate::vfs::readdir(&dir) {
            let matches: Vec<(String, crate::vfs::FileType)> = entries
                .into_iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .collect();

            if matches.len() == 1 {
                let (name, ftype) = &matches[0];
                let suffix = if *ftype == crate::vfs::FileType::Directory { "/" } else { " " };
                let base = if arg.contains('/') {
                    let slash_pos = arg.rfind('/').unwrap_or(0);
                    &arg[..=slash_pos]
                } else { "" };
                // Rebuild the line replacing the last argument
                let before_last = if parts.len() <= 1 || line.ends_with(' ') {
                    String::from(line)
                } else {
                    let last_start = line.rfind(arg).unwrap_or(line.len());
                    String::from(&line[..last_start])
                };
                let completed = alloc::format!("{}{}{}{}", before_last, base, name, suffix);
                state.replace_line(&completed);
            } else if matches.len() > 1 {
                crate::kprintln!();
                for (name, ftype) in &matches {
                    let ind = if *ftype == crate::vfs::FileType::Directory { "/" } else { "" };
                    crate::kprint!("{}{}  ", name, ind);
                }
                crate::kprintln!();
                print_prompt(state);
                state.redraw_input();
            }
        }
    }
}

/// Split a path argument into (directory, filename_prefix) for tab completion.
fn split_path_for_completion<'a>(cwd: &str, arg: &'a str) -> (String, &'a str) {
    if let Some(pos) = arg.rfind('/') {
        let dir_part = &arg[..=pos];
        let prefix = &arg[pos + 1..];
        (resolve_path(cwd, dir_part), prefix)
    } else {
        (String::from(cwd), arg)
    }
}

fn print_prompt(state: &mut ShellState) {
    // Colorized prompt: "astryx" in green, ":" normal, CWD in blue, ">" in white
    crate::kprint!("{}{}{}{}{}{}{}{} ",
        color::BOLD, color::BRIGHT_GREEN, "astryx",
        color::RESET, color::BLUE, state.cwd,
        color::RESET, ">");
    // Record where input starts
    if let Some(ref console) = *crate::drivers::console::CONSOLE.lock() {
        state.prompt_col = console.cursor_pos().0;
    }
    state.line_buf.clear();
    state.cursor = 0;
    // Show cursor
    if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
        console.show_cursor();
    }
}

/// Parse and execute a command line.
fn execute(state: &mut ShellState, line: &str) {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.is_empty() { return; }

    match parts[0] {
        "help" => cmd_help(),
        "info" | "uname" => cmd_info(),
        "uptime" => cmd_uptime(),
        "mem" => cmd_mem(),
        "heap" => cmd_heap(),
        "clear" | "cls" => cmd_clear(),
        "echo" => cmd_echo(line),
        "pwd" => orbit_println!("{}", state.cwd),
        "cd" => cmd_cd(state, &parts),
        "ls" => cmd_ls(state, &parts),
        "cat" => cmd_cat(state, &parts),
        "mkdir" => cmd_mkdir(state, &parts),
        "touch" => cmd_touch(state, &parts),
        "rm" => cmd_rm(state, &parts),
        "write" => cmd_write(state, line, &parts),
        "append" => cmd_append(state, line, &parts),
        "stat" => cmd_stat(state, &parts),
        "tree" => cmd_tree(state, &parts),
        "mv" => cmd_mv(state, &parts),
        "ln" => cmd_ln(state, &parts),
        "readlink" => cmd_readlink(state, &parts),
        "chmod" => cmd_chmod(state, &parts),
        "sync" => cmd_sync(),
        "ps" => cmd_ps(),
        "threads" => cmd_threads(),
        "sched" => cmd_sched(),
        "kill" => cmd_kill(&parts),
        "spawn" => cmd_spawn(&parts),
        "priority" => cmd_priority(&parts),
        "cpus" => cmd_cpus(),
        "ifconfig" | "ip" => cmd_ifconfig(),
        "ping" => cmd_ping(&parts),
        "ping6" => cmd_ping6(&parts),
        "netstats" => cmd_netstats(),
        "nslookup" | "resolve" => cmd_nslookup(&parts),
        "dns" => cmd_dns(&parts),
        "pipe" => cmd_pipe(&parts),
        "history" => cmd_history(state),
        "hexdump" => cmd_hexdump(state, &parts),
        "date" => cmd_date(),
        "whoami" => orbit_println!("root"),
        "hostname" => cmd_hostname(),
        "motd" => cmd_motd(),
        "ob" => cmd_ob(&parts),
        "reg" => cmd_reg(&parts),
        "devmgr" => cmd_devmgr(),
        "procfs" => cmd_procfs(&parts),
        "perf" => cmd_perf(&parts),
        "exec" => cmd_exec(&parts),
        "beep" => cmd_beep(),
        "play" => cmd_play(&parts),
        "volume" => cmd_volume(&parts),
        "audio" => cmd_audio(),
        "usb" => cmd_usb(),
        "desktop" => cmd_desktop(),
        "panic" => panic!("User-triggered kernel panic"),
        "reboot" => {
            orbit_println!("Rebooting...");
            unsafe { crate::hal::outb(0x64, 0xFE); }
        }
        "shutdown" | "halt" => {
            orbit_println!("Halting system...");
            crate::hal::disable_interrupts();
            loop { crate::hal::halt(); }
        }
        _ => {
            // Bare-path execution: /disk/bin/foo or ./foo runs without `exec` prefix.
            let cmd0 = parts[0];
            if cmd0.starts_with('/') || cmd0.starts_with("./") {
                let mut argv: alloc::vec::Vec<&str> = alloc::vec!["exec"];
                argv.extend_from_slice(&parts);
                cmd_exec(&argv);
            } else {
                crate::kprint!("{}orbit: command not found: '{}'{}\n",
                    color::RED, cmd0, color::RESET);
            }
        }
    }
}

// ==================== Command Implementations ====================

fn cmd_beep() {
    if !crate::drivers::ac97::is_available() {
        orbit_println!("{}No audio device available{}", color::RED, color::RESET);
        return;
    }
    orbit_println!("{}♪ Beep!{}", color::BRIGHT_CYAN, color::RESET);
    crate::drivers::ac97::beep();
}

fn cmd_play(parts: &[&str]) {
    if !crate::drivers::ac97::is_available() {
        orbit_println!("{}No audio device available{}", color::RED, color::RESET);
        return;
    }
    // play <freq> [duration_ms] [amplitude]
    if parts.len() < 2 {
        orbit_println!("Usage: play <freq_hz> [duration_ms] [amplitude 0-100]");
        orbit_println!("  play 440        — A4 for 500ms");
        orbit_println!("  play 261 1000   — Middle C for 1 second");
        orbit_println!("  play chime      — Startup chime");
        return;
    }
    if parts[1] == "chime" {
        orbit_println!("{}♪ Playing startup chime...{}", color::BRIGHT_CYAN, color::RESET);
        crate::drivers::ac97::startup_chime();
        return;
    }
    let freq: u32 = parts[1].parse().unwrap_or(440);
    let dur: u32 = if parts.len() > 2 { parts[2].parse().unwrap_or(500) } else { 500 };
    let amp: f32 = if parts.len() > 3 {
        let pct: u32 = parts[3].parse().unwrap_or(50);
        pct as f32 / 100.0
    } else {
        0.5
    };
    orbit_println!("{}♪ Playing {} Hz for {} ms (amp={:.0}%){}", color::BRIGHT_CYAN, freq, dur, amp * 100.0, color::RESET);
    crate::drivers::ac97::play_tone(freq, dur, amp);
}

fn cmd_volume(parts: &[&str]) {
    if !crate::drivers::ac97::is_available() {
        orbit_println!("{}No audio device available{}", color::RED, color::RESET);
        return;
    }
    if parts.len() < 2 {
        let (l, r) = crate::drivers::ac97::get_volume();
        let pct_l = ((63 - l) as u32 * 100) / 63;
        let pct_r = ((63 - r) as u32 * 100) / 63;
        orbit_println!("Volume: L={}% R={}% (raw L={} R={}, 0=max 63=mute)", pct_l, pct_r, l, r);
        return;
    }
    let pct: u32 = parts[1].parse().unwrap_or(100);
    let raw = ((100u32.saturating_sub(pct)) * 63 / 100) as u8;
    crate::drivers::ac97::set_volume(raw, raw);
    orbit_println!("Volume set to {}% (raw={})", pct, raw);
}

fn cmd_audio() {
    orbit_println!("{}Audio Subsystem{}", color::BOLD, color::RESET);
    if crate::drivers::ac97::is_available() {
        let rate = crate::drivers::ac97::sample_rate();
        let (l, r) = crate::drivers::ac97::get_volume();
        let playing = crate::drivers::ac97::is_playing();
        let (civ, lvi, picb) = crate::drivers::ac97::status();
        orbit_println!("  Device:       AC97 (Intel ICH)");
        orbit_println!("  Sample Rate:  {} Hz", rate);
        orbit_println!("  Volume:       L={} R={} (0=max, 63=mute)", l, r);
        orbit_println!("  Playing:      {}", if playing { "yes" } else { "no" });
        orbit_println!("  DMA Status:   CIV={} LVI={} PICB={}", civ, lvi, picb);
    } else {
        orbit_println!("  {}No audio device detected{}", color::RED, color::RESET);
    }
}

fn cmd_usb() {
    orbit_println!("{}USB Subsystem{}", color::BOLD, color::RESET);
    let controllers = crate::drivers::usb::list_controllers();
    if controllers.is_empty() {
        orbit_println!("  {}No USB controllers detected{}", color::RED, color::RESET);
    } else {
        orbit_println!("  Controllers: {}", controllers.len());
        for (i, info) in controllers.iter().enumerate() {
            orbit_println!("  [{}] {} ({:04x}:{:04x}) at {:02x}:{:02x}.{} irq={}",
                i, info.controller_type, info.vendor_id, info.device_id,
                info.bus, info.device, info.function, info.irq);
        }
    }
}

fn cmd_desktop() {
    if !crate::gui::is_initialized() {
        orbit_println!("{}GUI not initialized (no SVGA framebuffer){}", color::RED, color::RESET);
        return;
    }
    orbit_println!("Launching desktop...");
    crate::gui::desktop::launch_desktop();
    crate::gui::desktop::run_desktop_loop();
}

fn cmd_help() {
    orbit_println!("{}{}Orbit Shell v0.2 — AstryxOS{}", color::BOLD, color::BRIGHT_CYAN, color::RESET);
    orbit_println!("");
    orbit_println!("{}System:{}", color::YELLOW, color::RESET);
    orbit_println!("  help          Show this help");
    orbit_println!("  info / uname  System information");
    orbit_println!("  uptime        System uptime");
    orbit_println!("  mem           Physical memory stats");
    orbit_println!("  heap          Kernel heap stats");
    orbit_println!("  date          Current tick-based time");
    orbit_println!("  whoami        Current user");
    orbit_println!("  hostname      Show hostname");
    orbit_println!("  motd          Message of the day");
    orbit_println!("  clear / cls   Clear screen");
    orbit_println!("  history       Command history");
    orbit_println!("  reboot        Reboot system");
    orbit_println!("  shutdown      Halt system");
    orbit_println!("");
    orbit_println!("{}Files:{}", color::YELLOW, color::RESET);
    orbit_println!("  pwd           Print working directory");
    orbit_println!("  cd <dir>      Change directory");
    orbit_println!("  ls [path]     List directory");
    orbit_println!("  cat <file>    Display file contents");
    orbit_println!("  hexdump <f>   Hex dump of file");
    orbit_println!("  touch <file>  Create empty file");
    orbit_println!("  mkdir <dir>   Create directory");
    orbit_println!("  rm <path>     Remove file/directory");
    orbit_println!("  write <f> <t> Write text to file");
    orbit_println!("  append <f><t> Append text to file");
    orbit_println!("  stat <path>   File information");
    orbit_println!("  tree [path]   Directory tree");
    orbit_println!("  mv <s> <d>    Rename/move file");
    orbit_println!("  ln -s <t> <l> Create symbolic link");
    orbit_println!("  readlink <l>  Read symlink target");
    orbit_println!("  chmod <m> <f> Change permissions (octal)");
    orbit_println!("  sync          Flush filesystem caches");
    orbit_println!("  echo <text>   Echo text");
    orbit_println!("");
    orbit_println!("{}Processes & Threads:{}", color::YELLOW, color::RESET);
    orbit_println!("  ps              List processes");
    orbit_println!("  threads         List all threads with state & priority");
    orbit_println!("  sched           Scheduler statistics");
    orbit_println!("  kill <tid>      Terminate thread");
    orbit_println!("  spawn [name]    Spawn a test kernel thread");
    orbit_println!("  priority <tid> [n]  Get/set thread priority (0-31)");
    orbit_println!("");
    orbit_println!("{}Network:{}", color::YELLOW, color::RESET);
    orbit_println!("  ifconfig / ip Network interface info");
    orbit_println!("  ping <host>   Send ICMP echo (IP or hostname)");
    orbit_println!("  netstats      Network statistics");
    orbit_println!("  nslookup <h>  DNS lookup");
    orbit_println!("  dns [server]  Show/set DNS server");
    orbit_println!("");
    orbit_println!("{}NT Kernel:{}", color::YELLOW, color::RESET);
    orbit_println!("  ob [path]     Object Manager namespace");
    orbit_println!("  reg <cmd>     Registry operations");
    orbit_println!("  devmgr        Device Manager");
    orbit_println!("  procfs <path> /proc filesystem");
    orbit_println!("");
    orbit_println!("{}Performance:{}", color::YELLOW, color::RESET);
    orbit_println!("  perf          Full performance metrics");
    orbit_println!("  perf irq      Interrupt vector counts");
    orbit_println!("  perf syscalls Syscall invocation counts");
    orbit_println!("  perf mem      Heap allocation metrics");
    orbit_println!("");
    orbit_println!("{}User-mode:{}", color::YELLOW, color::RESET);
    orbit_println!("  exec [name]   Run ELF binary in Ring 3 (default: hello)");
    orbit_println!("");
    orbit_println!("{}GUI:{}", color::YELLOW, color::RESET);
    orbit_println!("  desktop       Launch graphical desktop");
    orbit_println!("");
    orbit_println!("{}IPC:{}", color::YELLOW, color::RESET);
    orbit_println!("  pipe test     Test pipe read/write");
    orbit_println!("");
    orbit_println!("{}Shortcuts:{}", color::YELLOW, color::RESET);
    orbit_println!("  Ctrl+C        Cancel current line");
    orbit_println!("  Ctrl+L        Clear screen");
    orbit_println!("  Ctrl+A/E      Move to start/end of line");
    orbit_println!("  Ctrl+U/K      Kill to start/end of line");
    orbit_println!("  Ctrl+W        Delete previous word");
    orbit_println!("  Up/Down       Navigate command history");
    orbit_println!("  Left/Right    Move cursor in line");
    orbit_println!("  Home/End      Move to start/end of line");
    orbit_println!("  Tab           Auto-complete command/path");
}

fn cmd_info() {
    orbit_println!("AstryxOS — Aether Kernel v0.1");
    orbit_println!("Architecture: x86_64 (UEFI)");
    orbit_println!("Scheduler:    CoreSched (round-robin, preemptive)");
    orbit_println!("Processes:    {}", crate::proc::process_count());
    orbit_println!("Threads:      {}", crate::proc::thread_count());
    let ticks = crate::arch::x86_64::irq::get_ticks();
    orbit_println!("Uptime:       {} seconds", ticks / 100);
}

fn cmd_uptime() {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let secs = ticks / 100;
    let mins = secs / 60;
    let hours = mins / 60;
    orbit_println!("up {} hours, {} minutes, {} seconds ({} ticks)",
        hours, mins % 60, secs % 60, ticks);
}

fn cmd_mem() {
    let (total, used) = crate::mm::pmm::stats();
    orbit_println!("Physical Memory:");
    orbit_println!("  Total: {:>6} pages ({:>4} MiB)", total, total * 4 / 1024);
    orbit_println!("  Used:  {:>6} pages ({:>4} MiB)", used, used * 4 / 1024);
    orbit_println!("  Free:  {:>6} pages ({:>4} MiB)", total - used, (total - used) * 4 / 1024);
    let pct = if total > 0 { (used * 100) / total } else { 0 };
    orbit_println!("  Usage: {}%", pct);
}

fn cmd_heap() {
    let (total, allocated, free) = crate::mm::heap::stats();
    orbit_println!("Kernel Heap:");
    orbit_println!("  Total:     {:>8} bytes ({} KiB)", total, total / 1024);
    orbit_println!("  Allocated: {:>8} bytes ({} KiB)", allocated, allocated / 1024);
    orbit_println!("  Free:      {:>8} bytes ({} KiB)", free, free / 1024);
    let pct = if total > 0 { (allocated * 100) / total } else { 0 };
    orbit_println!("  Usage: {}%", pct);
}

fn cmd_clear() {
    if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
        console.clear();
    }
}

fn cmd_echo(line: &str) {
    let text = line.strip_prefix("echo").unwrap_or("").trim_start();
    orbit_println!("{}", text);
}

fn cmd_cd(state: &mut ShellState, parts: &[&str]) {
    let target = if parts.len() < 2 { "/" } else { parts[1] };
    let new_path = resolve_path(&state.cwd, target);

    // Verify it's a directory.
    match crate::vfs::stat(&new_path) {
        Ok(st) => {
            match st.file_type {
                crate::vfs::FileType::Directory => {
                    state.cwd = new_path;
                }
                _ => orbit_println!("cd: {}: Not a directory", target),
            }
        }
        Err(e) => orbit_println!("cd: {}: {:?}", target, e),
    }
}

fn cmd_ls(state: &ShellState, parts: &[&str]) {
    let path = if parts.len() > 1 {
        resolve_path(&state.cwd, parts[1])
    } else {
        state.cwd.clone()
    };

    match crate::vfs::readdir(&path) {
        Ok(entries) => {
            for (name, ftype) in &entries {
                let indicator = match ftype {
                    crate::vfs::FileType::Directory => "/",
                    crate::vfs::FileType::SymLink => "@",
                    crate::vfs::FileType::Pipe => "|",
                    _ => "",
                };
                let type_char = match ftype {
                    crate::vfs::FileType::Directory => "d",
                    crate::vfs::FileType::RegularFile => "-",
                    crate::vfs::FileType::SymLink => "l",
                    crate::vfs::FileType::Pipe => "p",
                    _ => "?",
                };
                // Try to get size.
                let full_path = if path == "/" {
                    alloc::format!("/{}", name)
                } else {
                    alloc::format!("{}/{}", path, name)
                };
                let size = crate::vfs::stat(&full_path)
                    .map(|s| s.size)
                    .unwrap_or(0);
                orbit_println!("  {} {:>8}  {}{}", type_char, size, name, indicator);
            }
            if entries.is_empty() {
                orbit_println!("  (empty)");
            }
        }
        Err(e) => orbit_println!("ls: {}: {:?}", path, e),
    }
}

fn cmd_cat(state: &ShellState, parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: cat <file>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    match crate::vfs::read_file(&path) {
        Ok(data) => {
            if let Ok(text) = core::str::from_utf8(&data) {
                // Print without trailing newline if already present.
                if text.ends_with('\n') {
                    crate::kprint!("{}", text);
                } else {
                    orbit_println!("{}", text);
                }
            } else {
                orbit_println!("(binary data, {} bytes)", data.len());
            }
        }
        Err(e) => orbit_println!("cat: {}: {:?}", parts[1], e),
    }
}

fn cmd_mkdir(state: &ShellState, parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: mkdir <path>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    match crate::vfs::mkdir(&path) {
        Ok(()) => {}
        Err(e) => orbit_println!("mkdir: {}: {:?}", parts[1], e),
    }
}

fn cmd_touch(state: &ShellState, parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: touch <file>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    match crate::vfs::create_file(&path) {
        Ok(()) => {}
        Err(e) => orbit_println!("touch: {}: {:?}", parts[1], e),
    }
}

fn cmd_rm(state: &ShellState, parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: rm <path>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    match crate::vfs::remove(&path) {
        Ok(()) => {}
        Err(e) => orbit_println!("rm: {}: {:?}", parts[1], e),
    }
}

fn cmd_write(state: &ShellState, line: &str, parts: &[&str]) {
    if parts.len() < 3 {
        orbit_println!("Usage: write <file> <text>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    // Get everything after the second word as text.
    let text_start = line.find(parts[1]).unwrap_or(0) + parts[1].len();
    let text = line[text_start..].trim_start();
    match crate::vfs::write_file(&path, text.as_bytes()) {
        Ok(n) => orbit_println!("Wrote {} bytes to {}", n, path),
        Err(e) => orbit_println!("write: {}: {:?}", path, e),
    }
}

fn cmd_append(state: &ShellState, line: &str, parts: &[&str]) {
    if parts.len() < 3 {
        orbit_println!("Usage: append <file> <text>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    let text_start = line.find(parts[1]).unwrap_or(0) + parts[1].len();
    let text = line[text_start..].trim_start();
    match crate::vfs::append_file(&path, text.as_bytes()) {
        Ok(n) => orbit_println!("Appended {} bytes to {}", n, path),
        Err(e) => orbit_println!("append: {}: {:?}", path, e),
    }
}

fn cmd_stat(state: &ShellState, parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: stat <path>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    match crate::vfs::stat(&path) {
        Ok(st) => {
            orbit_println!("  File: {}", path);
            orbit_println!("  Type: {:?}", st.file_type);
            orbit_println!("  Size: {} bytes", st.size);
            orbit_println!("  Inode: {}", st.inode);
            orbit_println!("  Perms: 0o{:o}", st.permissions);
            if st.created != 0 {
                orbit_println!("  Created:  {} ticks", st.created);
            }
            if st.modified != 0 {
                orbit_println!("  Modified: {} ticks", st.modified);
            }
            if st.accessed != 0 {
                orbit_println!("  Accessed: {} ticks", st.accessed);
            }
        }
        Err(e) => orbit_println!("stat: {}: {:?}", path, e),
    }
}

fn cmd_mv(state: &ShellState, parts: &[&str]) {
    if parts.len() < 3 {
        orbit_println!("Usage: mv <source> <destination>");
        return;
    }
    let src = resolve_path(&state.cwd, parts[1]);
    let dst = resolve_path(&state.cwd, parts[2]);
    match crate::vfs::rename(&src, &dst) {
        Ok(()) => orbit_println!("Renamed {} -> {}", src, dst),
        Err(e) => orbit_println!("mv: {:?}", e),
    }
}

fn cmd_ln(state: &ShellState, parts: &[&str]) {
    if parts.len() < 3 || parts[1] != "-s" {
        orbit_println!("Usage: ln -s <target> <link_name>");
        return;
    }
    if parts.len() < 4 {
        orbit_println!("Usage: ln -s <target> <link_name>");
        return;
    }
    let target = parts[2];
    let link = resolve_path(&state.cwd, parts[3]);
    match crate::vfs::symlink(&link, target) {
        Ok(()) => orbit_println!("Created symlink {} -> {}", link, target),
        Err(e) => orbit_println!("ln: {:?}", e),
    }
}

fn cmd_readlink(state: &ShellState, parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: readlink <symlink>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    match crate::vfs::readlink(&path) {
        Ok(target) => orbit_println!("{}", target),
        Err(e) => orbit_println!("readlink: {:?}", e),
    }
}

fn cmd_chmod(state: &ShellState, parts: &[&str]) {
    if parts.len() < 3 {
        orbit_println!("Usage: chmod <mode> <path>");
        return;
    }
    let mode = match u32::from_str_radix(parts[1], 8) {
        Ok(m) => m,
        Err(_) => {
            orbit_println!("chmod: invalid mode '{}' (use octal, e.g. 755)", parts[1]);
            return;
        }
    };
    let path = resolve_path(&state.cwd, parts[2]);
    match crate::vfs::chmod(&path, mode) {
        Ok(()) => orbit_println!("Changed mode of {} to 0o{:o}", path, mode),
        Err(e) => orbit_println!("chmod: {:?}", e),
    }
}

fn cmd_sync() {
    crate::vfs::sync_all();
    orbit_println!("Filesystem synced");
}

fn cmd_tree(state: &ShellState, parts: &[&str]) {
    let path = if parts.len() > 1 {
        resolve_path(&state.cwd, parts[1])
    } else {
        state.cwd.clone()
    };
    orbit_println!("{}", path);
    print_tree(&path, "", true);
}

fn print_tree(path: &str, prefix: &str, _is_last: bool) {
    if let Ok(entries) = crate::vfs::readdir(path) {
        let count = entries.len();
        for (i, (name, ftype)) in entries.iter().enumerate() {
            let is_last = i == count - 1;
            let connector = if is_last { "└── " } else { "├── " };
            let indicator = if *ftype == crate::vfs::FileType::Directory { "/" } else { "" };
            orbit_println!("{}{}{}{}", prefix, connector, name, indicator);

            if *ftype == crate::vfs::FileType::Directory {
                let child_path = if path == "/" {
                    alloc::format!("/{}", name)
                } else {
                    alloc::format!("{}/{}", path, name)
                };
                let child_prefix = alloc::format!("{}{}", prefix, if is_last { "    " } else { "│   " });
                print_tree(&child_path, &child_prefix, is_last);
            }
        }
    }
}

fn cmd_hexdump(state: &ShellState, parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: hexdump <file>");
        return;
    }
    let path = resolve_path(&state.cwd, parts[1]);
    match crate::vfs::read_file(&path) {
        Ok(data) => {
            let max_bytes = 256.min(data.len());
            for row in (0..max_bytes).step_by(16) {
                crate::kprint!("{:08x}  ", row);
                for col in 0..16 {
                    if row + col < max_bytes {
                        crate::kprint!("{:02x} ", data[row + col]);
                    } else {
                        crate::kprint!("   ");
                    }
                    if col == 7 { crate::kprint!(" "); }
                }
                crate::kprint!(" |");
                for col in 0..16 {
                    if row + col < max_bytes {
                        let b = data[row + col];
                        if b >= 0x20 && b <= 0x7E {
                            crate::kprint!("{}", b as char);
                        } else {
                            crate::kprint!(".");
                        }
                    }
                }
                crate::kprintln!("|");
            }
            if data.len() > max_bytes {
                orbit_println!("... ({} more bytes)", data.len() - max_bytes);
            }
        }
        Err(e) => orbit_println!("hexdump: {}: {:?}", parts[1], e),
    }
}

fn cmd_ps() {
    orbit_println!("  {:>4}  {:>4}  {:<10}  {}", "PID", "PPID", "State", "Name");
    orbit_println!("  {:>4}  {:>4}  {:<10}  {}", "---", "----", "-----", "----");
    // Query all processes.
    let count = crate::proc::process_count();
    for pid in 0..count as u64 + 2 {
        if let Some(name) = crate::proc::process_name(pid) {
            orbit_println!("  {:>4}  {:>4}  {:<10}  {}", pid, 0, "Active", name);
        }
    }
}

fn cmd_threads() {
    let current = crate::proc::current_tid();
    orbit_println!("  {:>4}  {:>4}  {:<8}  {:>3}  {}", "TID", "PID", "State", "Pri", "Name");
    orbit_println!("  {:>4}  {:>4}  {:<8}  {:>3}  {}", "---", "---", "-----", "---", "----");
    let threads = crate::proc::THREAD_TABLE.lock();
    for t in threads.iter() {
        let state = match t.state {
            crate::proc::ThreadState::Ready => "Ready",
            crate::proc::ThreadState::Running => "Running",
            crate::proc::ThreadState::Blocked => "Blocked",
            crate::proc::ThreadState::Sleeping => "Sleep",
            crate::proc::ThreadState::Dead => "Dead",
        };
        let len = t.name.iter().position(|&b| b == 0).unwrap_or(t.name.len());
        let name = core::str::from_utf8(&t.name[..len]).unwrap_or("?");
        let marker = if t.tid == current { "*" } else { " " };
        orbit_println!("{}{:>4}  {:>4}  {:<8}  {:>3}  {}", marker, t.tid, t.pid, state, t.priority, name);
    }
    orbit_println!("  {} threads total, current TID: {}", threads.len(), current);
}

fn cmd_sched() {
    let (ready, total) = crate::sched::stats();
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let cpus = crate::arch::x86_64::apic::cpu_count();
    orbit_println!("Scheduler Statistics (CoreSched):");
    orbit_println!("  Algorithm:        Priority-based (preemptive, 0-31)");
    orbit_println!("  Time quantum:     5 ticks (50ms)");
    orbit_println!("  Ready threads:    {}/{}", ready, total);
    orbit_println!("  Timer ticks:      {}", ticks);
    orbit_println!("  Online CPUs:      {}", cpus);
    orbit_println!("  True blocking:    enabled");
}

fn cmd_cpus() {
    let cpus = crate::arch::x86_64::apic::cpu_count();
    let bsp = crate::arch::x86_64::apic::current_apic_id();
    let apic_on = crate::arch::x86_64::apic::is_enabled();
    orbit_println!("CPU Information:");
    orbit_println!("  APIC:        {}", if apic_on { "enabled" } else { "disabled" });
    orbit_println!("  Online CPUs: {}", cpus);
    orbit_println!("  Current CPU: APIC ID {}", bsp);
    orbit_println!("  Max CPUs:    {}", crate::arch::x86_64::apic::MAX_CPUS);
}

fn cmd_kill(parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: kill <tid>");
        return;
    }
    match parts[1].parse::<u64>() {
        Ok(tid) => {
            if tid == 0 {
                orbit_println!("kill: cannot kill idle thread");
            } else {
                // Mark the target thread as Dead.
                let found = {
                    let mut threads = crate::proc::THREAD_TABLE.lock();
                    if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                        t.state = crate::proc::ThreadState::Dead;
                        t.exit_code = 137; // SIGKILL
                        true
                    } else {
                        false
                    }
                };
                if found {
                    orbit_println!("Killed thread TID {}", tid);
                } else {
                    orbit_println!("kill: thread {} not found", tid);
                }
            }
        }
        Err(_) => orbit_println!("kill: invalid TID"),
    }
}

/// Spawn a test kernel thread.
fn cmd_spawn(parts: &[&str]) {
    let name = if parts.len() > 1 { parts[1] } else { "test" };
    let pid = crate::proc::current_pid();
    match crate::proc::create_thread(pid, name, test_thread_entry as *const () as u64) {
        Some(tid) => orbit_println!("Spawned thread '{}' TID {} in PID {}", name, tid, pid),
        None => orbit_println!("spawn: failed to create thread"),
    }
}

/// Test thread entry point for `spawn` command.
fn test_thread_entry() {
    let tid = crate::proc::current_tid();
    crate::serial_println!("[test_thread] TID {} started", tid);
    // Run for 50 ticks (~500ms), yielding each iteration.
    for i in 0..50 {
        crate::sched::yield_cpu();
        let _ = i; // prevent optimization
    }
    crate::serial_println!("[test_thread] TID {} finished", tid);
    crate::proc::exit_thread(0);
}

/// View or set thread priority.
fn cmd_priority(parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: priority <tid> [level]");
        orbit_println!("  Levels: 0 (idle) .. 8 (normal) .. 15 (high) .. 31 (max)");
        return;
    }
    let tid: u64 = match parts[1].parse() {
        Ok(v) => v,
        Err(_) => { orbit_println!("priority: invalid TID"); return; }
    };
    if parts.len() >= 3 {
        let level: u8 = match parts[2].parse() {
            Ok(v) => v,
            Err(_) => { orbit_println!("priority: invalid level"); return; }
        };
        match crate::proc::set_thread_priority(tid, level) {
            Some(prev) => orbit_println!("Thread {} priority: {} -> {}", tid, prev, level.min(31)),
            None => orbit_println!("priority: thread {} not found", tid),
        }
    } else {
        match crate::proc::get_thread_priority(tid) {
            Some(p) => orbit_println!("Thread {} priority: {}", tid, p),
            None => orbit_println!("priority: thread {} not found", tid),
        }
    }
}

fn cmd_ifconfig() {
    let mac = crate::net::our_mac();
    let ip = crate::net::our_ip();
    let gw = crate::net::gateway_ip();
    let mask = crate::net::subnet_mask();
    orbit_println!("eth0:");
    orbit_println!("  HWaddr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    orbit_println!("  inet {}.{}.{}.{}  netmask {}.{}.{}.{}",
        ip[0], ip[1], ip[2], ip[3],
        mask[0], mask[1], mask[2], mask[3]);
    orbit_println!("  gateway {}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
    let (rx_pkts, tx_pkts, rx_bytes, tx_bytes) = crate::net::stats();
    orbit_println!("  RX packets:{} bytes:{}", rx_pkts, rx_bytes);
    orbit_println!("  TX packets:{} bytes:{}", tx_pkts, tx_bytes);
}

fn cmd_ping(parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: ping <ip or hostname>");
        return;
    }

    // Try to parse as IP address first, then try DNS resolution
    let target = parts[1];
    let ip = if let Some(parsed) = parse_ipv4(target) {
        parsed
    } else {
        // Try DNS resolution
        orbit_println!("Resolving {}...", target);
        match crate::net::dns::resolve(target) {
            Some(resolved) => {
                orbit_println!("{} resolved to {}.{}.{}.{}",
                    target, resolved[0], resolved[1], resolved[2], resolved[3]);
                resolved
            }
            None => {
                orbit_println!("{}ping: could not resolve '{}'{}", color::RED, target, color::RESET);
                return;
            }
        }
    };

    // Send 4 pings
    let count = 4u16;
    orbit_println!("PING {}.{}.{}.{} — {} data bytes",
        ip[0], ip[1], ip[2], ip[3], 56);

    let mut received = 0u16;
    for seq in 1..=count {
        let _ = crate::net::icmp::take_reply();

        let start_tick = crate::arch::x86_64::irq::get_ticks();
        crate::net::icmp::send_ping(ip, 0xAE, seq);

        let timeout_ticks: u64 = 300;
        let mut got_reply = false;

        loop {
            let now = crate::arch::x86_64::irq::get_ticks();
            if now.wrapping_sub(start_tick) >= timeout_ticks {
                break;
            }
            crate::net::poll();

            if let Some(reply) = crate::net::icmp::take_reply() {
                let elapsed = now.wrapping_sub(start_tick);
                let ms = elapsed * 10;
                orbit_println!("Reply from {}.{}.{}.{}: seq={} bytes={} time={}ms",
                    reply.src_ip[0], reply.src_ip[1], reply.src_ip[2], reply.src_ip[3],
                    reply.seq, reply.data_len, ms);
                received += 1;
                got_reply = true;
                break;
            }

            crate::hal::halt();
        }

        if !got_reply {
            orbit_println!("Request timed out (seq={})", seq);
        }
    }

    let loss = ((count - received) as u32 * 100) / count as u32;
    orbit_println!("--- ping statistics ---");
    orbit_println!("{} transmitted, {} received, {}% packet loss",
        count, received, loss);
}

/// Parse an IPv4 address string, return None if not valid IP format.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 { return None; }
    let mut ip = [0u8; 4];
    for (i, octet) in octets.iter().enumerate() {
        ip[i] = octet.parse().ok()?;
    }
    Some(ip)
}

/// Parse an IPv6 address string (supports :: compression).
fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    let mut groups = [0u16; 8];

    let parts: Vec<&str> = s.split("::").collect();
    if parts.len() > 2 { return None; }

    if parts.len() == 2 {
        // Has :: compression
        let left: Vec<&str> = if parts[0].is_empty() { Vec::new() } else { parts[0].split(':').collect() };
        let right: Vec<&str> = if parts[1].is_empty() { Vec::new() } else { parts[1].split(':').collect() };

        if left.len() + right.len() > 7 { return None; }

        for (i, part) in left.iter().enumerate() {
            groups[i] = u16::from_str_radix(part, 16).ok()?;
        }

        let right_start = 8 - right.len();
        for (i, part) in right.iter().enumerate() {
            groups[right_start + i] = u16::from_str_radix(part, 16).ok()?;
        }
    } else {
        // No :: — must have exactly 8 groups
        let grp: Vec<&str> = s.split(':').collect();
        if grp.len() != 8 { return None; }
        for (i, part) in grp.iter().enumerate() {
            groups[i] = u16::from_str_radix(part, 16).ok()?;
        }
    }

    let mut addr = [0u8; 16];
    for i in 0..8 {
        let bytes = groups[i].to_be_bytes();
        addr[i * 2] = bytes[0];
        addr[i * 2 + 1] = bytes[1];
    }
    Some(addr)
}

fn cmd_ping6(parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: ping6 <ipv6-addr or hostname>");
        return;
    }

    let target = parts[1];
    let ip6 = if let Some(parsed) = parse_ipv6(target) {
        parsed
    } else {
        // Try DNS AAAA resolution
        orbit_println!("Resolving {} (AAAA)...", target);
        match crate::net::dns::resolve_ipv6(target) {
            Some(resolved) => {
                orbit_println!("{} resolved to {}", target, crate::net::format_ipv6(resolved));
                resolved
            }
            None => {
                orbit_println!("{}ping6: could not resolve '{}'{}", color::RED, target, color::RESET);
                return;
            }
        }
    };

    let count = 4u16;
    orbit_println!("PING6 {} — {} data bytes", crate::net::format_ipv6(ip6), 56);

    let mut received = 0u16;
    for seq in 1..=count {
        let _ = crate::net::icmpv6::take_reply();

        let start_tick = crate::arch::x86_64::irq::get_ticks();
        crate::net::icmpv6::send_ping6(ip6, 0xAE, seq);

        let timeout_ticks: u64 = 300;
        let mut got_reply = false;

        loop {
            let now = crate::arch::x86_64::irq::get_ticks();
            if now.wrapping_sub(start_tick) >= timeout_ticks {
                break;
            }
            crate::net::poll();

            if let Some(reply) = crate::net::icmpv6::take_reply() {
                let elapsed = now.wrapping_sub(start_tick);
                let ms = elapsed * 10;
                orbit_println!("Reply from {}: seq={} bytes={} time={}ms",
                    crate::net::format_ipv6(reply.src_addr),
                    reply.seq, reply.data_len, ms);
                received += 1;
                got_reply = true;
                break;
            }

            crate::hal::halt();
        }

        if !got_reply {
            orbit_println!("Request timed out (seq={})", seq);
        }
    }

    let loss = ((count - received) as u32 * 100) / count as u32;
    orbit_println!("--- ping6 statistics ---");
    orbit_println!("{} transmitted, {} received, {}% packet loss",
        count, received, loss);
}

fn cmd_netstats() {
    let (rx_pkts, tx_pkts, rx_bytes, tx_bytes) = crate::net::stats();
    orbit_println!("Network Statistics:");
    orbit_println!("  RX: {} packets, {} bytes", rx_pkts, rx_bytes);
    orbit_println!("  TX: {} packets, {} bytes", tx_pkts, tx_bytes);
}

fn cmd_pipe(parts: &[&str]) {
    if parts.len() < 2 || parts[1] != "test" {
        orbit_println!("Usage: pipe test");
        return;
    }
    let pipe_id = crate::ipc::pipe::create_pipe();
    orbit_println!("Created pipe {}", pipe_id);

    let msg = b"Hello from Orbit!";
    if let Some(written) = crate::ipc::pipe::pipe_write(pipe_id, msg) {
        orbit_println!("Wrote {} bytes to pipe", written);
    } else {
        orbit_println!("Pipe write failed");
    }

    let mut buf = [0u8; 64];
    if let Some(read) = crate::ipc::pipe::pipe_read(pipe_id, &mut buf) {
        if read > 0 {
            let text = core::str::from_utf8(&buf[..read]).unwrap_or("???");
            orbit_println!("Read from pipe: \"{}\"", text);
        } else {
            orbit_println!("Pipe read returned 0 bytes");
        }
    } else {
        orbit_println!("Pipe read failed");
    }

    crate::ipc::pipe::pipe_close_writer(pipe_id);
    crate::ipc::pipe::pipe_close_reader(pipe_id);
    orbit_println!("Pipe test complete!");
}

fn cmd_history(state: &ShellState) {
    for (i, cmd) in state.history.iter().enumerate() {
        orbit_println!("  {:>3}  {}", i + 1, cmd);
    }
}

// ==================== DNS Commands ====================

fn cmd_nslookup(parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: nslookup <hostname>");
        return;
    }
    let hostname = parts[1];
    let dns_server = crate::net::dns::get_nameserver();
    orbit_println!("Server:  {}.{}.{}.{}", dns_server[0], dns_server[1], dns_server[2], dns_server[3]);
    orbit_println!("");

    let mut found = false;

    // Try A record (IPv4)
    match crate::net::dns::resolve(hostname) {
        Some(ip) => {
            orbit_println!("Name:    {}", hostname);
            orbit_println!("Address: {}.{}.{}.{} (A)", ip[0], ip[1], ip[2], ip[3]);
            found = true;
        }
        None => {}
    }

    // Try AAAA record (IPv6)
    match crate::net::dns::resolve_ipv6(hostname) {
        Some(ip6) => {
            if !found {
                orbit_println!("Name:    {}", hostname);
            }
            orbit_println!("Address: {} (AAAA)", crate::net::format_ipv6(ip6));
            found = true;
        }
        None => {}
    }

    if !found {
        crate::kprint!("{}** server can't find {}: NXDOMAIN{}\n",
            color::RED, hostname, color::RESET);
    }
}

fn cmd_dns(parts: &[&str]) {
    if parts.len() < 2 {
        let ns = crate::net::dns::get_nameserver();
        orbit_println!("DNS nameserver: {}.{}.{}.{}", ns[0], ns[1], ns[2], ns[3]);
        return;
    }
    if let Some(ip) = parse_ipv4(parts[1]) {
        crate::net::dns::set_nameserver(ip);
        orbit_println!("DNS nameserver set to {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    } else {
        orbit_println!("{}Invalid IP address{}", color::RED, color::RESET);
    }
}

fn cmd_dhcp(parts: &[&str]) {
    let subcmd = if parts.len() > 1 { parts[1] } else { "status" };
    match subcmd {
        "discover" | "request" => {
            orbit_println!("Starting DHCP discovery...");
            if crate::net::dhcp::discover() {
                orbit_println!("{}DHCP lease obtained successfully{}", color::GREEN, color::RESET);
                crate::net::dhcp::status();
            } else {
                orbit_println!("{}DHCP discovery failed{}", color::RED, color::RESET);
            }
        }
        "release" => {
            if crate::net::dhcp::release() {
                orbit_println!("{}DHCP lease released{}", color::GREEN, color::RESET);
            } else {
                orbit_println!("{}No active lease to release{}", color::YELLOW, color::RESET);
            }
        }
        "renew" => {
            if crate::net::dhcp::renew() {
                orbit_println!("{}DHCP lease renewed{}", color::GREEN, color::RESET);
                crate::net::dhcp::status();
            } else {
                orbit_println!("{}DHCP renewal failed{}", color::RED, color::RESET);
            }
        }
        "status" | "info" => {
            crate::net::dhcp::status();
        }
        _ => {
            orbit_println!("Usage: dhcp <discover|release|renew|status>");
        }
    }
}

// ==================== NT Kernel Commands ====================

fn cmd_ob(parts: &[&str]) {
    let path = if parts.len() > 1 { parts[1] } else { "\\" };
    crate::ob::dump_namespace(path);
}

fn cmd_reg(parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: reg <query|add|delete> <key> [value] [data]");
        orbit_println!("  reg query <key>            — List values under key");
        orbit_println!("  reg add <key> <val> <data> — Set a value");
        orbit_println!("  reg delete <key> [val]     — Delete key or value");
        return;
    }
    match parts[1] {
        "query" => {
            let key = if parts.len() > 2 { parts[2] } else { "\\" };
            crate::config::registry_query(key);
        }
        "add" => {
            if parts.len() < 5 {
                orbit_println!("Usage: reg add <key> <value_name> <data>");
                return;
            }
            crate::config::registry_set(parts[2], parts[3], parts[4]);
        }
        "delete" => {
            if parts.len() < 3 {
                orbit_println!("Usage: reg delete <key> [value_name]");
                return;
            }
            let val = if parts.len() > 3 { Some(parts[3]) } else { None };
            crate::config::registry_delete(parts[2], val);
        }
        _ => orbit_println!("Unknown reg subcommand: '{}'", parts[1]),
    }
}

fn cmd_devmgr() {
    crate::io::devmgr::dump_device_tree();
}

fn cmd_procfs(parts: &[&str]) {
    let path = if parts.len() > 1 { parts[1] } else { "/" };
    crate::vfs::procfs::read_procfs(path);
}

fn cmd_date() {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let secs = ticks / 100;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    orbit_println!("Uptime: {:02}:{:02}:{:02} ({} ticks since boot)", h, m, s, ticks);
}

fn cmd_hostname() {
    match crate::vfs::read_file("/etc/hostname") {
        Ok(data) => {
            if let Ok(name) = core::str::from_utf8(&data) {
                orbit_println!("{}", name.trim());
            } else {
                orbit_println!("astryx");
            }
        }
        Err(_) => orbit_println!("astryx"),
    }
}

fn cmd_motd() {
    match crate::vfs::read_file("/etc/motd") {
        Ok(data) => {
            if let Ok(text) = core::str::from_utf8(&data) {
                crate::kprint!("{}", text);
            }
        }
        Err(_) => orbit_println!("Welcome to AstryxOS!"),
    }
}

// ==================== Path Resolution ====================

/// Resolve a path relative to the current working directory.
fn resolve_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        // Absolute path — normalize it.
        normalize_path(path)
    } else if path == ".." {
        // Go up one level.
        parent_path(cwd)
    } else if path == "." {
        String::from(cwd)
    } else {
        // Relative path.
        let base = if cwd == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}/{}", cwd, path)
        };
        normalize_path(&base)
    }
}

fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => { parts.pop(); }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        String::from("/")
    } else {
        let mut result = String::new();
        for p in parts {
            result.push('/');
            result.push_str(p);
        }
        result
    }
}

fn parent_path(path: &str) -> String {
    if path == "/" { return String::from("/"); }
    if let Some(pos) = path.rfind('/') {
        if pos == 0 {
            String::from("/")
        } else {
            String::from(&path[..pos])
        }
    } else {
        String::from("/")
    }
}

// ==================== Performance Metrics Commands ====================

fn cmd_perf(parts: &[&str]) {
    let sub = parts.get(1).copied().unwrap_or("summary");
    match sub {
        "summary" | "stat" => {
            let s = crate::perf::snapshot();
            orbit_println!("{}╔═══════════════════════════════════════════════╗{}", color::CYAN, color::RESET);
            orbit_println!("{}║  AstryxOS Performance Metrics                 ║{}", color::CYAN, color::RESET);
            orbit_println!("{}╚═══════════════════════════════════════════════╝{}", color::CYAN, color::RESET);
            orbit_println!("");
            orbit_println!("{}── Uptime ──────────────────────────────────────{}", color::YELLOW, color::RESET);
            orbit_println!("  Ticks:     {}", s.uptime_ticks);
            orbit_println!("  Uptime:    {}s ({}m {}s)",
                s.uptime_seconds,
                s.uptime_seconds / 60,
                s.uptime_seconds % 60);
            orbit_println!("");
            orbit_println!("{}── CPU ─────────────────────────────────────────{}", color::YELLOW, color::RESET);
            orbit_println!("  Context switches:  {}", s.context_switches);
            orbit_println!("  Idle ticks:        {} ({}% idle)", s.idle_ticks, s.cpu_idle_pct);
            orbit_println!("");
            orbit_println!("{}── Interrupts ──────────────────────────────────{}", color::YELLOW, color::RESET);
            orbit_println!("  Total:      {}", s.total_interrupts);
            orbit_println!("  Timer:      {} (IRQ0)", s.timer_interrupts);
            orbit_println!("  Keyboard:   {} (IRQ1)", s.keyboard_interrupts);
            orbit_println!("");
            orbit_println!("{}── Syscalls ────────────────────────────────────{}", color::YELLOW, color::RESET);
            orbit_println!("  Total:      {}", s.total_syscalls);
            if s.unknown_syscalls > 0 {
                orbit_println!("  Unknown:    {}", s.unknown_syscalls);
            }
            orbit_println!("");
            orbit_println!("{}── Memory ──────────────────────────────────────{}", color::YELLOW, color::RESET);
            orbit_println!("  Heap allocs:   {}", s.heap_allocs);
            orbit_println!("  Heap frees:    {}", s.heap_frees);
            orbit_println!("  Current:       {} KiB", s.heap_current_bytes / 1024);
            orbit_println!("  Peak:          {} KiB", s.heap_peak_bytes / 1024);
            orbit_println!("  Total alloc'd: {} KiB", s.heap_alloc_bytes / 1024);
            orbit_println!("  Page faults:   {}", s.page_faults);
            orbit_println!("");
            orbit_println!("{}── Network ─────────────────────────────────────{}", color::YELLOW, color::RESET);
            orbit_println!("  RX: {} packets / {} bytes", s.net_rx_packets, s.net_rx_bytes);
            orbit_println!("  TX: {} packets / {} bytes", s.net_tx_packets, s.net_tx_bytes);
        }
        "irq" => {
            orbit_println!("{}Interrupt Vector Counts:{}", color::CYAN, color::RESET);
            for v in 0..48u8 {
                let count = crate::perf::interrupt_count(v);
                if count > 0 {
                    let name = match v {
                        0 => "Divide Error",
                        6 => "Invalid Opcode",
                        8 => "Double Fault",
                        13 => "General Protection",
                        14 => "Page Fault",
                        32 => "Timer (IRQ0)",
                        33 => "Keyboard (IRQ1)",
                        _ => "",
                    };
                    orbit_println!("  Vector {:>3}: {:>10}  {}", v, count, name);
                }
            }
        }
        "syscalls" => {
            orbit_println!("{}Syscall Counts:{}", color::CYAN, color::RESET);
            let total = crate::perf::total_syscalls();
            orbit_println!("  Total: {}", total);
            for nr in 0..10u64 {
                let count = crate::perf::syscall_count(nr);
                if count > 0 {
                    orbit_println!("  {:>3} ({:<8}): {}", nr, crate::perf::syscall_name(nr), count);
                }
            }
            let unknown = crate::perf::unknown_syscalls();
            if unknown > 0 {
                orbit_println!("  Unknown: {}", unknown);
            }
        }
        "mem" => {
            let (allocs, frees, alloc_bytes, free_bytes, current, peak) = crate::perf::heap_alloc_stats();
            orbit_println!("{}Heap Allocation Metrics:{}", color::CYAN, color::RESET);
            orbit_println!("  Allocations:   {}", allocs);
            orbit_println!("  Frees:         {}", frees);
            orbit_println!("  Net:           {} (allocs - frees)", allocs.saturating_sub(frees));
            orbit_println!("  Alloc'd total: {} bytes ({} KiB)", alloc_bytes, alloc_bytes / 1024);
            orbit_println!("  Freed total:   {} bytes ({} KiB)", free_bytes, free_bytes / 1024);
            orbit_println!("  Current live:  {} bytes ({} KiB)", current, current / 1024);
            orbit_println!("  Peak:          {} bytes ({} KiB)", peak, peak / 1024);
            orbit_println!("  Page faults:   {}", crate::perf::page_faults());
        }
        _ => {
            orbit_println!("Usage: perf [summary|irq|syscalls|mem]");
            orbit_println!("  summary  — full performance metrics overview (default)");
            orbit_println!("  irq      — per-vector interrupt counts");
            orbit_println!("  syscalls — per-syscall invocation counts");
            orbit_println!("  mem      — detailed heap allocation metrics");
        }
    }
}

/// Execute an ELF binary in Ring 3.
fn cmd_exec(parts: &[&str]) {
    if parts.len() < 2 {
        orbit_println!("Usage: exec <path|hello>");
        orbit_println!("  exec hello         — Run embedded hello ELF");
        orbit_println!("  exec /disk/bin/app — Run ELF from filesystem");
        return;
    }

    let name = parts[1];

    // Enable scheduler so the user-mode process can be scheduled.
    let was_active = crate::sched::is_active();
    if !was_active {
        crate::sched::enable();
    }

    let result = if name == "hello" || name == "/bin/hello" {
        orbit_println!("Loading embedded ELF: hello ({} bytes)", crate::proc::hello_elf::HELLO_ELF.len());
        crate::proc::usermode::create_user_process("hello", &crate::proc::hello_elf::HELLO_ELF)
            .map_err(|e| alloc::format!("ELF load failed: {:?}", e))
    } else {
        // Try loading from VFS.
        orbit_println!("Loading ELF from VFS: {}", name);
        match crate::vfs::read_file(name) {
            Ok(data) => {
                if !crate::proc::elf::is_elf(&data) {
                    Err(alloc::format!("'{}' is not an ELF binary", name))
                } else {
                    crate::proc::usermode::create_user_process(name, &data)
                        .map_err(|e| alloc::format!("ELF load failed: {:?}", e))
                        .map(|pid| {
                            // Disk-loaded ELFs use the Linux syscall ABI.
                            let mut procs = crate::proc::PROCESS_TABLE.lock();
                            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                                p.linux_abi = true;
                            }
                            pid
                        })
                }
            }
            Err(e) => Err(alloc::format!("file not found: {:?}", e)),
        }
    };

    match result {
        Ok(pid) => {
            orbit_println!("Process created: PID {}", pid);
            orbit_println!("Scheduling user-mode process...");

            // Poll waitpid until the child becomes a zombie, yielding each
            // iteration so the scheduler can run the user process.
            // Use the kernel pid 0 as "any child" since the shell runs as pid 0.
            loop {
                crate::sched::yield_cpu();
                crate::hal::enable_interrupts();
                for _ in 0..10000 { core::hint::spin_loop(); }
                if let Some((_reaped, code)) = crate::proc::waitpid(0, pid as i64) {
                    if code == 0 {
                        orbit_println!("Process exited (code 0)");
                    } else {
                        orbit_println!("{}Process exited with code {}{}", color::RED, code, color::RESET);
                    }
                    break;
                }
            }
        }
        Err(msg) => {
            orbit_println!("{}exec: {}{}", color::RED, msg, color::RESET);
        }
    }

    if !was_active {
        crate::sched::disable();
    }
}

// ==================== Orbit Print Macros ====================

macro_rules! orbit_println {
    ($($arg:tt)*) => {
        crate::kprintln!($($arg)*)
    };
}
use orbit_println;

macro_rules! orbit_color_println {
    ($color:expr, $($arg:tt)*) => {
        crate::kprint!("{}", $color);
        crate::kprintln!($($arg)*);
        crate::kprint!("{}", color::RESET);
    };
}
use orbit_color_println;
