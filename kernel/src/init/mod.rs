/// Ascension — AstryxOS Init System
///
/// Ascension is the PID-1 equivalent for AstryxOS. It runs entirely in the
/// kernel during the current phase (no separate user-mode init binary yet).
/// When a full user-mode init binary is available it will be exec'd as PID 1
/// and this module will act only as the kernel-side bootstrap shim.
///
/// Responsibilities:
///   1. Parse `/etc/ascension.conf` at boot and register services.
///   2. Launch registered services as user-mode ELF processes.
///   3. Monitor services (poll on scheduler yield or SIGCHLD wakeup) and
///      restart auto-restart services when they exit.
///   4. Launch the console shell (Orbit) as the last step.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

// ── Service definition ────────────────────────────────────────────────────────

/// Restart policy for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// Don't restart on exit.
    No,
    /// Restart automatically on any exit.
    Always,
    /// Restart only if exit code ≠ 0.
    OnFailure,
}

/// A service registered with Ascension.
#[derive(Clone)]
pub struct Service {
    pub name: String,
    pub binary: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub restart: Restart,
    /// Current running PID, None if not running.
    pub pid: Option<crate::proc::Pid>,
    /// Number of times restarted.
    pub restart_count: u32,
}

impl Service {
    fn new(name: &str, binary: &str) -> Self {
        Self {
            name: String::from(name),
            binary: String::from(binary),
            args: alloc::vec![String::from(name)],
            env: alloc::vec![
                String::from("HOME=/"),
                String::from("PATH=/bin:/disk/bin"),
            ],
            restart: Restart::No,
            pid: None,
            restart_count: 0,
        }
    }
}

// ── Global service table ──────────────────────────────────────────────────────

static SERVICE_TABLE: Mutex<Vec<Service>> = Mutex::new(Vec::new());

// ── Public API ────────────────────────────────────────────────────────────────

/// Register a built-in service. Call before `launch_all()`.
pub fn register(name: &str, binary: &str, restart: Restart) {
    let mut svc = Service::new(name, binary);
    svc.restart = restart;
    SERVICE_TABLE.lock().push(svc);
}

/// Register a service with explicit args.
pub fn register_with_args(name: &str, binary: &str, args: &[&str], restart: Restart) {
    let mut svc = Service::new(name, binary);
    svc.args = args.iter().map(|s| String::from(*s)).collect();
    svc.restart = restart;
    SERVICE_TABLE.lock().push(svc);
}

/// Parse `/etc/ascension.conf` and register services found there.
/// Config format (one service per line):
///   # comment
///   service <name> <binary> [args...]
///   service-restart <name> <binary> [args...]   (restart=Always)
///   service-onfail  <name> <binary> [args...]   (restart=OnFailure)
pub fn parse_config() {
    let data = match crate::vfs::read_file("/etc/ascension.conf") {
        Ok(d) => d,
        Err(_) => return,
    };

    let text = match core::str::from_utf8(&data) {
        Ok(s) => s,
        Err(_) => return,
    };

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.splitn(3, char::is_whitespace);
        let directive = match parts.next() { Some(d) => d, None => continue };
        let name = match parts.next() { Some(n) => n.trim(), None => continue };
        let rest  = match parts.next() { Some(r) => r.trim(), None => continue };

        let restart = match directive {
            "service-restart" => Restart::Always,
            "service-onfail"  => Restart::OnFailure,
            "service"         => Restart::No,
            _                 => continue,
        };

        // Split rest into binary + args.
        let mut parts2 = rest.splitn(2, char::is_whitespace);
        let binary = match parts2.next() { Some(b) => b.trim(), None => continue };
        let extra_args: Vec<&str> = match parts2.next() {
            Some(a) => a.split_whitespace().collect(),
            None    => Vec::new(),
        };

        let mut all_args = alloc::vec![name, binary];
        all_args.extend_from_slice(&extra_args);

        let mut svc = Service::new(name, binary);
        svc.args = all_args.iter().map(|s| String::from(*s)).collect();
        svc.restart = restart;
        SERVICE_TABLE.lock().push(svc);

        crate::serial_println!("[INIT] Registered service '{}' → '{}'", name, binary);
    }
}

/// Launch all registered services that are not yet running.
pub fn launch_all() {
    let count = SERVICE_TABLE.lock().len();
    for i in 0..count {
        launch_one(i);
    }
}

/// Check all services; restart any that have exited and have restart=Always/OnFailure.
pub fn check_restarts() {
    let count = SERVICE_TABLE.lock().len();
    for i in 0..count {
        // Check if this service's process has exited.
        let (pid, restart, exit_code) = {
            let table = SERVICE_TABLE.lock();
            let svc = &table[i];
            let pid = match svc.pid { Some(p) => p, None => continue };
            let exit_code = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter()
                    .find(|p| p.pid == pid)
                    .map(|p| if p.state == crate::proc::ProcessState::Zombie {
                        Some(p.exit_code)
                    } else {
                        None
                    })
                    .flatten()
            };
            match exit_code {
                Some(code) => (pid, svc.restart, code),
                None => continue, // still running
            }
        };

        let should_restart = match restart {
            Restart::Always    => true,
            Restart::OnFailure => exit_code != 0,
            Restart::No        => false,
        };

        if should_restart {
            {
                let mut table = SERVICE_TABLE.lock();
                let svc = &mut table[i];
                crate::serial_println!(
                    "[INIT] Service '{}' (PID {}) exited with {} — restarting (count={})",
                    svc.name, pid, exit_code, svc.restart_count + 1
                );
                svc.pid = None;
                svc.restart_count += 1;
            }
            launch_one(i);
        } else if restart == Restart::No {
            let mut table = SERVICE_TABLE.lock();
            let svc = &mut table[i];
            if svc.pid == Some(pid) {
                crate::serial_println!(
                    "[INIT] Service '{}' (PID {}) exited with {} (no restart)",
                    svc.name, pid, exit_code
                );
                svc.pid = None;
            }
        }
    }
}

/// Returns a snapshot of the current service table (name, pid, restart_count).
pub fn service_status() -> Vec<(String, Option<crate::proc::Pid>, u32)> {
    SERVICE_TABLE.lock()
        .iter()
        .map(|s| (s.name.clone(), s.pid, s.restart_count))
        .collect()
}

/// Returns number of registered services.
pub fn service_count() -> usize {
    SERVICE_TABLE.lock().len()
}

// ── Boot entry point ──────────────────────────────────────────────────────────

/// Full Ascension boot sequence:
///   1. Parse `/etc/ascension.conf`
///   2. Launch all registered services
///   3. Return (caller may then run interactive shell or idle loop)
pub fn boot() {
    crate::serial_println!("[INIT] Ascension init starting...");
    parse_config();
    launch_all();
    let count = service_count();
    crate::serial_println!("[INIT] Ascension init complete — {} service(s) launched", count);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn launch_one(idx: usize) {
    // Extract what we need without holding the lock during ELF load.
    // Extract what we need as owned strings before releasing the lock,
    // since VFS read and ELF load must happen without holding SERVICE_TABLE.
    let (name, binary, args, env) = {
        let table = SERVICE_TABLE.lock();
        let svc = &table[idx];
        if svc.pid.is_some() {
            return; // already running
        }
        let args: Vec<String> = svc.args.clone();
        let env: Vec<String>  = svc.env.clone();
        (svc.name.clone(), svc.binary.clone(), args, env)
    };

    let elf_data = match crate::vfs::read_file(&binary) {
        Ok(data) => {
            crate::serial_println!("[INIT] Service '{}': read {} bytes from '{}'",
                name, data.len(), binary);
            data
        }
        Err(e) => {
            crate::serial_println!("[INIT] Service '{}': binary '{}' not found: {:?}",
                name, binary, e);
            return;
        }
    };

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let env_ref: Vec<&str>  = env.iter().map(|s| s.as_str()).collect();

    match crate::proc::usermode::create_user_process_with_args(
        &name, &elf_data, &args_ref, &env_ref,
    ) {
        Ok(pid) => {
            crate::serial_println!("[INIT] Service '{}' launched as PID {}", name, pid);
            SERVICE_TABLE.lock()[idx].pid = Some(pid);
        }
        Err(e) => {
            crate::serial_println!("[INIT] Service '{}': launch failed: {:?}", name, e);
        }
    }
}
