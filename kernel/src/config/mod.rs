//! NT Configuration Manager — Registry
//!
//! Inspired by the Windows NT Registry (ntoskrnl/config/), this subsystem
//! provides a hierarchical key-value store for system configuration.
//!
//! # Hives
//! - `HKLM\System`  — Boot config, services, hardware
//! - `HKLM\Software` — Software settings
//! - `HKLM\Hardware` — Hardware detection results
//! - `HKU\.Default`  — Default user profile

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

/// Registry value types.
#[derive(Debug, Clone)]
pub enum RegistryValue {
    String(String),
    DWord(u32),
    QWord(u64),
    Binary(Vec<u8>),
    MultiString(Vec<String>),
    None,
}

impl core::fmt::Display for RegistryValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::String(s) => write!(f, "REG_SZ \"{}\"", s),
            Self::DWord(v) => write!(f, "REG_DWORD {:#010x} ({})", v, v),
            Self::QWord(v) => write!(f, "REG_QWORD {:#018x}", v),
            Self::Binary(b) => {
                write!(f, "REG_BINARY ({} bytes)", b.len())
            }
            Self::MultiString(v) => write!(f, "REG_MULTI_SZ [{} entries]", v.len()),
            Self::None => write!(f, "REG_NONE"),
        }
    }
}

/// A registry key — contains named values and subkeys.
struct RegistryKey {
    values: BTreeMap<String, RegistryValue>,
    subkeys: BTreeMap<String, RegistryKey>,
}

impl RegistryKey {
    fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            subkeys: BTreeMap::new(),
        }
    }
}

/// The entire registry tree.
static REGISTRY: Mutex<Option<BTreeMap<String, RegistryKey>>> = Mutex::new(None);

/// Initialize the Registry with default hives and values.
pub fn init() {
    let mut root = BTreeMap::new();

    // HKLM\System
    {
        let mut system = RegistryKey::new();

        // CurrentControlSet\Control
        let mut control = RegistryKey::new();
        control.values.insert(
            String::from("SystemBootDevice"),
            RegistryValue::String(String::from("ramdisk(0)")),
        );
        control.values.insert(
            String::from("CurrentUser"),
            RegistryValue::String(String::from("root")),
        );
        control.values.insert(
            String::from("WaitToKillServiceTimeout"),
            RegistryValue::DWord(20000),
        );

        // CurrentControlSet\Services
        let mut services = RegistryKey::new();

        let mut e1000_svc = RegistryKey::new();
        e1000_svc.values.insert(
            String::from("DisplayName"),
            RegistryValue::String(String::from("Intel e1000 Ethernet Adapter")),
        );
        e1000_svc.values.insert(
            String::from("Start"),
            RegistryValue::DWord(0), // Boot start
        );
        e1000_svc.values.insert(
            String::from("Type"),
            RegistryValue::DWord(1), // Kernel driver
        );
        services.subkeys.insert(String::from("e1000"), e1000_svc);

        let mut sched_svc = RegistryKey::new();
        sched_svc.values.insert(
            String::from("DisplayName"),
            RegistryValue::String(String::from("CoreSched Scheduler")),
        );
        sched_svc.values.insert(
            String::from("TimeQuantum"),
            RegistryValue::DWord(5), // 5 ticks = 50ms
        );
        services.subkeys.insert(String::from("CoreSched"), sched_svc);

        let mut ccs = RegistryKey::new();
        ccs.subkeys.insert(String::from("Control"), control);
        ccs.subkeys.insert(String::from("Services"), services);

        system.subkeys.insert(String::from("CurrentControlSet"), ccs);

        // Select
        let mut select = RegistryKey::new();
        select.values.insert(String::from("Current"), RegistryValue::DWord(1));
        select.values.insert(String::from("Default"), RegistryValue::DWord(1));
        system.subkeys.insert(String::from("Select"), select);

        root.insert(String::from("HKLM\\System"), system);
    }

    // HKLM\Software
    {
        let mut software = RegistryKey::new();

        let mut astryx = RegistryKey::new();
        astryx.values.insert(
            String::from("Version"),
            RegistryValue::String(String::from("0.1.0")),
        );
        astryx.values.insert(
            String::from("Codename"),
            RegistryValue::String(String::from("Aether")),
        );
        astryx.values.insert(
            String::from("BuildDate"),
            RegistryValue::String(String::from("2025")),
        );

        software.subkeys.insert(String::from("AstryxOS"), astryx);
        root.insert(String::from("HKLM\\Software"), software);
    }

    // HKLM\Hardware
    {
        let mut hardware = RegistryKey::new();

        let mut desc = RegistryKey::new();
        desc.values.insert(
            String::from("Identifier"),
            RegistryValue::String(String::from("x86_64 UEFI System")),
        );
        desc.values.insert(
            String::from("Architecture"),
            RegistryValue::String(String::from("x86_64")),
        );
        hardware.subkeys.insert(String::from("Description"), desc);

        root.insert(String::from("HKLM\\Hardware"), hardware);
    }

    // HKU\.Default
    {
        let mut default_user = RegistryKey::new();

        let mut env = RegistryKey::new();
        env.values.insert(
            String::from("PATH"),
            RegistryValue::String(String::from("/bin")),
        );
        env.values.insert(
            String::from("HOME"),
            RegistryValue::String(String::from("/home/root")),
        );
        env.values.insert(
            String::from("SHELL"),
            RegistryValue::String(String::from("/bin/orbit")),
        );
        default_user.subkeys.insert(String::from("Environment"), env);

        root.insert(String::from("HKU\\.Default"), default_user);
    }

    *REGISTRY.lock() = Some(root);
    crate::serial_println!("[CONFIG] Registry initialized — 4 hives loaded");
}

/// Query and display registry key contents.
pub fn registry_query(path: &str) {
    let reg = REGISTRY.lock();
    let root = match reg.as_ref() {
        Some(r) => r,
        None => { crate::kprintln!("Registry not initialized"); return; }
    };

    if path == "\\" || path == "/" || path.is_empty() {
        // List root hives
        crate::kprintln!("Registry Hives:");
        for name in root.keys() {
            crate::kprintln!("  {}", name);
        }
        return;
    }

    let clean = path.replace('/', "\\");
    let parts: Vec<&str> = clean.split('\\').filter(|s| !s.is_empty()).collect();

    if parts.is_empty() { return; }

    // First part(s) identify the hive
    // Try matching "HKLM\System", "HKLM\Software", etc.
    let (hive_key, rest) = find_hive(&parts);

    let key = match root.get(hive_key) {
        Some(k) => k,
        None => { crate::kprintln!("Key not found: {}", path); return; }
    };

    // Walk subkeys
    let mut current = key;
    for part in rest {
        match current.subkeys.get(*part) {
            Some(sub) => current = sub,
            None => { crate::kprintln!("Key not found: {}", path); return; }
        }
    }

    // Display the key contents
    crate::kprintln!("Key: {}", path);
    if !current.values.is_empty() {
        crate::kprintln!("Values:");
        for (name, val) in &current.values {
            crate::kprintln!("  {}  {}", name, val);
        }
    }
    if !current.subkeys.is_empty() {
        crate::kprintln!("Subkeys:");
        for name in current.subkeys.keys() {
            crate::kprintln!("  {}\\{}", path, name);
        }
    }
    if current.values.is_empty() && current.subkeys.is_empty() {
        crate::kprintln!("  (empty)");
    }
}

/// Set a registry value (creates key path if needed).
pub fn registry_set(path: &str, name: &str, data: &str) {
    let mut reg = REGISTRY.lock();
    let root = match reg.as_mut() {
        Some(r) => r,
        None => { crate::kprintln!("Registry not initialized"); return; }
    };

    let clean = path.replace('/', "\\");
    let parts: Vec<&str> = clean.split('\\').filter(|s| !s.is_empty()).collect();
    let (hive_key, rest) = find_hive(&parts);

    if !root.contains_key(hive_key) {
        root.insert(String::from(hive_key), RegistryKey::new());
    }

    let mut current = root.get_mut(hive_key).unwrap();
    for part in rest {
        if !current.subkeys.contains_key(*part) {
            current.subkeys.insert(String::from(*part), RegistryKey::new());
        }
        current = current.subkeys.get_mut(*part).unwrap();
    }

    // Auto-detect value type: if it starts with 0x, treat as DWORD
    let value = if let Some(hex) = data.strip_prefix("0x") {
        if let Ok(v) = u32::from_str_radix(hex, 16) {
            RegistryValue::DWord(v)
        } else {
            RegistryValue::String(String::from(data))
        }
    } else if let Ok(v) = data.parse::<u32>() {
        RegistryValue::DWord(v)
    } else {
        RegistryValue::String(String::from(data))
    };

    current.values.insert(String::from(name), value);
    crate::kprintln!("Set {}\\{} = {}", path, name, data);
}

/// Read a registry value without formatting it to the console.
///
/// Returns a clone of the `RegistryValue` at `path\name`, or `None` if the
/// key path or named value does not exist.  This is the canonical read
/// path; `registry_query` is only for shell-style display.  Tests use
/// `registry_get` so a silently-broken `registry_set` no longer
/// "passes" by producing no observable error.
pub fn registry_get(path: &str, name: &str) -> Option<RegistryValue> {
    let reg = REGISTRY.lock();
    let root = reg.as_ref()?;

    let clean = path.replace('/', "\\");
    let parts: Vec<&str> = clean.split('\\').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    let (hive_key, rest) = find_hive(&parts);

    let mut current = root.get(hive_key)?;
    for part in rest {
        current = current.subkeys.get(*part)?;
    }
    current.values.get(name).cloned()
}

/// Delete a registry key or value.
pub fn registry_delete(path: &str, value_name: Option<&str>) {
    let mut reg = REGISTRY.lock();
    let root = match reg.as_mut() {
        Some(r) => r,
        None => { crate::kprintln!("Registry not initialized"); return; }
    };

    let clean = path.replace('/', "\\");
    let parts: Vec<&str> = clean.split('\\').filter(|s| !s.is_empty()).collect();
    let (hive_key, rest) = find_hive(&parts);

    let hive = match root.get_mut(hive_key) {
        Some(h) => h,
        None => { crate::kprintln!("Key not found: {}", path); return; }
    };

    if rest.is_empty() {
        if let Some(vn) = value_name {
            if hive.values.remove(vn).is_some() {
                crate::kprintln!("Deleted value: {}\\{}", path, vn);
            } else {
                crate::kprintln!("Value not found: {}", vn);
            }
        } else {
            crate::kprintln!("Cannot delete a root hive");
        }
        return;
    }

    // Walk to parent
    let mut current = hive;
    for part in &rest[..rest.len() - 1] {
        match current.subkeys.get_mut(*part) {
            Some(sub) => current = sub,
            None => { crate::kprintln!("Key not found: {}", path); return; }
        }
    }

    let last = *rest.last().unwrap();

    if let Some(vn) = value_name {
        // Delete a value from the target key
        match current.subkeys.get_mut(last) {
            Some(target) => {
                if target.values.remove(vn).is_some() {
                    crate::kprintln!("Deleted value: {}\\{}", path, vn);
                } else {
                    crate::kprintln!("Value not found: {}", vn);
                }
            }
            None => crate::kprintln!("Key not found: {}", path),
        }
    } else {
        // Delete the subkey itself
        if current.subkeys.remove(last).is_some() {
            crate::kprintln!("Deleted key: {}", path);
        } else {
            crate::kprintln!("Key not found: {}", path);
        }
    }
}

/// Helper: split a path into (hive_key, remaining_parts).
/// Handles paths like "HKLM\System\CurrentControlSet\Control".
fn find_hive<'a>(parts: &'a [&'a str]) -> (&'a str, &'a [&'a str]) {
    // Try two-part hive key first (e.g., "HKLM\System")
    if parts.len() >= 2 {
        // Reconstruct the hive key and check
        let candidate = alloc::format!("{}\\{}", parts[0], parts[1]);
        // We know our hives: HKLM\System, HKLM\Software, HKLM\Hardware, HKU\.Default
        let known_hives = ["HKLM\\System", "HKLM\\Software", "HKLM\\Hardware", "HKU\\.Default"];
        for hive in &known_hives {
            if candidate == *hive {
                // This is a hack — we need the hive key as a &str that lives long enough.
                // We'll return the static string that matches.
                return (hive, &parts[2..]);
            }
        }
    }

    // Fallback: treat first part as the hive
    if parts.is_empty() {
        ("", &[])
    } else {
        (parts[0], &parts[1..])
    }
}
