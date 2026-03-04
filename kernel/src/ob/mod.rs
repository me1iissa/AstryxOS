//! NT Object Manager — Kernel Object Namespace
//!
//! Inspired by the Windows NT Object Manager (ntoskrnl/ob/), this subsystem
//! provides a hierarchical namespace for kernel objects. Every kernel entity
//! (device, file, process, semaphore, etc.) is represented as a named object
//! in this namespace.
//!
//! # Architecture
//! - `KernelObject` trait — common interface for all object types
//! - `ObjectHeader` — metadata (type, ref count, name, security descriptor)
//! - `ObjectDirectory` — namespace tree of named objects
//! - `HandleTable` — per-process mapping of handles to objects
//!
//! # Namespace
//! The root namespace `\` contains standard directories:
//! - `\Device` — device objects
//! - `\Driver` — loaded driver objects
//! - `\ObjectTypes` — registered object types
//! - `\BaseNamedObjects` — shared kernel objects (events, mutexes, etc.)

extern crate alloc;

pub mod handle;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::security::SecurityDescriptor;

/// Object type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Directory,
    Device,
    Driver,
    SymbolicLink,
    Event,
    Mutex,
    Semaphore,
    Section,
    Port,
    Process,
    Thread,
    File,
    Key,       // Registry key
    Type,      // Object type descriptor
}

impl ObjectType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Directory    => "Directory",
            Self::Device       => "Device",
            Self::Driver       => "Driver",
            Self::SymbolicLink => "SymbolicLink",
            Self::Event        => "Event",
            Self::Mutex        => "Mutant",
            Self::Semaphore    => "Semaphore",
            Self::Section      => "Section",
            Self::Port         => "Port",
            Self::Process      => "Process",
            Self::Thread       => "Thread",
            Self::File         => "File",
            Self::Key          => "Key",
            Self::Type         => "Type",
        }
    }
}

/// Trait implemented by all kernel object types.
///
/// Any type-specific body attached to an ObjectHeader implements this trait.
pub trait KernelObject: Send + Sync {
    /// Return the object type tag.
    fn object_type(&self) -> ObjectType;
    /// Return the object's name.
    fn object_name(&self) -> &str;
}

/// Object header — metadata for every kernel object.
pub struct ObjectHeader {
    pub name: String,
    pub object_type: ObjectType,
    pub ref_count: AtomicUsize,
    /// Optional NT-style security descriptor attached to this object.
    pub security_descriptor: Option<SecurityDescriptor>,
    /// For SymbolicLink objects, the target path this link resolves to.
    pub link_target: Option<String>,
    /// Optional typed body implementing the KernelObject trait.
    pub body: Option<alloc::boxed::Box<dyn KernelObject>>,
}

/// An entry in the object namespace — either a directory or a leaf object.
enum NamespaceEntry {
    Directory(BTreeMap<String, NamespaceEntry>),
    Object(ObjectHeader),
}

/// Global object namespace root.
static NAMESPACE: Mutex<Option<BTreeMap<String, NamespaceEntry>>> = Mutex::new(None);

// ============================================================================
// Helpers for path parsing (shared by all operations)
// ============================================================================

/// Clean and split an NT path into components.
fn parse_path(path: &str) -> Vec<&str> {
    let clean = path.trim_start_matches('\\').trim_start_matches('/');
    clean.split(|c| c == '\\' || c == '/').filter(|s| !s.is_empty()).collect()
}

// ============================================================================
// Internal namespace operations (caller must hold lock)
// ============================================================================

/// Insert an object into an already-locked namespace root.
fn insert_inner(
    root: &mut BTreeMap<String, NamespaceEntry>,
    path: &str,
    obj_type: ObjectType,
    sd: Option<SecurityDescriptor>,
    link_target: Option<String>,
) -> bool {
    let parts = parse_path(path);
    if parts.is_empty() { return false; }

    let mut current: &mut BTreeMap<String, NamespaceEntry> = root;
    for i in 0..parts.len() - 1 {
        let part = parts[i];
        if !current.contains_key(part) {
            current.insert(
                String::from(part),
                NamespaceEntry::Directory(BTreeMap::new()),
            );
        }
        match current.get_mut(part) {
            Some(NamespaceEntry::Directory(sub)) => current = sub,
            _ => return false,
        }
    }

    let name = *parts.last().unwrap();
    current.insert(
        String::from(name),
        NamespaceEntry::Object(ObjectHeader {
            name: String::from(name),
            object_type: obj_type,
            ref_count: AtomicUsize::new(1),
            security_descriptor: sd,
            link_target,
            body: None,
        }),
    );

    true
}

/// Walk namespace and return a reference to the entry at `path`.
fn walk_namespace<'a>(
    root: &'a BTreeMap<String, NamespaceEntry>,
    path: &str,
) -> Option<&'a NamespaceEntry> {
    let parts = parse_path(path);
    if parts.is_empty() { return None; }

    let mut current = root;
    for (i, part) in parts.iter().enumerate() {
        match current.get(*part) {
            Some(NamespaceEntry::Directory(sub)) => {
                if i == parts.len() - 1 {
                    return Some(current.get(*part).unwrap());
                }
                current = sub;
            }
            Some(entry) => {
                if i == parts.len() - 1 {
                    return Some(entry);
                }
                return None; // Can't traverse through non-directory
            }
            None => return None,
        }
    }
    None
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the Object Manager.
pub fn init() {
    let mut root = BTreeMap::new();

    // Create standard directories
    let dirs = [
        "Device", "Driver", "ObjectTypes", "BaseNamedObjects",
        "FileSystem", "Callback", "Sessions", "KernelObjects",
        "Security", "GLOBAL??",
    ];

    for name in &dirs {
        root.insert(
            String::from(*name),
            NamespaceEntry::Directory(BTreeMap::new()),
        );
    }

    // Register known object types in \ObjectTypes
    let type_names = [
        "Directory", "Device", "Driver", "SymbolicLink",
        "Event", "Mutant", "Semaphore", "Section",
        "Port", "Process", "Thread", "File", "Key", "Type",
    ];
    if let Some(NamespaceEntry::Directory(ref mut types_dir)) = root.get_mut("ObjectTypes") {
        for tn in &type_names {
            types_dir.insert(
                String::from(*tn),
                NamespaceEntry::Object(ObjectHeader {
                    name: String::from(*tn),
                    object_type: ObjectType::Type,
                    ref_count: AtomicUsize::new(1),
                    security_descriptor: None,
                    link_target: None,
                    body: None,
                }),
            );
        }
    }

    // Create some well-known device objects
    if let Some(NamespaceEntry::Directory(ref mut dev_dir)) = root.get_mut("Device") {
        for dev_name in &["Null", "Console", "Serial0", "Framebuffer0", "E1000"] {
            dev_dir.insert(
                String::from(*dev_name),
                NamespaceEntry::Object(ObjectHeader {
                    name: String::from(*dev_name),
                    object_type: ObjectType::Device,
                    ref_count: AtomicUsize::new(1),
                    security_descriptor: None,
                    link_target: None,
                    body: None,
                }),
            );
        }
    }

    // Create some symbolic links in \GLOBAL??
    if let Some(NamespaceEntry::Directory(ref mut global_dir)) = root.get_mut("GLOBAL??") {
        for (link, target) in &[
            ("C:", "\\Device\\HarddiskVolume1"),
            ("NUL", "\\Device\\Null"),
            ("CON", "\\Device\\Console"),
        ] {
            global_dir.insert(
                String::from(*link),
                NamespaceEntry::Object(ObjectHeader {
                    name: String::from(*link),
                    object_type: ObjectType::SymbolicLink,
                    ref_count: AtomicUsize::new(1),
                    security_descriptor: None,
                    link_target: Some(String::from(*target)),
                    body: None,
                }),
            );
        }
    }

    *NAMESPACE.lock() = Some(root);
    crate::serial_println!("[OB] Object Manager initialized — namespace created");
}

// ============================================================================
// Public API — Namespace operations
// ============================================================================

/// Insert an object into the namespace.
pub fn insert_object(path: &str, obj_type: ObjectType) -> bool {
    let mut ns = NAMESPACE.lock();
    let root = match ns.as_mut() {
        Some(r) => r,
        None => return false,
    };
    insert_inner(root, path, obj_type, None, None)
}

/// Insert an object with a security descriptor.
pub fn insert_object_with_sd(path: &str, obj_type: ObjectType, sd: Option<SecurityDescriptor>) -> bool {
    let mut ns = NAMESPACE.lock();
    let root = match ns.as_mut() {
        Some(r) => r,
        None => return false,
    };
    insert_inner(root, path, obj_type, sd, None)
}

/// Insert a symbolic link object with a target path.
pub fn insert_symlink(path: &str, target: &str) -> bool {
    let mut ns = NAMESPACE.lock();
    let root = match ns.as_mut() {
        Some(r) => r,
        None => return false,
    };
    insert_inner(root, path, ObjectType::SymbolicLink, None, Some(String::from(target)))
}

/// Look up an object's type by its namespace path.
pub fn lookup_object_type(path: &str) -> Option<ObjectType> {
    let ns = NAMESPACE.lock();
    let root = ns.as_ref()?;
    match walk_namespace(root, path)? {
        NamespaceEntry::Directory(_) => Some(ObjectType::Directory),
        NamespaceEntry::Object(h) => Some(h.object_type),
    }
}

/// Check whether an object exists at the given path.
pub fn has_object(path: &str) -> bool {
    let ns = NAMESPACE.lock();
    let root = match ns.as_ref() {
        Some(r) => r,
        None => return false,
    };
    walk_namespace(root, path).is_some()
}

/// Resolve a symbolic link, returning the target path.
pub fn resolve_symlink(path: &str) -> Option<String> {
    let ns = NAMESPACE.lock();
    let root = ns.as_ref()?;
    match walk_namespace(root, path)? {
        NamespaceEntry::Object(h) if h.object_type == ObjectType::SymbolicLink => {
            h.link_target.clone()
        }
        _ => None,
    }
}

/// Get a clone of the security descriptor for an object, if any.
pub fn get_object_security_descriptor(path: &str) -> Option<SecurityDescriptor> {
    let ns = NAMESPACE.lock();
    let root = ns.as_ref()?;
    match walk_namespace(root, path)? {
        NamespaceEntry::Object(h) => h.security_descriptor.clone(),
        NamespaceEntry::Directory(_) => None,
    }
}

/// Remove an object from the namespace. Returns true if it was found and removed.
pub fn remove_object(path: &str) -> bool {
    let mut ns = NAMESPACE.lock();
    let root = match ns.as_mut() {
        Some(r) => r,
        None => return false,
    };

    let parts = parse_path(path);
    if parts.is_empty() { return false; }

    let mut current: &mut BTreeMap<String, NamespaceEntry> = root;
    for i in 0..parts.len() - 1 {
        let part = parts[i];
        match current.get_mut(part) {
            Some(NamespaceEntry::Directory(sub)) => current = sub,
            _ => return false,
        }
    }

    let name = *parts.last().unwrap();
    current.remove(name).is_some()
}

/// Dump the namespace at the given path for shell display.
///
/// Path uses NT convention: `\` is root, `\Device` for device directory, etc.
pub fn dump_namespace(path: &str) {
    let ns = NAMESPACE.lock();
    let root = match ns.as_ref() {
        Some(r) => r,
        None => {
            crate::kprintln!("Object Manager not initialized");
            return;
        }
    };

    if path == "\\" || path == "/" || path.is_empty() {
        // Dump root
        crate::kprintln!("\\");
        for (name, entry) in root.iter() {
            let type_str = match entry {
                NamespaceEntry::Directory(_) => "Directory",
                NamespaceEntry::Object(h) => h.object_type.name(),
            };
            crate::kprintln!("  \\{}  [{}]", name, type_str);
        }
        return;
    }

    // Walk path
    let clean = path.trim_start_matches('\\').trim_start_matches('/');
    let parts: Vec<&str> = clean.split(|c| c == '\\' || c == '/').filter(|s| !s.is_empty()).collect();

    let mut current: &BTreeMap<String, NamespaceEntry> = root;
    for (i, part) in parts.iter().enumerate() {
        match current.get(*part) {
            Some(NamespaceEntry::Directory(sub)) => {
                if i == parts.len() - 1 {
                    // This is the target directory — dump it
                    crate::kprintln!("\\{}", parts.join("\\"));
                    if sub.is_empty() {
                        crate::kprintln!("  (empty)");
                    }
                    for (name, entry) in sub.iter() {
                        let type_str = match entry {
                            NamespaceEntry::Directory(_) => "Directory",
                            NamespaceEntry::Object(h) => h.object_type.name(),
                        };
                        crate::kprintln!("  \\{}\\{}  [{}]", parts.join("\\"), name, type_str);
                    }
                    return;
                }
                current = sub;
            }
            Some(NamespaceEntry::Object(header)) => {
                crate::kprintln!("Object: \\{}", parts[..=i].join("\\"));
                crate::kprintln!("  Type:     {}", header.object_type.name());
                crate::kprintln!("  RefCount: {}", header.ref_count.load(Ordering::Relaxed));
                return;
            }
            None => {
                crate::kprintln!("Object not found: \\{}", parts.join("\\"));
                return;
            }
        }
    }
}
