//! NT Object Manager — Kernel Object Namespace
//!
//! Implements an NT-style hierarchical kernel object namespace.  Public
//! reference for the model: Microsoft Learn / Windows Driver Kit
//! "Kernel-Mode Driver Programming — Windows Kernel Objects".  Every
//! kernel entity (device, file, process, semaphore, etc.) is represented
//! as a named object in this namespace.
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

/// Increment the reference count on the object at `path`.  Returns the
/// **new** count, or `None` if no object exists at that path (the caller
/// holds a free-floating path that was never inserted into the namespace —
/// e.g. an ephemeral `HandleEntry::object_path` used purely for handle-table
/// bookkeeping).  Public reference for the model: WDK
/// `ObReferenceObject` documentation on Microsoft Learn — the sanctioned
/// way to keep an object alive across a window where another caller
/// might attempt to delete it.  Per the design intent of this module,
/// an object with a live handle (or other named-object reference) must
/// not vanish from the namespace just because some other path called
/// `remove_object` on the same name — the recycle-while-aliased pattern
/// is the dual of the W215 page-aliasing class in physical memory.
///
/// Note on ordering: `NAMESPACE.lock()` already serialises every public
/// entry point here, so the per-slot `AcqRel` on the atomic increment is
/// strictly redundant for cross-thread visibility under the namespace
/// lock.  We keep `AcqRel` for symmetry with [`obref_dec`] (whose CAS
/// loop uses the same ordering, see Intel SDM Vol. 3A §8.2.2) and to
/// keep the atomic semantically explicit in isolation.
pub fn obref_inc(path: &str) -> Option<usize> {
    let ns = NAMESPACE.lock();
    let root = ns.as_ref()?;
    match walk_namespace(root, path)? {
        NamespaceEntry::Object(h) => Some(h.ref_count.fetch_add(1, Ordering::AcqRel) + 1),
        NamespaceEntry::Directory(_) => None,
    }
}

/// Decrement the reference count on the object at `path`.  Returns the
/// **new** count, or `None` if no object exists at that path.  A return
/// value of `Some(0)` indicates the caller has released the last reference
/// and the object may now be safely removed via [`remove_object`].  The
/// decrement uses a compare-exchange loop so a count that is already 0 is
/// left at 0 (the pre-loop `fetch_sub(1)` form would wrap an `AtomicUsize`
/// through `usize::MAX`, leaking the slot to "live forever" status).
///
/// The use pattern mirrors the WDK `ObDereferenceObject` discipline: pair
/// every `obref_inc(path)` with exactly one `obref_dec(path)`.  This
/// module does NOT auto-delete when the count reaches zero — callers
/// who want refcount-driven deletion call `remove_object` themselves once
/// they observe `Some(0)`; this keeps the namespace operation explicit
/// rather than buried inside a refcount decrement, matching how
/// `pmm::free_page` is explicit at the physical-frame layer.
///
/// The CAS uses `AcqRel` on success and `Acquire` on failure so that any
/// non-free-path consumer that orders a subsequent action on the
/// observed-zero result sees a proper acquire fence.  Per Intel SDM
/// Vol. 3A §8.2.2 `LOCK CMPXCHG` is already fully ordered on x86, so
/// this is a no-op at runtime but more semantically explicit and forward-
/// portable to weaker-ordered ISAs.
pub fn obref_dec(path: &str) -> Option<usize> {
    let ns = NAMESPACE.lock();
    let root = ns.as_ref()?;
    let header = match walk_namespace(root, path)? {
        NamespaceEntry::Object(h) => h,
        NamespaceEntry::Directory(_) => return None,
    };
    // CAS-loop so a slot at 0 is left at 0 (cf. the same discipline applied
    // to physical-frame refcounts in `mm::refcount::page_ref_dec`).
    let mut cur = header.ref_count.load(Ordering::Acquire);
    loop {
        if cur == 0 {
            return Some(0);
        }
        match header.ref_count.compare_exchange_weak(
            cur,
            cur - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(cur - 1),
            Err(observed) => cur = observed,
        }
    }
}

/// Snapshot the current reference count for the object at `path`.  Returns
/// `None` if no object exists at that path.  Diagnostic / test-only —
/// the name carries the "this is a snapshot, do not race on it" semantics
/// explicitly: kernel code that depends on the count's value MUST use
/// the `obref_inc` / `obref_dec` pair to keep the underlying object alive
/// rather than acting on the value returned here.
pub fn peek_object_refcount(path: &str) -> Option<usize> {
    let ns = NAMESPACE.lock();
    let root = ns.as_ref()?;
    match walk_namespace(root, path)? {
        NamespaceEntry::Object(h) => Some(h.ref_count.load(Ordering::Acquire)),
        NamespaceEntry::Directory(_) => None,
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
///
/// **Forcible removal** — this function does not consult the object's
/// reference count.  Callers that want to defer removal until every handle
/// has been closed should use [`remove_object_if_unreferenced`] instead.
/// The two-variant API mirrors the NT object manager split between
/// `ObCloseHandle` (which decrements and may auto-cleanup) and
/// `ObMakeTemporaryObject` + final dereference (which sets the temporary
/// flag and lets the last reference release trigger the cleanup).
///
/// Forcible removal remains the right primitive for fixed-namespace
/// cleanup paths (e.g. test-suite teardown, driver unload) where the
/// caller has already proved no other component holds a reference.
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

/// Outcome of [`remove_object_if_unreferenced`].  Names every distinct
/// state explicitly so callers can pattern-match on intent rather than
/// disambiguating `Ok(true)` / `Ok(false)` / `Err(())` at call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// Object existed with refcount ≤ 1 and was removed.
    Removed,
    /// Object existed but had refcount > 1; removal refused.  The slot is
    /// left in place so the live referrers continue to observe a valid
    /// object at this path.
    RefusedRefcount,
    /// No object at `path` to remove (caller can treat this the same as
    /// "already removed").
    NotFound,
}

/// Remove the object at `path` only if its reference count is at most 1
/// (i.e. no caller has bumped the refcount via [`obref_inc`]).
///
/// Returns a [`RemoveOutcome`] naming the disposition explicitly.  The
/// "≤ 1" threshold (rather than "== 0") accommodates the convention set
/// by [`insert_inner`]: every freshly-inserted object starts with
/// `ref_count = 1` representing the namespace's own ownership of the
/// slot.  A caller that has not bumped the count via [`obref_inc`] sees
/// refcount 1 and the removal succeeds; an additional `obref_inc` (e.g.
/// via [`crate::ob::handle::HandleTable::allocate`]) pushes the count to
/// 2+ and removal is refused until the matching [`obref_dec`] runs.
pub fn remove_object_if_unreferenced(path: &str) -> RemoveOutcome {
    let mut ns = NAMESPACE.lock();
    let root = match ns.as_mut() {
        Some(r) => r,
        None => return RemoveOutcome::NotFound,
    };

    let parts = parse_path(path);
    if parts.is_empty() { return RemoveOutcome::NotFound; }

    let mut current: &mut BTreeMap<String, NamespaceEntry> = root;
    for i in 0..parts.len() - 1 {
        let part = parts[i];
        match current.get_mut(part) {
            Some(NamespaceEntry::Directory(sub)) => current = sub,
            _ => return RemoveOutcome::NotFound,
        }
    }

    let name = *parts.last().unwrap();
    // Inspect the refcount under the namespace lock so a concurrent
    // `obref_inc` cannot squeeze in between the check and the removal.
    match current.get(name) {
        Some(NamespaceEntry::Object(h)) => {
            if h.ref_count.load(Ordering::Acquire) > 1 {
                return RemoveOutcome::RefusedRefcount;
            }
        }
        Some(NamespaceEntry::Directory(_)) => {
            // Directories have no ref_count of their own; leave the
            // existing forcible-removal semantics to `remove_object`.
            return RemoveOutcome::NotFound;
        }
        None => return RemoveOutcome::NotFound,
    }
    if current.remove(name).is_some() {
        RemoveOutcome::Removed
    } else {
        RemoveOutcome::NotFound
    }
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
