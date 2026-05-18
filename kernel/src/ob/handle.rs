//! Per-Process Handle Table
//!
//! Maps integer handles to kernel objects in the OB namespace.  Public
//! reference for the NT-style handle-table model: Microsoft Learn /
//! Windows Driver Kit "Handles and Objects" (`ZwClose`, `OBJECT_HANDLE_INFORMATION`).
//!
//! # Handle Values
//! - Handle 0 is reserved/invalid.
//! - Handle values are multiples of 4 (NT convention), starting from 4.
//! - Each handle carries the object path, type, granted access mask, and
//!   an inheritable flag for child process inheritance.
//!
//! # Reference-count discipline
//!
//! Every `allocate` / `duplicate` call increments the reference count on
//! the underlying object in the OB namespace via [`crate::ob::obref_inc`].
//! Every `close` decrements via [`crate::ob::obref_dec`].  Together with
//! [`crate::ob::remove_object_if_unreferenced`] this enforces the WDK
//! discipline that an object cannot be removed while a live handle
//! references it.
//!
//! Refcount calls are *best-effort* against the namespace lookup —
//! handles may carry ephemeral paths that were never inserted (e.g. test
//! fixtures that construct a `HandleEntry` directly without first calling
//! `ob::insert_object`).  For those, `obref_inc` returns `None` and we
//! treat the handle as free-floating; `close` likewise no-ops the decrement.
//! This preserves backward compatibility while still extending the
//! namespace-integrated path with correctness when both halves are in
//! play.  Public test cases (test 23 in `test_runner.rs`) cover both
//! patterns to lock the discipline in place.
//!
//! # Lock order
//!
//! Both `allocate` / `duplicate` / `close` and `Drop` call into the
//! refcount helpers in [`crate::ob`], which acquire `NAMESPACE.lock()`.
//! Callers therefore MUST NOT hold `NAMESPACE.lock()` when invoking
//! these methods or when dropping a `HandleTable` — doing so would
//! re-enter the namespace mutex and deadlock.  The convention is:
//! acquire the handle table's outer mutex (per-process), then call the
//! handle-table method, which transiently takes `NAMESPACE.lock()`
//! internally and releases it before returning.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use crate::ob::ObjectType;

/// A single entry in the handle table.
#[derive(Debug, Clone)]
pub struct HandleEntry {
    /// Path to the object in the OB namespace (e.g. `\Device\Null`).
    pub object_path: String,
    /// Cached type of the referenced object.
    pub object_type: ObjectType,
    /// Access mask granted when the handle was opened.
    pub granted_access: u32,
    /// Whether this handle is inherited by child processes.
    pub inheritable: bool,
}

/// Per-process handle table — maps integer handle values to object references.
pub struct HandleTable {
    entries: BTreeMap<u32, HandleEntry>,
    next_handle: u32,
}

impl HandleTable {
    /// Create an empty handle table. First allocated handle will be 4.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_handle: 4,
        }
    }

    /// Allocate a new handle for the given entry. Returns the handle value.
    ///
    /// Calls [`crate::ob::obref_inc`] for the entry's `object_path`; if the
    /// path is not in the namespace, the increment is silently skipped (the
    /// handle is treated as carrying a free-floating reference, matching
    /// pre-refcount semantics).
    pub fn allocate(&mut self, entry: HandleEntry) -> u32 {
        // Best-effort refcount bump.  Discarded result: a return of `None`
        // simply means the path is not (yet) in the namespace and the
        // handle is free-floating — caller is responsible for ensuring
        // the eventual `close` matches.
        let _ = crate::ob::obref_inc(&entry.object_path);
        let handle = self.next_handle;
        self.next_handle += 4; // NT-style: multiples of 4
        self.entries.insert(handle, entry);
        handle
    }

    /// Look up a handle entry by handle value.
    pub fn lookup(&self, handle: u32) -> Option<&HandleEntry> {
        self.entries.get(&handle)
    }

    /// Close (remove) a handle. Returns true if the handle existed.
    ///
    /// Calls [`crate::ob::obref_dec`] for the entry's `object_path` (best
    /// effort — see [`Self::allocate`] for the same discipline).
    pub fn close(&mut self, handle: u32) -> bool {
        match self.entries.remove(&handle) {
            Some(e) => {
                let _ = crate::ob::obref_dec(&e.object_path);
                true
            }
            None => false,
        }
    }

    /// Duplicate a handle, optionally changing the granted access mask.
    /// Returns the new handle value, or None if the source handle doesn't exist.
    ///
    /// Calls [`crate::ob::obref_inc`] for the entry's `object_path` so the
    /// duplicate is reference-balanced — each handle holds exactly one
    /// reference to the underlying object regardless of how it was created
    /// (`allocate` or `duplicate`).
    pub fn duplicate(&mut self, src_handle: u32, desired_access: u32) -> Option<u32> {
        let src = self.entries.get(&src_handle)?;
        let new_entry = HandleEntry {
            object_path: src.object_path.clone(),
            object_type: src.object_type,
            granted_access: desired_access,
            inheritable: src.inheritable,
        };
        // The duplicate carries its own reference — best-effort bump.
        let _ = crate::ob::obref_inc(&new_entry.object_path);
        let new_handle = self.next_handle;
        self.next_handle += 4;
        self.entries.insert(new_handle, new_entry);
        Some(new_handle)
    }

    /// Return the number of open handles.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

impl Drop for HandleTable {
    /// Releases every outstanding handle's reference at table teardown.
    /// Without this, a process whose `HandleTable` is destroyed (e.g. on
    /// reap) leaks `obref_inc`s for every still-open handle and the
    /// corresponding namespace objects can never be freed via
    /// [`crate::ob::remove_object_if_unreferenced`].
    fn drop(&mut self) {
        for (_h, e) in self.entries.iter() {
            let _ = crate::ob::obref_dec(&e.object_path);
        }
    }
}
