//! Per-Process Handle Table
//!
//! Maps integer handles to kernel objects in the OB namespace.
//! Inspired by the NT Executive handle table (ntoskrnl/ex/handle.c).
//!
//! # Handle Values
//! - Handle 0 is reserved/invalid.
//! - Handle values are multiples of 4 (NT convention), starting from 4.
//! - Each handle carries the object path, type, granted access mask, and
//!   an inheritable flag for child process inheritance.

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
    pub fn allocate(&mut self, entry: HandleEntry) -> u32 {
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
    pub fn close(&mut self, handle: u32) -> bool {
        self.entries.remove(&handle).is_some()
    }

    /// Duplicate a handle, optionally changing the granted access mask.
    /// Returns the new handle value, or None if the source handle doesn't exist.
    pub fn duplicate(&mut self, src_handle: u32, desired_access: u32) -> Option<u32> {
        let src = self.entries.get(&src_handle)?;
        let new_entry = HandleEntry {
            object_path: src.object_path.clone(),
            object_type: src.object_type,
            granted_access: desired_access,
            inheritable: src.inheritable,
        };
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
