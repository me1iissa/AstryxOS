//! Security Subsystem — NT-Inspired Object Security Model
//!
//! Provides a unified security model for all kernel objects (files, processes,
//! sockets, pipes, devices, etc.), combining NT security descriptor semantics
//! with POSIX permission compatibility.
//!
//! # Architecture
//! - **SecurityId (SID)** — Identifies a security principal (user or group).
//! - **AccessMask** — Bitflags describing desired/granted access rights.
//! - **AccessControlEntry (ACE)** — Allow or deny a specific SID a set of access rights.
//! - **AccessControlList (ACL)** — Ordered list of ACEs (DACL for access, SACL for audit).
//! - **SecurityDescriptor** — Attached to every kernel object; contains owner, group, DACL.
//! - **SecuritySubject** — Represents the caller's identity during access checks.
//!
//! # POSIX Compatibility
//! Traditional Unix mode bits (rwxrwxrwx) are stored alongside the DACL for
//! compatibility with POSIX syscalls (chmod, chown, stat). The DACL takes
//! precedence when present; mode bits are a fallback and are kept in sync.
//!
//! # Usage
//! ```ignore
//! let subject = SecuritySubject::from_process(pid);
//! let sd = object.security_descriptor();
//! if !check_access(&subject, &sd, ACCESS_READ | ACCESS_WRITE) {
//!     return Err(VfsError::PermissionDenied);
//! }
//! ```

pub mod sid;
pub mod privilege;
pub mod token;

extern crate alloc;

use alloc::vec::Vec;

// Re-export key types for convenience.
pub use sid::Sid;
pub use privilege::{Privilege, PrivilegeAttributes, TokenPrivilege};
pub use token::{AccessToken, TokenType, ImpersonationLevel, TokenGroup, TokenSource};

// ============================================================================
// Security Identifiers (SIDs)
// ============================================================================

/// A Security Identifier — uniquely identifies a user or group.
///
/// Modelled after NT SIDs but simplified to a single u32 for POSIX uid/gid
/// compatibility. Special well-known SIDs use reserved ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecurityId(pub u32);

impl SecurityId {
    /// The root/SYSTEM account — bypasses all access checks.
    pub const SYSTEM: SecurityId = SecurityId(0);
    /// The "nobody" account — minimum privileges.
    pub const NOBODY: SecurityId = SecurityId(65534);
    /// Well-known group: "wheel" / administrators.
    pub const WHEEL: SecurityId = SecurityId(0); // GID 0
    /// Well-known group: "users".
    pub const USERS: SecurityId = SecurityId(100);

    /// Create a SID from a POSIX uid or gid.
    pub const fn from_id(id: u32) -> Self {
        SecurityId(id)
    }

    /// Check if this is the root/SYSTEM SID.
    pub const fn is_root(&self) -> bool {
        self.0 == 0
    }
}

// ============================================================================
// Access Mask — Bitflags for access rights
// ============================================================================

/// Access rights bitflags. Combines generic, standard, and object-specific rights.
///
/// Layout (inspired by NT ACCESS_MASK):
/// - Bits 0-15: Object-specific rights
/// - Bits 16-23: Standard rights
/// - Bits 24-27: Reserved
/// - Bits 28-31: Generic rights
pub type AccessMask = u32;

// --- Generic rights (bits 28-31) ---
/// Generic read access.
pub const GENERIC_READ: AccessMask = 1 << 31;
/// Generic write access.
pub const GENERIC_WRITE: AccessMask = 1 << 30;
/// Generic execute access.
pub const GENERIC_EXECUTE: AccessMask = 1 << 29;
/// Generic all access (full control).
pub const GENERIC_ALL: AccessMask = 1 << 28;

// --- Standard rights (bits 16-23) ---
/// Right to delete the object.
pub const ACCESS_DELETE: AccessMask = 1 << 16;
/// Right to read the security descriptor.
pub const READ_CONTROL: AccessMask = 1 << 17;
/// Right to modify the DACL.
pub const WRITE_DAC: AccessMask = 1 << 18;
/// Right to change the owner.
pub const WRITE_OWNER: AccessMask = 1 << 19;
/// Right to synchronize on the object.
pub const SYNCHRONIZE: AccessMask = 1 << 20;

// --- Object-specific rights (bits 0-15) ---
// File/directory rights:
/// Read data from a file / list directory contents.
pub const FILE_READ_DATA: AccessMask = 1 << 0;
/// Write data to a file / add a file to a directory.
pub const FILE_WRITE_DATA: AccessMask = 1 << 1;
/// Append data to a file / add a subdirectory.
pub const FILE_APPEND_DATA: AccessMask = 1 << 2;
/// Execute a file / traverse a directory.
pub const FILE_EXECUTE: AccessMask = 1 << 3;
/// Read file attributes.
pub const FILE_READ_ATTRIBUTES: AccessMask = 1 << 4;
/// Write file attributes.
pub const FILE_WRITE_ATTRIBUTES: AccessMask = 1 << 5;
/// Read extended attributes.
pub const FILE_READ_EA: AccessMask = 1 << 6;
/// Write extended attributes.
pub const FILE_WRITE_EA: AccessMask = 1 << 7;

// Process rights:
/// Terminate a process.
pub const PROCESS_TERMINATE: AccessMask = 1 << 0;
/// Create a new thread in the process.
pub const PROCESS_CREATE_THREAD: AccessMask = 1 << 1;
/// Read process memory.
pub const PROCESS_VM_READ: AccessMask = 1 << 3;
/// Write process memory.
pub const PROCESS_VM_WRITE: AccessMask = 1 << 4;
/// Duplicate a handle.
pub const PROCESS_DUP_HANDLE: AccessMask = 1 << 5;
/// Query process information.
pub const PROCESS_QUERY_INFO: AccessMask = 1 << 10;

// Socket/pipe rights (reuse file bits 0-3):
/// Read from socket/pipe.
pub const SOCKET_READ: AccessMask = FILE_READ_DATA;
/// Write to socket/pipe.
pub const SOCKET_WRITE: AccessMask = FILE_WRITE_DATA;
/// Connect/accept on socket.
pub const SOCKET_CONNECT: AccessMask = 1 << 8;
/// Bind/listen on socket.
pub const SOCKET_BIND: AccessMask = 1 << 9;

// Convenience aggregates:
/// Standard file read (data + attributes + read control).
pub const FILE_GENERIC_READ: AccessMask =
    FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
/// Standard file write.
pub const FILE_GENERIC_WRITE: AccessMask =
    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | SYNCHRONIZE;
/// Standard file execute.
pub const FILE_GENERIC_EXECUTE: AccessMask = FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
/// Full file control.
pub const FILE_ALL_ACCESS: AccessMask =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | ACCESS_DELETE | WRITE_DAC | WRITE_OWNER;

// ============================================================================
// Access Control Entries (ACEs)
// ============================================================================

/// The type of an ACE — allow, deny, or audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceType {
    /// Grants the specified access rights.
    Allow,
    /// Explicitly denies the specified access rights.
    Deny,
    /// Logs access attempts (for SACL).
    Audit,
}

/// A single Access Control Entry.
#[derive(Debug, Clone)]
pub struct AccessControlEntry {
    /// Whether this ACE allows, denies, or audits.
    pub ace_type: AceType,
    /// The security principal this ACE applies to.
    pub sid: SecurityId,
    /// The access rights this ACE grants or denies.
    pub mask: AccessMask,
    /// Inheritance flags (for directories: propagate to children).
    pub flags: AceFlags,
}

/// ACE inheritance flags.
pub type AceFlags = u8;
/// ACE is inherited by child objects.
pub const ACE_OBJECT_INHERIT: AceFlags = 1 << 0;
/// ACE is inherited by child containers (directories).
pub const ACE_CONTAINER_INHERIT: AceFlags = 1 << 1;
/// ACE does not apply to this object, only to children.
pub const ACE_INHERIT_ONLY: AceFlags = 1 << 2;

// ============================================================================
// Access Control Lists (ACLs)
// ============================================================================

/// A Discretionary Access Control List — ordered list of ACEs.
///
/// ACE evaluation order: deny ACEs are checked first, then allow ACEs.
/// If no ACE matches, access is denied (closed by default).
#[derive(Debug, Clone)]
pub struct Acl {
    pub entries: Vec<AccessControlEntry>,
}

impl Acl {
    /// Create an empty ACL (denies all access).
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create an ACL from POSIX mode bits.
    ///
    /// Generates three ACEs: owner, group, other.
    pub fn from_mode(owner: SecurityId, group: SecurityId, mode: u32) -> Self {
        let mut entries = Vec::new();

        // Owner ACE
        let owner_mask = mode_to_mask((mode >> 6) & 0o7);
        if owner_mask != 0 {
            entries.push(AccessControlEntry {
                ace_type: AceType::Allow,
                sid: owner,
                mask: owner_mask,
                flags: 0,
            });
        }

        // Group ACE
        let group_mask = mode_to_mask((mode >> 3) & 0o7);
        if group_mask != 0 {
            entries.push(AccessControlEntry {
                ace_type: AceType::Allow,
                sid: group,
                mask: group_mask,
                flags: 0,
            });
        }

        // Others ACE — use a well-known "Everyone" SID (we use NOBODY as placeholder)
        let other_mask = mode_to_mask(mode & 0o7);
        if other_mask != 0 {
            entries.push(AccessControlEntry {
                ace_type: AceType::Allow,
                sid: SID_EVERYONE,
                mask: other_mask,
                flags: 0,
            });
        }

        Self { entries }
    }

    /// Add a new ACE to the list.
    pub fn add_ace(&mut self, ace: AccessControlEntry) {
        self.entries.push(ace);
    }
}

/// Well-known SID representing "everyone" / "world".
pub const SID_EVERYONE: SecurityId = SecurityId(0xFFFF_FFFF);

/// Convert POSIX rwx bits (0-7) to an AccessMask.
fn mode_to_mask(rwx: u32) -> AccessMask {
    let mut mask: AccessMask = 0;
    if rwx & 4 != 0 {
        mask |= FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL;
    }
    if rwx & 2 != 0 {
        mask |= FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
    }
    if rwx & 1 != 0 {
        mask |= FILE_EXECUTE;
    }
    mask
}

/// Convert an AccessMask back to POSIX rwx bits (0-7).
pub fn mask_to_mode(mask: AccessMask) -> u32 {
    let mut mode = 0u32;
    if mask & FILE_READ_DATA != 0 {
        mode |= 4;
    }
    if mask & FILE_WRITE_DATA != 0 {
        mode |= 2;
    }
    if mask & FILE_EXECUTE != 0 {
        mode |= 1;
    }
    mode
}

// ============================================================================
// Security Descriptor
// ============================================================================

/// A Security Descriptor — the complete security metadata for a kernel object.
///
/// Every kernel object (file, process, socket, pipe, device, etc.) has one.
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    /// Owner of the object.
    pub owner: SecurityId,
    /// Primary group of the object.
    pub group: SecurityId,
    /// Discretionary ACL — controls access to the object.
    pub dacl: Option<Acl>,
    /// System ACL — controls auditing (optional, rarely used).
    pub sacl: Option<Acl>,
    /// POSIX mode bits (kept in sync with DACL for compatibility).
    /// Format: 0oUGO (e.g., 0o755).
    pub mode: u32,
}

impl SecurityDescriptor {
    /// Create a security descriptor with the given owner, group, and POSIX mode.
    /// Automatically generates a DACL from the mode bits.
    pub fn new(owner: SecurityId, group: SecurityId, mode: u32) -> Self {
        let dacl = Acl::from_mode(owner, group, mode);
        Self {
            owner,
            group,
            dacl: Some(dacl),
            sacl: None,
            mode,
        }
    }

    /// Create a security descriptor for a root-owned system object (mode 0755).
    pub fn system_default() -> Self {
        Self::new(SecurityId::SYSTEM, SecurityId::WHEEL, 0o755)
    }

    /// Create a security descriptor for a root-owned read-only object (mode 0444).
    pub fn system_readonly() -> Self {
        Self::new(SecurityId::SYSTEM, SecurityId::WHEEL, 0o444)
    }

    /// Create a security descriptor for a user-owned file with typical defaults.
    pub fn user_file(uid: u32, gid: u32) -> Self {
        Self::new(SecurityId::from_id(uid), SecurityId::from_id(gid), 0o644)
    }

    /// Create a security descriptor for a user-owned directory.
    pub fn user_dir(uid: u32, gid: u32) -> Self {
        Self::new(SecurityId::from_id(uid), SecurityId::from_id(gid), 0o755)
    }

    /// Create a security descriptor for a user-owned executable.
    pub fn user_executable(uid: u32, gid: u32) -> Self {
        Self::new(SecurityId::from_id(uid), SecurityId::from_id(gid), 0o755)
    }

    /// Update the POSIX mode and regenerate the DACL.
    pub fn set_mode(&mut self, mode: u32) {
        self.mode = mode;
        self.dacl = Some(Acl::from_mode(self.owner, self.group, mode));
    }

    /// Change the owner and regenerate the DACL.
    pub fn set_owner(&mut self, owner: SecurityId) {
        self.owner = owner;
        self.dacl = Some(Acl::from_mode(self.owner, self.group, self.mode));
    }

    /// Change the group and regenerate the DACL.
    pub fn set_group(&mut self, group: SecurityId) {
        self.group = group;
        self.dacl = Some(Acl::from_mode(self.owner, self.group, self.mode));
    }
}

// ============================================================================
// Security Subject — represents a caller's identity
// ============================================================================

/// A security subject — the identity and privileges of a thread making
/// an access request.
#[derive(Debug, Clone)]
pub struct SecuritySubject {
    /// Effective user ID.
    pub uid: SecurityId,
    /// Effective group ID.
    pub gid: SecurityId,
    /// Supplementary group memberships.
    pub groups: Vec<SecurityId>,
    /// Whether this subject has system/root privileges.
    pub is_privileged: bool,
}

impl SecuritySubject {
    /// Create a subject with root/SYSTEM privileges.
    pub fn system() -> Self {
        Self {
            uid: SecurityId::SYSTEM,
            gid: SecurityId::WHEEL,
            groups: Vec::new(),
            is_privileged: true,
        }
    }

    /// Create a subject from a uid/gid.
    pub fn from_credentials(uid: u32, gid: u32, groups: &[u32]) -> Self {
        Self {
            uid: SecurityId::from_id(uid),
            gid: SecurityId::from_id(gid),
            groups: groups.iter().map(|&g| SecurityId::from_id(g)).collect(),
            is_privileged: uid == 0,
        }
    }

    /// Create a subject from the current process's credentials.
    pub fn from_current_process() -> Self {
        let pid = crate::proc::current_pid();
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
            Self {
                uid: SecurityId::from_id(proc.uid),
                gid: SecurityId::from_id(proc.gid),
                groups: proc.supplementary_groups.iter()
                    .map(|&g| SecurityId::from_id(g))
                    .collect(),
                is_privileged: proc.uid == 0,
            }
        } else {
            // Fallback to SYSTEM if process not found (shouldn't happen)
            Self::system()
        }
    }

    /// Check if the subject is a member of the given group SID.
    pub fn is_member_of(&self, group: SecurityId) -> bool {
        self.gid == group || self.groups.contains(&group)
    }
}

// ============================================================================
// Access Check — the core security evaluation function
// ============================================================================

/// Check whether a security subject is allowed the requested access to an object.
///
/// # Algorithm
/// 1. Root/SYSTEM always gets access (except execute on non-executable files).
/// 2. If a DACL is present, evaluate ACEs in order:
///    - Deny ACEs are processed first.
///    - Then Allow ACEs.
///    - An ACE matches if the subject's UID/GID/groups match the ACE's SID.
/// 3. If no DACL, fall back to POSIX mode bit checks.
/// 4. Default-deny: if no ACE grants the access, it's denied.
///
/// # Returns
/// `true` if access is granted, `false` if denied.
pub fn check_access(
    subject: &SecuritySubject,
    sd: &SecurityDescriptor,
    desired_access: AccessMask,
) -> bool {
    // Rule 1: SYSTEM/root bypasses all checks (with nuance for execute)
    if subject.is_privileged {
        // Root can do anything except execute a file that has no execute bit at all.
        // This matches Linux kernel behavior (CAP_DAC_OVERRIDE).
        if desired_access & FILE_EXECUTE != 0 {
            // Root can execute if ANY execute bit is set in mode
            if sd.mode & 0o111 == 0 {
                return false;
            }
        }
        return true;
    }

    // Rule 2: Check DACL if present
    if let Some(ref dacl) = sd.dacl {
        return evaluate_dacl(subject, dacl, sd, desired_access);
    }

    // Rule 3: Fallback to POSIX mode bits
    check_mode_bits(subject, sd, desired_access)
}

/// Evaluate a DACL against a subject and desired access.
fn evaluate_dacl(
    subject: &SecuritySubject,
    dacl: &Acl,
    sd: &SecurityDescriptor,
    desired_access: AccessMask,
) -> bool {
    let mut remaining = desired_access;

    // Pass 1: Check deny ACEs
    for ace in &dacl.entries {
        if ace.ace_type != AceType::Deny {
            continue;
        }
        if ace.flags & ACE_INHERIT_ONLY != 0 {
            continue;
        }
        if ace_matches_subject(ace, subject, sd) {
            // If any denied bit overlaps with desired, deny immediately
            if ace.mask & desired_access != 0 {
                return false;
            }
        }
    }

    // Pass 2: Check allow ACEs
    for ace in &dacl.entries {
        if ace.ace_type != AceType::Allow {
            continue;
        }
        if ace.flags & ACE_INHERIT_ONLY != 0 {
            continue;
        }
        if ace_matches_subject(ace, subject, sd) {
            remaining &= !ace.mask;
            if remaining == 0 {
                return true; // All desired access granted
            }
        }
    }

    // Default deny: some requested access was not granted
    false
}

/// Check if an ACE applies to a given security subject.
fn ace_matches_subject(
    ace: &AccessControlEntry,
    subject: &SecuritySubject,
    sd: &SecurityDescriptor,
) -> bool {
    // Match owner
    if ace.sid == sd.owner && subject.uid == sd.owner {
        return true;
    }
    // Match group
    if ace.sid == sd.group && subject.is_member_of(sd.group) {
        return true;
    }
    // Match "everyone" SID
    if ace.sid == SID_EVERYONE {
        return true;
    }
    // Match specific SID
    if ace.sid == subject.uid {
        return true;
    }
    // Match group memberships
    if subject.is_member_of(ace.sid) {
        return true;
    }
    false
}

/// Fallback: check POSIX mode bits.
fn check_mode_bits(
    subject: &SecuritySubject,
    sd: &SecurityDescriptor,
    desired_access: AccessMask,
) -> bool {
    let mode_bits = if subject.uid == sd.owner {
        (sd.mode >> 6) & 0o7
    } else if subject.is_member_of(sd.group) {
        (sd.mode >> 3) & 0o7
    } else {
        sd.mode & 0o7
    };

    let allowed = mode_to_mask(mode_bits);
    (desired_access & allowed) == desired_access
}

// ============================================================================
// Convenience functions for common checks
// ============================================================================

/// Check if the current process can read an object.
pub fn can_read(sd: &SecurityDescriptor) -> bool {
    let subject = SecuritySubject::from_current_process();
    check_access(&subject, sd, FILE_READ_DATA)
}

/// Check if the current process can write an object.
pub fn can_write(sd: &SecurityDescriptor) -> bool {
    let subject = SecuritySubject::from_current_process();
    check_access(&subject, sd, FILE_WRITE_DATA)
}

/// Check if the current process can execute a file.
pub fn can_execute(sd: &SecurityDescriptor) -> bool {
    let subject = SecuritySubject::from_current_process();
    check_access(&subject, sd, FILE_EXECUTE)
}

/// Check if the current process can delete an object.
pub fn can_delete(sd: &SecurityDescriptor) -> bool {
    let subject = SecuritySubject::from_current_process();
    check_access(&subject, sd, ACCESS_DELETE)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the security subsystem.
pub fn init() {
    crate::serial_println!("[SEC] Security subsystem initialized (NT-style ACLs + POSIX mode + Tokens/SIDs)");
}

/// Check whether an access token is allowed the requested access to a security descriptor.
///
/// This bridges the NT-style token model with the existing ACL model: the token's
/// user SID and enabled group SIDs are tested against each ACE in the DACL.
///
/// # Algorithm
/// 1. If the token user is LocalSystem (S-1-5-18), grant all access.
/// 2. Build a SecuritySubject from the token's user and groups.
/// 3. Delegate to the existing `check_access` function.
pub fn check_token_access(
    tok: &token::AccessToken,
    sd: &SecurityDescriptor,
    desired: u32,
) -> bool {
    // SYSTEM token bypasses
    if tok.user == sid::sid_local_system() {
        return true;
    }

    // Build a SecuritySubject from the token's identity.
    let uid_val = if !tok.user.sub_authorities.is_empty() {
        *tok.user.sub_authorities.last().unwrap()
    } else {
        u32::MAX
    };

    let gid_val = if !tok.primary_group.sub_authorities.is_empty() {
        *tok.primary_group.sub_authorities.last().unwrap()
    } else {
        u32::MAX
    };

    let group_ids: Vec<u32> = tok
        .groups
        .iter()
        .filter(|g| g.enabled && !g.deny_only)
        .filter_map(|g| g.sid.sub_authorities.last().copied())
        .collect();

    let subject = SecuritySubject {
        uid: SecurityId::from_id(uid_val),
        gid: SecurityId::from_id(gid_val),
        groups: group_ids.iter().map(|&g| SecurityId::from_id(g)).collect(),
        is_privileged: uid_val == 0 || tok.user == sid::sid_local_system(),
    };

    check_access(&subject, sd, desired)
}

// ============================================================================
// Object-level access check (bridges OB ↔ Security)
// ============================================================================

/// Check whether the current process has the requested access to an object
/// in the OB namespace.
///
/// Returns `STATUS_SUCCESS` if access is granted, `STATUS_ACCESS_DENIED` if
/// denied, or `STATUS_OBJECT_NAME_NOT_FOUND` if the object doesn't exist.
pub fn check_object_access(path: &str, desired_access: u32) -> astryx_shared::NtStatus {
    use astryx_shared::ntstatus::*;

    // Verify the object exists
    if !crate::ob::has_object(path) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Look up the object's security descriptor
    match crate::ob::get_object_security_descriptor(path) {
        Some(sd) => {
            let subject = SecuritySubject::from_current_process();
            if check_access(&subject, &sd, desired_access) {
                STATUS_SUCCESS
            } else {
                STATUS_ACCESS_DENIED
            }
        }
        None => {
            // No SD attached — default allow (system objects without explicit SD)
            STATUS_SUCCESS
        }
    }
}
