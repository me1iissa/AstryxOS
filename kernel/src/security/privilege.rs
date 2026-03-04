//! Privileges — NT-style security privileges for access tokens
//!
//! Each privilege represents a specific system-level right (e.g., debug programs,
//! load drivers, shut down). Privileges are held in access tokens and can be
//! individually enabled or disabled.

extern crate alloc;

use alloc::vec::Vec;

/// Enumeration of NT-style privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Privilege {
    SeAssignPrimaryTokenPrivilege = 3,
    SeIncreaseQuotaPrivilege = 5,
    SeTcbPrivilege = 7,
    SeSecurityPrivilege = 8,
    SeTakeOwnershipPrivilege = 9,
    SeLoadDriverPrivilege = 10,
    SeSystemProfilePrivilege = 11,
    SeSystemtimePrivilege = 12,
    SeProfileSingleProcessPrivilege = 13,
    SeIncreaseBasePriorityPrivilege = 14,
    SeCreatePagefilePrivilege = 15,
    SeCreatePermanentPrivilege = 16,
    SeBackupPrivilege = 17,
    SeRestorePrivilege = 18,
    SeShutdownPrivilege = 19,
    SeDebugPrivilege = 20,
    SeAuditPrivilege = 21,
    SeSystemEnvironmentPrivilege = 22,
    SeChangeNotifyPrivilege = 23,
    SeUndockPrivilege = 25,
    SeManageVolumePrivilege = 28,
    SeImpersonatePrivilege = 29,
    SeCreateGlobalPrivilege = 30,
}

/// Attributes describing the state of a privilege in a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivilegeAttributes {
    /// Whether the privilege is currently enabled.
    pub enabled: bool,
    /// Whether the privilege is enabled by default.
    pub enabled_by_default: bool,
}

/// A privilege entry in an access token.
#[derive(Debug, Clone)]
pub struct TokenPrivilege {
    /// The privilege type.
    pub privilege: Privilege,
    /// Current attributes (enabled state).
    pub attributes: PrivilegeAttributes,
}

/// Return the human-readable name for a privilege.
pub fn privilege_name(priv_: Privilege) -> &'static str {
    match priv_ {
        Privilege::SeAssignPrimaryTokenPrivilege => "SeAssignPrimaryTokenPrivilege",
        Privilege::SeIncreaseQuotaPrivilege => "SeIncreaseQuotaPrivilege",
        Privilege::SeTcbPrivilege => "SeTcbPrivilege",
        Privilege::SeSecurityPrivilege => "SeSecurityPrivilege",
        Privilege::SeTakeOwnershipPrivilege => "SeTakeOwnershipPrivilege",
        Privilege::SeLoadDriverPrivilege => "SeLoadDriverPrivilege",
        Privilege::SeSystemProfilePrivilege => "SeSystemProfilePrivilege",
        Privilege::SeSystemtimePrivilege => "SeSystemtimePrivilege",
        Privilege::SeProfileSingleProcessPrivilege => "SeProfileSingleProcessPrivilege",
        Privilege::SeIncreaseBasePriorityPrivilege => "SeIncreaseBasePriorityPrivilege",
        Privilege::SeCreatePagefilePrivilege => "SeCreatePagefilePrivilege",
        Privilege::SeCreatePermanentPrivilege => "SeCreatePermanentPrivilege",
        Privilege::SeBackupPrivilege => "SeBackupPrivilege",
        Privilege::SeRestorePrivilege => "SeRestorePrivilege",
        Privilege::SeShutdownPrivilege => "SeShutdownPrivilege",
        Privilege::SeDebugPrivilege => "SeDebugPrivilege",
        Privilege::SeAuditPrivilege => "SeAuditPrivilege",
        Privilege::SeSystemEnvironmentPrivilege => "SeSystemEnvironmentPrivilege",
        Privilege::SeChangeNotifyPrivilege => "SeChangeNotifyPrivilege",
        Privilege::SeUndockPrivilege => "SeUndockPrivilege",
        Privilege::SeManageVolumePrivilege => "SeManageVolumePrivilege",
        Privilege::SeImpersonatePrivilege => "SeImpersonatePrivilege",
        Privilege::SeCreateGlobalPrivilege => "SeCreateGlobalPrivilege",
    }
}

/// All privileges, which are a complete list of defined privilege variants.
const ALL_PRIVILEGES: &[Privilege] = &[
    Privilege::SeAssignPrimaryTokenPrivilege,
    Privilege::SeIncreaseQuotaPrivilege,
    Privilege::SeTcbPrivilege,
    Privilege::SeSecurityPrivilege,
    Privilege::SeTakeOwnershipPrivilege,
    Privilege::SeLoadDriverPrivilege,
    Privilege::SeSystemProfilePrivilege,
    Privilege::SeSystemtimePrivilege,
    Privilege::SeProfileSingleProcessPrivilege,
    Privilege::SeIncreaseBasePriorityPrivilege,
    Privilege::SeCreatePagefilePrivilege,
    Privilege::SeCreatePermanentPrivilege,
    Privilege::SeBackupPrivilege,
    Privilege::SeRestorePrivilege,
    Privilege::SeShutdownPrivilege,
    Privilege::SeDebugPrivilege,
    Privilege::SeAuditPrivilege,
    Privilege::SeSystemEnvironmentPrivilege,
    Privilege::SeChangeNotifyPrivilege,
    Privilege::SeUndockPrivilege,
    Privilege::SeManageVolumePrivilege,
    Privilege::SeImpersonatePrivilege,
    Privilege::SeCreateGlobalPrivilege,
];

/// Return all privileges with all attributes enabled — for the SYSTEM token.
pub fn all_admin_privileges() -> Vec<TokenPrivilege> {
    ALL_PRIVILEGES
        .iter()
        .map(|&p| TokenPrivilege {
            privilege: p,
            attributes: PrivilegeAttributes {
                enabled: true,
                enabled_by_default: true,
            },
        })
        .collect()
}

/// Return default user privileges — only SeChangeNotifyPrivilege enabled.
pub fn default_user_privileges() -> Vec<TokenPrivilege> {
    ALL_PRIVILEGES
        .iter()
        .map(|&p| {
            let is_change_notify = p == Privilege::SeChangeNotifyPrivilege;
            TokenPrivilege {
                privilege: p,
                attributes: PrivilegeAttributes {
                    enabled: is_change_notify,
                    enabled_by_default: is_change_notify,
                },
            }
        })
        .collect()
}
