//! Access Tokens — NT-style security tokens for processes and threads
//!
//! An access token encapsulates the security context of a process or thread:
//! user SID, group memberships, privileges, default DACL, and impersonation
//! level. Tokens are the basis for all access-check decisions.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::sid::*;
use super::privilege::*;
use super::AccessControlEntry;

/// Token type — primary (process) or impersonation (thread).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Primary token — attached to a process.
    Primary,
    /// Impersonation token — attached to a thread, overrides process token.
    Impersonation,
}

/// Impersonation level — how much the server can act on behalf of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonationLevel {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation,
}

/// A group membership entry in an access token.
#[derive(Debug, Clone)]
pub struct TokenGroup {
    /// Group SID.
    pub sid: Sid,
    /// Whether this group is currently enabled.
    pub enabled: bool,
    /// Whether this group is mandatory (cannot be disabled).
    pub mandatory: bool,
    /// Whether this group is the token's default owner for new objects.
    pub owner: bool,
    /// Whether this group is deny-only (used only in deny ACEs).
    pub deny_only: bool,
}

/// Identifies the source (creator) of a token.
#[derive(Debug, Clone)]
pub struct TokenSource {
    /// 8-byte source name (e.g., b"*SYSTEM*", b"User32\0\0").
    pub name: [u8; 8],
    /// Source identifier (usually a LUID).
    pub id: u64,
}

/// An Access Token — the complete security context for a process or thread.
pub struct AccessToken {
    /// Unique token identifier.
    pub id: u64,
    /// Whether this is a primary or impersonation token.
    pub token_type: TokenType,
    /// Impersonation level (only meaningful for impersonation tokens).
    pub impersonation_level: Option<ImpersonationLevel>,
    /// User SID — the primary security principal.
    pub user: Sid,
    /// Group memberships.
    pub groups: Vec<TokenGroup>,
    /// Privilege set.
    pub privileges: Vec<TokenPrivilege>,
    /// Primary group SID (default for new objects).
    pub primary_group: Sid,
    /// Default DACL applied to new objects created by this token's owner.
    pub default_dacl: Option<Vec<AccessControlEntry>>,
    /// Token source information.
    pub source: TokenSource,
    /// Logon session ID.
    pub session_id: u32,
}

/// Global token ID counter.
static NEXT_TOKEN_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new unique token ID.
fn alloc_token_id() -> u64 {
    NEXT_TOKEN_ID.fetch_add(1, Ordering::Relaxed)
}

impl AccessToken {
    /// Create a SYSTEM token with LocalSystem identity and all privileges enabled.
    pub fn new_system_token() -> AccessToken {
        let id = alloc_token_id();
        let mut source_name = [0u8; 8];
        source_name[..8].copy_from_slice(b"*SYSTEM*");

        AccessToken {
            id,
            token_type: TokenType::Primary,
            impersonation_level: None,
            user: sid_local_system(),
            groups: Vec::from([
                TokenGroup {
                    sid: sid_builtin_admins(),
                    enabled: true,
                    mandatory: true,
                    owner: true,
                    deny_only: false,
                },
                TokenGroup {
                    sid: sid_world(),
                    enabled: true,
                    mandatory: true,
                    owner: false,
                    deny_only: false,
                },
            ]),
            privileges: all_admin_privileges(),
            primary_group: sid_local_system(),
            default_dacl: None,
            source: TokenSource {
                name: source_name,
                id: 0,
            },
            session_id: 0,
        }
    }

    /// Create a user token with the given user SID and group memberships.
    ///
    /// Assigns default user privileges (only SeChangeNotifyPrivilege enabled).
    pub fn new_user_token(user_sid: Sid, groups: Vec<TokenGroup>) -> AccessToken {
        let id = alloc_token_id();
        let primary_group = if !groups.is_empty() {
            groups[0].sid.clone()
        } else {
            sid_builtin_users()
        };

        let mut source_name = [0u8; 8];
        source_name[..6].copy_from_slice(b"User32");

        AccessToken {
            id,
            token_type: TokenType::Primary,
            impersonation_level: None,
            user: user_sid,
            groups,
            privileges: default_user_privileges(),
            primary_group,
            default_dacl: None,
            source: TokenSource {
                name: source_name,
                id: 0,
            },
            session_id: 1,
        }
    }
}

/// Check if a token holds a specific privilege and it is currently enabled.
pub fn token_has_privilege(token: &AccessToken, priv_: Privilege) -> bool {
    token
        .privileges
        .iter()
        .any(|tp| tp.privilege == priv_ && tp.attributes.enabled)
}

/// Enable a privilege in a token. The privilege must already exist in the token.
///
/// Returns `true` if successfully enabled, `false` if the privilege is not in the token.
pub fn token_enable_privilege(token: &mut AccessToken, priv_: Privilege) -> bool {
    if let Some(tp) = token.privileges.iter_mut().find(|tp| tp.privilege == priv_) {
        tp.attributes.enabled = true;
        true
    } else {
        false
    }
}

/// Disable a privilege in a token. The privilege must already exist in the token.
///
/// Returns `true` if successfully disabled, `false` if the privilege is not in the token.
pub fn token_disable_privilege(token: &mut AccessToken, priv_: Privilege) -> bool {
    if let Some(tp) = token.privileges.iter_mut().find(|tp| tp.privilege == priv_) {
        tp.attributes.enabled = false;
        true
    } else {
        false
    }
}

/// Check if the token's user or any enabled group matches the given SID.
pub fn token_check_membership(token: &AccessToken, sid: &Sid) -> bool {
    // Check user SID
    if token.user == *sid {
        return true;
    }
    // Check enabled (non-deny-only) group SIDs
    token.groups.iter().any(|g| g.enabled && !g.deny_only && g.sid == *sid)
}

/// Duplicate a token, potentially changing its type and impersonation level.
pub fn duplicate_token(
    token: &AccessToken,
    new_type: TokenType,
    level: Option<ImpersonationLevel>,
) -> AccessToken {
    AccessToken {
        id: alloc_token_id(),
        token_type: new_type,
        impersonation_level: level,
        user: token.user.clone(),
        groups: token.groups.clone(),
        privileges: token.privileges.clone(),
        primary_group: token.primary_group.clone(),
        default_dacl: token.default_dacl.clone(),
        source: token.source.clone(),
        session_id: token.session_id,
    }
}

// ============================================================================
// Global Token Registry
// ============================================================================

/// Global token registry — maps token ID → AccessToken.
static TOKEN_REGISTRY: Mutex<Option<BTreeMap<u64, AccessToken>>> = Mutex::new(None);

/// Ensure the registry is initialized.
fn ensure_registry(reg: &mut Option<BTreeMap<u64, AccessToken>>) -> &mut BTreeMap<u64, AccessToken> {
    if reg.is_none() {
        *reg = Some(BTreeMap::new());
    }
    reg.as_mut().unwrap()
}

/// Create and register a SYSTEM token. Returns the token ID.
pub fn create_system_token() -> u64 {
    let token = AccessToken::new_system_token();
    let id = token.id;
    let mut reg = TOKEN_REGISTRY.lock();
    let map = ensure_registry(&mut reg);
    map.insert(id, token);
    id
}

/// Create and register a user token. Returns the token ID.
pub fn create_user_token(user_sid: Sid, groups: Vec<TokenGroup>) -> u64 {
    let token = AccessToken::new_user_token(user_sid, groups);
    let id = token.id;
    let mut reg = TOKEN_REGISTRY.lock();
    let map = ensure_registry(&mut reg);
    map.insert(id, token);
    id
}

/// Access a token by ID (immutable closure).
pub fn with_token<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&AccessToken) -> R,
{
    let reg = TOKEN_REGISTRY.lock();
    let map = reg.as_ref()?;
    let token = map.get(&id)?;
    Some(f(token))
}

/// Access a token by ID (mutable closure).
pub fn with_token_mut<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut AccessToken) -> R,
{
    let mut reg = TOKEN_REGISTRY.lock();
    let map = ensure_registry(&mut reg);
    let token = map.get_mut(&id)?;
    Some(f(token))
}

/// Destroy (remove) a token from the registry.
pub fn destroy_token(id: u64) {
    let mut reg = TOKEN_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        map.remove(&id);
    }
}
