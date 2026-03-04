//! Security Identifiers (SIDs) — NT-style unique security principal identifiers
//!
//! A SID uniquely identifies a security principal (user, group, service account, etc.)
//! in the S-R-I-S-S-... format. This module provides the full NT SID structure,
//! well-known SID constructors, and Display formatting.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Security Identifier — uniquely identifies a security principal (user, group, etc.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    /// SID revision level (always 1).
    pub revision: u8,
    /// Identifier authority (6 bytes, big-endian).
    pub authority: [u8; 6],
    /// Sub-authority values (RIDs — relative identifiers).
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Create a SID from the given authority and sub-authorities.
    pub fn from_components(authority: [u8; 6], sub_authorities: &[u32]) -> Sid {
        Sid {
            revision: 1,
            authority,
            sub_authorities: Vec::from(sub_authorities),
        }
    }

    /// Format the SID in the standard S-R-I-S-S-... string representation.
    ///
    /// The authority is rendered as a single integer. For authorities that fit
    /// in the low 4 bytes (i.e. bytes 0 and 1 are zero), it is a simple u32.
    /// Otherwise it is a full 48-bit value.
    pub fn to_string_repr(&self) -> String {
        let authority_value: u64 = ((self.authority[0] as u64) << 40)
            | ((self.authority[1] as u64) << 32)
            | ((self.authority[2] as u64) << 24)
            | ((self.authority[3] as u64) << 16)
            | ((self.authority[4] as u64) << 8)
            | (self.authority[5] as u64);

        let mut s = String::new();
        s.push_str("S-");
        // Revision
        push_u64(&mut s, self.revision as u64);
        s.push('-');
        // Authority
        push_u64(&mut s, authority_value);
        // Sub-authorities
        for sa in &self.sub_authorities {
            s.push('-');
            push_u64(&mut s, *sa as u64);
        }
        s
    }

    /// Check if this SID matches one of the well-known SIDs.
    pub fn is_well_known(&self) -> bool {
        *self == sid_null()
            || *self == sid_world()
            || *self == sid_local()
            || *self == sid_creator_owner()
            || *self == sid_local_system()
            || *self == sid_local_service()
            || *self == sid_network_service()
            || *self == sid_builtin_admins()
            || *self == sid_builtin_users()
    }
}

/// Helper: push a u64 as decimal digits into a String (no format! needed).
fn push_u64(s: &mut String, mut val: u64) {
    if val == 0 {
        s.push('0');
        return;
    }
    let start = s.len();
    while val > 0 {
        let digit = (val % 10) as u8 + b'0';
        s.push(digit as char);
        val /= 10;
    }
    // Reverse the digits we just pushed
    let bytes = unsafe { s.as_bytes_mut() };
    bytes[start..].reverse();
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let authority_value: u64 = ((self.authority[0] as u64) << 40)
            | ((self.authority[1] as u64) << 32)
            | ((self.authority[2] as u64) << 24)
            | ((self.authority[3] as u64) << 16)
            | ((self.authority[4] as u64) << 8)
            | (self.authority[5] as u64);

        write!(f, "S-{}-{}", self.revision, authority_value)?;
        for sa in &self.sub_authorities {
            write!(f, "-{}", sa)?;
        }
        Ok(())
    }
}

// ============================================================================
// Well-known SID constructors
// ============================================================================

/// Helper: create [u8; 6] authority from a single small integer.
const fn authority(val: u8) -> [u8; 6] {
    [0, 0, 0, 0, 0, val]
}

/// S-1-0-0 — Null SID (nobody).
pub fn sid_null() -> Sid {
    Sid::from_components(authority(0), &[0])
}

/// S-1-1-0 — World / Everyone.
pub fn sid_world() -> Sid {
    Sid::from_components(authority(1), &[0])
}

/// S-1-2-0 — Local.
pub fn sid_local() -> Sid {
    Sid::from_components(authority(2), &[0])
}

/// S-1-3-0 — Creator Owner.
pub fn sid_creator_owner() -> Sid {
    Sid::from_components(authority(3), &[0])
}

/// S-1-5 — NT Authority (base, no sub-authorities).
pub fn sid_nt_authority() -> Sid {
    Sid {
        revision: 1,
        authority: authority(5),
        sub_authorities: Vec::new(),
    }
}

/// S-1-5-18 — Local System.
pub fn sid_local_system() -> Sid {
    Sid::from_components(authority(5), &[18])
}

/// S-1-5-19 — Local Service.
pub fn sid_local_service() -> Sid {
    Sid::from_components(authority(5), &[19])
}

/// S-1-5-20 — Network Service.
pub fn sid_network_service() -> Sid {
    Sid::from_components(authority(5), &[20])
}

/// S-1-5-32-544 — Builtin Administrators.
pub fn sid_builtin_admins() -> Sid {
    Sid::from_components(authority(5), &[32, 544])
}

/// S-1-5-32-545 — Builtin Users.
pub fn sid_builtin_users() -> Sid {
    Sid::from_components(authority(5), &[32, 545])
}

/// S-1-5-21-{rid} — Domain user with the given RID.
pub fn sid_user(rid: u32) -> Sid {
    Sid::from_components(authority(5), &[21, rid])
}
