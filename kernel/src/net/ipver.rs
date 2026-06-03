//! Runtime IP-version enable/disable toggles (IPv4 / IPv6).
//!
//! AstryxOS lets the operator turn an entire address family on or off at
//! runtime.  Two independent boolean flags gate the socket and connect
//! syscall paths:
//!
//! - **IPv4** — enabled by default.  AstryxOS has a working IPv4 egress path
//!   (e1000 → SLIRP NAT), so there is no reason to disable it out of the box.
//!   Disabling it is supported (e.g. for testing the IPv6-only path once that
//!   egress lands) but there is no standard Linux sysctl for it, so the IPv4
//!   toggle is exposed only via the native API and the `net-ipver` kdb command.
//!
//! - **IPv6** — **disabled by default.**  IPv6 TCP *egress* is not yet
//!   implemented in the stack (the connect(2) path has no AF_INET6 handshake),
//!   so a socket created in that family cannot actually reach a peer.  With
//!   IPv6 enabled, a stubbed connect that returns fake success makes an
//!   RFC 6724 / getaddrinfo(3) IPv6-first resolver (e.g. musl) believe a dead
//!   IPv6 destination "connected", wedging Happy-Eyeballs (which relies on the
//!   dead-family connect *failing* to fall back to IPv4).  Returning a clean
//!   error for the unsupported family — and, with IPv6 off by default, making
//!   `socket(AF_INET6)` fail with EAFNOSUPPORT outright — forces resolvers
//!   straight onto the working IPv4 path.  The toggle exists so IPv6 can be
//!   switched on once real egress is built.
//!
//! ## Linux-faithful enforcement contract
//!
//! These match the documented Linux behaviour so that upstream userspace
//! (musl/glibc getaddrinfo, the AI_ADDRCONFIG probe, Happy-Eyeballs) behaves
//! identically:
//!
//! - With the family disabled, `socket(AF_INET6, …)` returns **EAFNOSUPPORT**
//!   — the same as a Linux kernel booted with `ipv6.disable=1`
//!   (socket(2): "EAFNOSUPPORT — the implementation does not support the
//!   specified address family").  This is the primary, cleanest enforcement:
//!   a failing `socket()` makes the resolver skip the family entirely.
//!
//! - For a socket created *before* the family was disabled, `connect(2)` /
//!   `sendto(2)` to a destination in that family return **ENETUNREACH** — the
//!   same as the runtime `net.ipv6.conf.all.disable_ipv6=1` sysctl, which
//!   leaves the AF_INET6 socket creatable but makes egress on it unreachable.

use core::sync::atomic::{AtomicBool, Ordering};

/// IPv4 enabled.  Default **on** — IPv4 egress is implemented.
static IPV4_ENABLED: AtomicBool = AtomicBool::new(true);

/// IPv6 enabled.  Default **off** — IPv6 egress is not implemented; see the
/// module docs for the rationale (avoids the fake-success connect that wedges
/// IPv6-first resolvers).
static IPV6_ENABLED: AtomicBool = AtomicBool::new(false);

/// Returns `true` if the IPv4 address family is currently enabled.
#[inline]
pub fn ipv4_enabled() -> bool {
    IPV4_ENABLED.load(Ordering::Relaxed)
}

/// Returns `true` if the IPv6 address family is currently enabled.
#[inline]
pub fn ipv6_enabled() -> bool {
    IPV6_ENABLED.load(Ordering::Relaxed)
}

/// Enable or disable the IPv4 address family at runtime.
pub fn set_ipv4_enabled(on: bool) {
    IPV4_ENABLED.store(on, Ordering::Relaxed);
    crate::serial_println!("[NET] IPv4 family {}", if on { "ENABLED" } else { "DISABLED" });
}

/// Enable or disable the IPv6 address family at runtime.
///
/// Wired to the `net.ipv6.conf.{all,default}.disable_ipv6` procfs sysctl (the
/// sysctl stores `disable_ipv6`, so the boolean here is its logical negation)
/// and the `net-ipver` kdb command.
pub fn set_ipv6_enabled(on: bool) {
    IPV6_ENABLED.store(on, Ordering::Relaxed);
    crate::serial_println!("[NET] IPv6 family {}", if on { "ENABLED" } else { "DISABLED" });
}
