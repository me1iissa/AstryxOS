//! AstryxOS kernel build script.
//!
//! Responsibilities:
//!   1. Compile kernel/vdso/vdso.c into vdso.so (a position-independent shared
//!      object) and place it in OUT_DIR so the kernel can include_bytes! it.
//!
//! The vDSO is a host-side build artefact: we compile it with the *host*
//! x86_64 cross-compiler, not the kernel cross-toolchain.  This is fine because
//! the vDSO targets x86_64 Linux ABI (the same ISA as our kernel), not the
//! Astryx kernel ABI.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // ── vDSO compilation ────────────────────────────────────────────────
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let vdso_dir = manifest_dir.join("vdso");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let vdso_out = out_dir.join("vdso.so");

    // Re-run if any vDSO source file changes.
    println!("cargo:rerun-if-changed={}", vdso_dir.join("vdso.c").display());
    println!("cargo:rerun-if-changed={}", vdso_dir.join("vdso.lds").display());
    println!("cargo:rerun-if-changed={}", vdso_dir.join("build.sh").display());

    // Pick a compiler: prefer musl variant to keep the SO self-contained.
    let cc = if which("x86_64-linux-musl-gcc") {
        "x86_64-linux-musl-gcc"
    } else if which("x86_64-linux-gnu-gcc") {
        "x86_64-linux-gnu-gcc"
    } else {
        panic!("build.rs: no x86_64 C cross-compiler found; cannot build vDSO");
    };

    let status = Command::new(cc)
        .args([
            "-nostdlib",
            "-fPIC",
            "-fvisibility=hidden",
            "-Os",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-shared",
        ])
        .arg(format!("-Wl,--version-script={}", vdso_dir.join("vdso.lds").display()))
        .args([
            "-Wl,-Bsymbolic",
            "-Wl,-soname,linux-vdso.so.1",
            "-Wl,-s",
        ])
        .arg("-o")
        .arg(&vdso_out)
        .arg(vdso_dir.join("vdso.c"))
        .status()
        .expect("build.rs: failed to invoke C compiler for vDSO");

    if !status.success() {
        panic!("build.rs: vDSO compilation failed (exit {})", status);
    }

    println!(
        "cargo:warning=vDSO built: {} ({} bytes)",
        vdso_out.display(),
        std::fs::metadata(&vdso_out).map(|m| m.len()).unwrap_or(0),
    );
}

/// Check whether `prog` is on PATH.
fn which(prog: &str) -> bool {
    Command::new("which")
        .arg(prog)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
