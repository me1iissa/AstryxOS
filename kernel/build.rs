//! AstryxOS kernel build script.
//!
//! Compiles `kernel/vdso/vdso.S` and links it via `kernel/vdso/vdso.lds`
//! into a small position-independent shared object (`vdso.so`) placed in
//! Cargo's `OUT_DIR`.  The kernel embeds the resulting bytes via
//! `include_bytes!` and maps them into every user process at execve time
//! so glibc / musl can resolve `__vdso_clock_gettime` etc. without
//! entering the kernel for every clock read.
//!
//! We invoke `as` and `ld` directly (no GCC) to keep the build hermetic
//! and free of host-libc dependencies.  The toolchain prefix can be
//! overridden via the `ASTRYX_VDSO_AS` / `ASTRYX_VDSO_LD` environment
//! variables; without an override we try the host's plain `as`/`ld`
//! first (sufficient on x86_64 Linux build hosts), then fall back to
//! the `x86_64-linux-gnu-` prefixed cross variants.
//!
//! Because the vDSO is just a few hundred bytes of code, build cost is
//! negligible and the resulting artefact is byte-deterministic given a
//! fixed source.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let vdso_dir = manifest_dir.join("vdso");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let src = vdso_dir.join("vdso.S");
    let lds = vdso_dir.join("vdso.lds");
    let obj = out_dir.join("vdso.o");
    let so  = out_dir.join("vdso.so");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", lds.display());
    println!("cargo:rerun-if-env-changed=ASTRYX_VDSO_AS");
    println!("cargo:rerun-if-env-changed=ASTRYX_VDSO_LD");

    let as_tool = pick_tool("ASTRYX_VDSO_AS", &["as", "x86_64-linux-gnu-as"]);
    let ld_tool = pick_tool("ASTRYX_VDSO_LD", &["ld", "x86_64-linux-gnu-ld"]);

    // Step 1: assemble vdso.S → vdso.o
    let st = Command::new(&as_tool)
        .args(["--64", "-o"])
        .arg(&obj)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("build.rs: failed to invoke '{}': {}", as_tool, e));
    if !st.success() {
        panic!("build.rs: '{}' exited {}", as_tool, st);
    }

    // Step 2: link vdso.o → vdso.so as a shared, position-independent
    // ELF using the linker script that places vvar at a negative
    // virtual address and the loadable image at vaddr 0.
    let st = Command::new(&ld_tool)
        .args([
            "-shared",
            "-soname", "linux-vdso.so.1",
            "-Bsymbolic",
            "--no-undefined",
            "--hash-style=both",
            "-z", "max-page-size=4096",
            "-z", "noexecstack",
            "-T",
        ])
        .arg(&lds)
        .arg("-o")
        .arg(&so)
        .arg(&obj)
        .status()
        .unwrap_or_else(|e| panic!("build.rs: failed to invoke '{}': {}", ld_tool, e));
    if !st.success() {
        panic!("build.rs: '{}' exited {}", ld_tool, st);
    }

    let bytes = std::fs::metadata(&so).map(|m| m.len()).unwrap_or(0);
    println!(
        "cargo:warning=vDSO built: {} ({} bytes)",
        so.display(),
        bytes,
    );
}

/// Pick the first runnable program from `candidates`, honouring an
/// optional override in `env_var`.  Panics if nothing is found — the
/// vDSO is a hard build requirement.
fn pick_tool(env_var: &str, candidates: &[&str]) -> String {
    if let Ok(v) = std::env::var(env_var) {
        if !v.is_empty() {
            return v;
        }
    }
    for c in candidates {
        if Command::new(c).arg("--version").output().map(|o| o.status.success()).unwrap_or(false) {
            return (*c).to_string();
        }
    }
    panic!(
        "build.rs: none of {:?} found on PATH; set {} to override",
        candidates, env_var
    );
}
