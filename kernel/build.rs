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

    // ── QGA daemon (Phase QGA-2) ───────────────────────────────────────
    // Compile the native userspace QGA daemon (`userspace/qga/`) into a
    // freestanding ELF64 binary and stage it in OUT_DIR for include_bytes!
    // by `kernel/src/proc/qga_elf.rs`.  The daemon is only spawned when
    // the kernel is built with `--features qga`, but we build it
    // unconditionally so the include path is stable and the daemon stays
    // exercised by the workspace build.  Cost: ~0.7 s per fresh build.
    build_qga_daemon(&manifest_dir, &out_dir);
}

fn build_qga_daemon(manifest_dir: &PathBuf, out_dir: &PathBuf) {
    // The crate lives at <repo>/userspace/qga/ — sibling of <repo>/kernel/.
    let repo_root = manifest_dir.parent().expect("kernel must have a parent dir");
    let qga_dir = repo_root.join("userspace").join("qga");
    let libsys_dir = repo_root.join("userspace").join("libsys");

    // Re-run when sources change.  We do not list every file in the
    // userspace crate; the directories suffice because cargo's own
    // dependency tracking handles the inner rebuild.
    for sub in &["src", "Cargo.toml", ".cargo/config.toml"] {
        let p = qga_dir.join(sub);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
    for sub in &["src", "Cargo.toml"] {
        let p = libsys_dir.join(sub);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }

    // Use a dedicated target dir inside OUT_DIR so we never collide with
    // the outer cargo build's lockfile.  Reuse across rebuilds is fine —
    // cargo will incremental-build inside it.
    let qga_target_dir = out_dir.join("qga-target");

    // Invoke `cargo +nightly build` against the QGA crate.  We strip
    // CARGO_* env vars that the outer build sets, otherwise cargo refuses
    // to start a nested invocation with "cannot reuse the same workspace".
    //
    // Run from the qga crate directory so cargo discovers the per-crate
    // .cargo/config.toml (rustflags that pin relocation-model=static).
    // Without `current_dir()`, cargo walks up from `kernel/` and picks the
    // outer workspace config, producing a static-PIE binary that the
    // kernel's minimal ELF loader cannot relocate (no RELA support, only
    // DT_RELR).
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(&cargo);
    cmd.arg("build")
        .arg("--release")
        .arg("--target")
        .arg("x86_64-unknown-none")
        .arg("--manifest-path")
        .arg(qga_dir.join("Cargo.toml"))
        .current_dir(&qga_dir)
        .env("CARGO_TARGET_DIR", &qga_target_dir);
    // Clear inherited cargo build env vars to avoid feature/profile bleed.
    for var in &[
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_MANIFEST_DIR",
        "CARGO_PKG_VERSION",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        cmd.env_remove(var);
    }
    // Defence in depth: also export the rustflags as an explicit env var
    // so the build is correct even if cargo's config discovery surprises
    // us in future workspace topologies.
    cmd.env("CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS",
            "-C relocation-model=static -C link-args=-static");
    let st = cmd.status().unwrap_or_else(|e| {
        panic!("build.rs: failed to invoke cargo for QGA daemon: {}", e)
    });
    if !st.success() {
        panic!("build.rs: cargo build for QGA daemon exited {}", st);
    }

    // Stage the produced ELF in OUT_DIR under a stable name.
    let src_elf = qga_target_dir
        .join("x86_64-unknown-none")
        .join("release")
        .join("qga");
    let dst_elf = out_dir.join("qga.elf");
    std::fs::copy(&src_elf, &dst_elf).unwrap_or_else(|e| {
        panic!("build.rs: failed to copy QGA elf {}→{}: {}", src_elf.display(), dst_elf.display(), e)
    });

    let bytes = std::fs::metadata(&dst_elf).map(|m| m.len()).unwrap_or(0);
    println!("cargo:warning=QGA daemon built: {} ({} bytes)", dst_elf.display(), bytes);
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
