#!/usr/bin/env bash
#
# install-webxo.sh — Build the WebXO C++ HTTP server as a musl-linked
# userspace binary and stage it (plus a tiny docroot) into the AstryxOS
# data-disk staging tree.  This is the userspace half of the web-server
# demo; the kernel half is the `webxo-test` cargo feature (a userspace
# launcher mirroring sshd_demo.rs) and, for the combined "SSH + HTTP on
# one instance" demo, the persistent sshd-test runner.
#
# Why WebXO?
# ----------
# WebXO is a small (~600 KB total) static-page HTTP/1.1 server.  It speaks
# a narrow, well-understood syscall surface — socket(2), setsockopt(2)
# (SO_REUSEADDR), bind(2), listen(2), accept(2), recv(2)/send(2), plus a
# C++ std::thread worker pool (clone(2) + futex(2)) and ifstream-based
# file reads (openat/read/close).  Every one of those is already exercised
# end-to-end on this image by the musl Firefox port and the dropbear SSH
# service, so the server's runtime dependency closure is already present:
# the musl loader + libc, libstdc++, libgcc_s and libz are all staged by
# the earlier install-firefox-musl.sh / install-glibc pipeline.  Building
# WebXO therefore needs ZERO new shared-library staging.
#
# Linkage choice
# --------------
# WebXO upstream builds a separate shared library (libWebX.so) plus a thin
# executable that links against it.  For the AstryxOS image we instead
# compile every translation unit directly into ONE self-contained dynamic
# executable.  This avoids needing an extra LD_LIBRARY_PATH entry or an
# install of a versioned .so into the guest's loader search path — the
# binary depends only on the already-staged system libraries (libstdc++,
# libgcc_s, libz, libc.musl).  Smaller blast radius, one file to launch.
#
# What this script does
# ---------------------
#   1. Reuses the shared Alpine rootfs at ~/.cache/astryxos-firefox-musl/
#      rootfs/ (bootstrapped by install-firefox-musl.sh) and apk-adds
#      `build-base` (gcc, g++, musl-dev, make) + `zlib-dev` into it if the
#      compiler is not already present.  No second Alpine bootstrap.
#   2. Copies the WebXO source tree into a build directory inside the
#      rootfs and compiles it with the rootfs's musl g++ via a chroot-less
#      invocation (the musl loader runs the compiler driver, which then
#      drives cc1plus/as/ld out of the rootfs).  Output is a single
#      dynamic musl ELF: WebXOServer.
#   3. Stages the binary at build/disk/usr/bin/webxo and resolves its
#      shared-library closure, copying any NEEDED lib that is not already
#      present under build/disk/{lib,usr/lib}.
#   4. Stages a minimal docroot at build/disk/var/www/ with an index.html
#      that identifies the running AstryxOS instance, plus the WebXO error
#      pages the server serves for 404/500.
#
# Idempotent — exits 0 if the binary is already staged and source is
# unchanged.  Pass --force to rebuild.
#
# References (public):
#   - HTTP/1.1 semantics:   RFC 9110, RFC 7230
#   - POSIX sockets:        socket(2), bind(2), listen(2), accept(2),
#                           send(2), recv(2), setsockopt(2) SO_REUSEADDR
#   - musl loader usage:    ld-musl(8) (running a musl ELF via the loader
#                           with --library-path)
#   - QEMU SLIRP hostfwd:   https://www.qemu.org/docs/master/system/devices/net.html
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_USR_LIB="${DISK_DIR}/usr/lib"
DISK_LIB="${DISK_DIR}/lib"
DISK_WWW="${DISK_DIR}/var/www"

# Shared Alpine rootfs — same one used by install-firefox-musl.sh,
# install-sshd.sh, install-busybox-cli.sh.
CACHE_DIR="${HOME}/.cache/astryxos-firefox-musl"
APK_STATIC="${CACHE_DIR}/apk-tools/sbin/apk.static"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"
ALPINE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community"

# WebXO source location.  The canonical source lives outside the repo (it
# is not vendored into the AstryxOS tree to keep the repo lean); this
# variable can be overridden to point at a checkout.  Default probes a few
# conventional locations.
WEBXO_SRC="${WEBXO_SRC:-}"

MUSL_LOADER="${ROOTFS}/lib/ld-musl-x86_64.so.1"
MUSL_LIBPATH="${ROOTFS}/usr/lib:${ROOTFS}/lib"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        --src=*) WEBXO_SRC="${arg#--src=}" ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    esac
done

# ── Sanity: the shared Alpine rootfs must exist ──────────────────────────────
if [ ! -x "${APK_STATIC}" ] || [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[WEBXO] ERROR: shared Alpine rootfs not present at ${CACHE_DIR}"
    echo "[WEBXO]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi

# ── Locate the WebXO source tree ─────────────────────────────────────────────
# WebXO is an external project (https://github.com/KillerDucks/WebXO); its
# source is NOT vendored into this repo.  Point this script at a checkout via
# the WEBXO_SRC environment variable or --src=/path/to/WebXO.  A few neutral
# conventional locations are probed as a convenience.
if [ -z "${WEBXO_SRC}" ]; then
    for cand in \
        "${HOME}/WebXO" \
        "${HOME}/src/WebXO" \
        "${ROOT_DIR}/../WebXO"; do
        if [ -f "${cand}/CMakeLists.txt" ] && [ -d "${cand}/src/WebXLib" ]; then
            WEBXO_SRC="${cand}"
            break
        fi
    done
fi
if [ -z "${WEBXO_SRC}" ] || [ ! -d "${WEBXO_SRC}/src/WebXLib" ]; then
    echo "[WEBXO] ERROR: WebXO source not found."
    echo "[WEBXO]        Set WEBXO_SRC=/path/to/WebXO or pass --src=/path/to/WebXO"
    echo "[WEBXO]        (a checkout of https://github.com/KillerDucks/WebXO containing src/WebXLib/)."
    exit 1
fi
echo "[WEBXO] Using WebXO source at ${WEBXO_SRC}"

DISK_BIN_OUT="${DISK_USR_BIN}/webxo"

# ── Idempotency: skip if already staged and not forced ──────────────────────
if [ "${FORCE}" != true ] && [ -x "${DISK_BIN_OUT}" ]; then
    # Rebuild only if any source file is newer than the staged binary.
    if [ -z "$(find "${WEBXO_SRC}/src" -newer "${DISK_BIN_OUT}" -print -quit 2>/dev/null)" ]; then
        echo "[WEBXO] ${DISK_BIN_OUT} already staged and up to date; nothing to do (--force to rebuild)."
        exit 0
    fi
fi

# ── Step 1: ensure a musl g++ toolchain is in the rootfs ─────────────────────
ROOTFS_GXX="${ROOTFS}/usr/bin/g++"
if [ ! -x "${ROOTFS_GXX}" ] || [ "${FORCE}" = true ]; then
    echo "[WEBXO] Installing build-base + zlib-dev via apk into ${ROOTFS} ..."
    set +o pipefail
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --repository "${ALPINE_COMMUNITY}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --no-scripts \
        --update-cache \
        add build-base zlib-dev 2>&1 | sed 's/^/[WEBXO]   /' || true
    set -o pipefail
fi
if [ ! -x "${ROOTFS_GXX}" ]; then
    echo "[WEBXO] ERROR: g++ still missing after apk add build-base"
    exit 1
fi

# ── Step 2: compile WebXO into one self-contained musl executable ────────────
# We build inside the rootfs so the musl g++ driver, cc1plus, as and ld are
# all resolved from the rootfs (and so the produced ELF links against the
# rootfs's musl libc / libstdc++).  The build dir lives under the rootfs's
# /tmp so paths the compiler emits are rootfs-relative.
BUILD_REL="/tmp/webxo-build"
BUILD_ABS="${ROOTFS}${BUILD_REL}"
rm -rf "${BUILD_ABS}"
mkdir -p "${BUILD_ABS}/src"
cp -a "${WEBXO_SRC}/src/." "${BUILD_ABS}/src/"

# Compile flags (public-spec rationale):
#   -std=c++17                 — WebXO uses <filesystem>; c++17 folds it into
#                                libstdc++ proper (no separate -lstdc++fs on
#                                modern toolchains).
#   -O2                        — release optimisation.
#   -pthread                   — std::thread worker pool (clone(2)+futex(2)).
#   -static-libstdc++ / -static-libgcc were considered but REJECTED: the
#                                guest already has the shared libstdc++ /
#                                libgcc_s staged, and a dynamic link keeps
#                                the binary small + matches the proven FF
#                                runtime closure.
# We compile inside a chroot into the rootfs so the gcc driver resolves
# cc1plus / as / ld / its include + libexec dirs entirely from rootfs-internal
# paths (running the driver from outside the rootfs via the loader breaks its
# libexec-relative path computation).  chroot needs privilege; the rootfs was
# bootstrapped the same way (apk under sudo), so this matches the existing
# install-* convention.
#
# Glob all library .cpp + the main TU (paths are rootfs-relative under
# ${BUILD_REL}).
SRCS=$(cd "${BUILD_ABS}" && ls src/WebXLib/*.cpp src/pMain.cpp 2>/dev/null | tr '\n' ' ')
echo "[WEBXO] Compiling (chroot): ${SRCS}"

# A tiny driver script placed inside the rootfs and executed under chroot.
COMPILE_SH="${BUILD_ABS}/compile.sh"
cat > "${COMPILE_SH}" <<EOF
#!/bin/sh
set -e
cd ${BUILD_REL}
# WebXO's Directory.* uses std::experimental::filesystem (the pre-C++17
# Filesystem TS), whose symbols live in the static archive libstdc++fs.a,
# not in libstdc++.so.  Link it statically (-lstdc++fs) so those symbols
# fold into the binary — this adds no new runtime shared-library dependency.
g++ -std=c++17 -O2 -pthread -I src -I src/WebXLib ${SRCS} -lstdc++fs -lz -o webxo
EOF
chmod +x "${COMPILE_SH}"

sudo chroot "${ROOTFS}" /bin/sh "${BUILD_REL}/compile.sh" 2>&1 | sed 's/^/[WEBXO]   /'

# chroot writes webxo as root; make it readable/copyable by the build user.
sudo chown "$(id -u):$(id -g)" "${BUILD_ABS}/webxo" 2>/dev/null || true

if [ ! -x "${BUILD_ABS}/webxo" ]; then
    echo "[WEBXO] ERROR: compile did not produce ${BUILD_ABS}/webxo"
    exit 1
fi
echo "[WEBXO] Compiled webxo ($(stat -c%s "${BUILD_ABS}/webxo") bytes)"

# ── Step 3: stage the binary + resolve its shared-library closure ────────────
mkdir -p "${DISK_USR_BIN}" "${DISK_USR_LIB}" "${DISK_LIB}"
cp -fL "${BUILD_ABS}/webxo" "${DISK_BIN_OUT}"
chmod +x "${DISK_BIN_OUT}"
echo "[WEBXO] Staged /usr/bin/webxo ($(stat -c%s "${DISK_BIN_OUT}") bytes)"

echo "[WEBXO] Resolving webxo shared-library closure ..."
copied_count=0
missing_count=0
while IFS= read -r need; do
    case "${need}" in
        "libc.musl-x86_64.so.1"|"ld-musl-x86_64.so.1")
            if [ ! -f "${DISK_LIB}/${need}" ]; then
                echo "[WEBXO]   MISSING /lib/${need} (musl libc/loader — install-firefox-musl.sh should stage it)"
                missing_count=$((missing_count + 1))
            fi ;;
        *)
            for src_dir in "${ROOTFS}/usr/lib" "${ROOTFS}/lib"; do
                if [ -f "${src_dir}/${need}" ]; then
                    if [ ! -f "${DISK_LIB}/${need}" ]; then
                        cp -fL "${src_dir}/${need}" "${DISK_LIB}/${need}"
                        echo "[WEBXO]   Staged /lib/${need} ($(stat -c%s "${DISK_LIB}/${need}") bytes)"
                        copied_count=$((copied_count + 1))
                    fi
                    if [ ! -f "${DISK_USR_LIB}/${need}" ]; then
                        cp -fL "${src_dir}/${need}" "${DISK_USR_LIB}/${need}"
                    fi
                    continue 2
                fi
            done
            echo "[WEBXO]   WARNING: ${need} not found in rootfs — staging may be incomplete"
            ;;
    esac
done < <(readelf -d "${DISK_BIN_OUT}" 2>/dev/null | awk -F'[][]' '/NEEDED/ {print $2}')
echo "[WEBXO] Closed dependency: copied ${copied_count} new libs; ${missing_count} missing pre-reqs."

# ── Step 4: stage a minimal docroot ──────────────────────────────────────────
# Served from /var/www/ASTRYX (the basepath the launcher passes).  index.html
# identifies the running instance so a host curl gets a recognisable page.
DOCROOT="${DISK_WWW}/ASTRYX"
mkdir -p "${DOCROOT}"
cat > "${DOCROOT}/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AstryxOS · live</title>
<style>
  :root{
    --bg:#05060c; --ink:#e8ecff; --dim:#8b93b8;
    --cyan:#38e8ff; --violet:#9d6bff; --magenta:#ff5ec4; --lime:#6bffb2;
    --card:rgba(255,255,255,.04); --line:rgba(255,255,255,.10);
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{
    margin:0; min-height:100vh; color:var(--ink); background:var(--bg);
    font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;
    -webkit-font-smoothing:antialiased; overflow-x:hidden; position:relative;
  }
  .aurora{position:fixed; inset:-20% -20% auto -20%; height:80vh; z-index:-2; filter:blur(70px); opacity:.55;
    background:
      radial-gradient(40% 60% at 20% 30%, var(--violet), transparent 60%),
      radial-gradient(45% 55% at 75% 20%, var(--cyan), transparent 60%),
      radial-gradient(40% 50% at 55% 60%, var(--magenta), transparent 60%);
    animation:drift 18s ease-in-out infinite alternate;}
  @keyframes drift{from{transform:translate3d(-3%,-2%,0) scale(1)}to{transform:translate3d(4%,3%,0) scale(1.15)}}
  .stars{position:fixed; inset:0; z-index:-1; background-image:
      radial-gradient(1px 1px at 20% 30%, #fff, transparent),
      radial-gradient(1px 1px at 70% 60%, #cfe, transparent),
      radial-gradient(1px 1px at 40% 80%, #fff, transparent),
      radial-gradient(1.5px 1.5px at 85% 25%, #aef, transparent),
      radial-gradient(1px 1px at 55% 15%, #fff, transparent),
      radial-gradient(1px 1px at 10% 70%, #def, transparent);
    background-repeat:repeat; background-size:600px 600px; opacity:.5; animation:twinkle 6s ease-in-out infinite alternate;}
  @keyframes twinkle{from{opacity:.25}to{opacity:.6}}
  .wrap{max-width:1000px; margin:0 auto; padding:clamp(1.2rem,4vw,3rem) 1.2rem 4rem;}
  .pill{display:inline-flex; align-items:center; gap:.5ch; font-size:.78rem; letter-spacing:.04em;
    color:var(--lime); border:1px solid rgba(107,255,178,.3); background:rgba(107,255,178,.07);
    padding:.35rem .7rem; border-radius:999px; text-transform:uppercase; font-weight:600;}
  .dot{width:.55rem; height:.55rem; border-radius:50%; background:var(--lime); box-shadow:0 0 10px var(--lime);
    animation:pulse 1.6s ease-in-out infinite;}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
  h1{font-size:clamp(2.8rem,11vw,6rem); line-height:.95; margin:1.4rem 0 .2rem; font-weight:800; letter-spacing:-.03em;}
  h1 .grad{background:linear-gradient(100deg,var(--cyan),var(--violet) 45%,var(--magenta));
    -webkit-background-clip:text; background-clip:text; color:transparent;
    filter:drop-shadow(0 0 24px rgba(157,107,255,.35));}
  .tag{font-size:clamp(1.05rem,2.6vw,1.5rem); color:var(--ink); min-height:1.6em; font-weight:500;}
  .tag .cur{color:var(--cyan); animation:blink 1s steps(1) infinite}
  @keyframes blink{50%{opacity:0}}
  .sub{color:var(--dim); max-width:60ch; margin:.8rem 0 0; font-size:1.02rem; line-height:1.6}
  .stats{display:flex; flex-wrap:wrap; gap:.7rem; margin:2rem 0 1rem}
  .stat{flex:1 1 150px; background:var(--card); border:1px solid var(--line); border-radius:16px;
    padding:1rem 1.1rem; backdrop-filter:blur(6px)}
  .stat b{display:block; font-size:1.9rem; font-weight:800; letter-spacing:-.02em;
    background:linear-gradient(120deg,#fff,var(--cyan)); -webkit-background-clip:text; background-clip:text; color:transparent}
  .stat span{color:var(--dim); font-size:.82rem}
  .grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:1rem; margin:2.2rem 0}
  .card{background:var(--card); border:1px solid var(--line); border-radius:18px; padding:1.3rem;
    transition:transform .25s ease, border-color .25s ease, box-shadow .25s ease; position:relative; overflow:hidden}
  .card:hover{transform:translateY(-4px); border-color:rgba(56,232,255,.4); box-shadow:0 18px 50px rgba(56,232,255,.08)}
  .card .ic{font-size:1.5rem}
  .card h3{margin:.6rem 0 .35rem; font-size:1.08rem}
  .card p{margin:0; color:var(--dim); font-size:.92rem; line-height:1.55}
  .card::after{content:""; position:absolute; inset:0 0 auto 0; height:2px;
    background:linear-gradient(90deg,var(--cyan),var(--violet),var(--magenta)); opacity:.0; transition:opacity .25s}
  .card:hover::after{opacity:.9}
  .term{background:#070a13; border:1px solid var(--line); border-radius:16px; overflow:hidden; margin:2.2rem 0;
    box-shadow:0 24px 60px rgba(0,0,0,.5)}
  .term .bar{display:flex; align-items:center; gap:.5rem; padding:.65rem .9rem; border-bottom:1px solid var(--line);
    background:rgba(255,255,255,.02)}
  .term .b{width:.72rem; height:.72rem; border-radius:50%}
  .b.r{background:#ff5f57}.b.y{background:#febc2e}.b.g{background:#28c840}
  .term .ttl{margin-left:.4rem; color:var(--dim); font-size:.78rem; font-family:ui-monospace,monospace}
  .term pre{margin:0; padding:1.1rem 1.1rem 1.4rem; font-family:ui-monospace,"JetBrains Mono",Menlo,monospace;
    font-size:.86rem; line-height:1.6; color:#cdd6ff; white-space:pre-wrap; min-height:11.5em}
  .term .p{color:var(--lime)} .term .ok{color:var(--cyan)} .term .w{color:#febc2e}
  .term .c{display:inline-block; width:.6ch; background:var(--cyan); animation:blink 1s steps(1) infinite}
  footer{margin-top:2.5rem; padding-top:1.4rem; border-top:1px solid var(--line); color:var(--dim);
    font-size:.85rem; display:flex; flex-wrap:wrap; gap:.4rem 1.2rem; align-items:center; justify-content:space-between}
  footer code{color:var(--cyan); background:rgba(56,232,255,.08); padding:.1rem .45rem; border-radius:6px;
    font-family:ui-monospace,monospace}
  .reveal{opacity:0; transform:translateY(14px); animation:rise .7s cubic-bezier(.2,.7,.2,1) forwards}
  .reveal.d1{animation-delay:.05s}.reveal.d2{animation-delay:.15s}.reveal.d3{animation-delay:.28s}.reveal.d4{animation-delay:.42s}
  @keyframes rise{to{opacity:1; transform:none}}
  @media (prefers-reduced-motion:reduce){*{animation:none!important}.reveal{opacity:1; transform:none}}
</style>
</head>
<body>
<div class="aurora"></div><div class="stars"></div>
<main class="wrap">
  <div class="reveal"><span class="pill"><span class="dot"></span>live · served by AstryxOS</span></div>
  <h1 class="reveal d1">Hello from <span class="grad">AstryxOS</span></h1>
  <p class="tag reveal d1" id="tag"><span class="cur">_</span></p>
  <p class="sub reveal d2">
    You're reading a page served by <strong>WebXO</strong> — a userspace HTTP/1.1 server running on
    <strong>AstryxOS</strong>, a from-scratch operating system whose kernel is written in Rust. The same
    machine boots an <em>unmodified</em> Firefox, speaks real TCP/IP + TLS, and lets you SSH straight in.
    No Linux underneath — this OS does it itself.
  </p>
  <section class="stats">
    <div class="stat reveal d2"><b data-to="7">0</b><span>real websites rendered</span></div>
    <div class="stat reveal d2"><b data-to="100" data-suf="%">0</b><span>upstream Firefox</span></div>
    <div class="stat reveal d3"><b data-to="202">0</b><span>peak threads, one render</span></div>
    <div class="stat reveal d3"><b data-to="0" data-suf=" patches">0</b><span>to the Firefox binary</span></div>
  </section>
  <section class="grid">
    <div class="card reveal d1"><div class="ic">🦊</div><h3>Runs real Firefox</h3>
      <p>The actual upstream libxul/musl build — not a clone. It has rendered BBC News, CNN, Wikipedia and
         more to pixel-perfect PNGs, headless.</p></div>
    <div class="card reveal d2"><div class="ic">🌐</div><h3>Real network stack</h3>
      <p>Hand-written TCP/IP, DNS, ARP and DHCP. HTTPS handshakes, sockets, epoll — enough to load the
         live web over the wire.</p></div>
    <div class="card reveal d3"><div class="ic">🔑</div><h3>SSH right in</h3>
      <p>dropbear + a busybox shell with a proper PTY (cooked termios, ONLCR, the works). Connect from any
         box on your LAN.</p></div>
    <div class="card reveal d4"><div class="ic">⚡</div><h3>Serves this page</h3>
      <p>WebXO binds <code style="color:var(--lime)">0.0.0.0:8080</code> as a normal userspace process —
         co-resident with SSH, from a single boot.</p></div>
  </section>
  <section class="term reveal d2">
    <div class="bar"><span class="b r"></span><span class="b y"></span><span class="b g"></span>
      <span class="ttl">root@astryx:~ — live boot log</span></div>
    <pre id="log"></pre>
  </section>
  <footer class="reveal d3">
    <span>Served by <code>WebXO/1.6.0</code> · HTTP/1.1 (RFC&nbsp;9110) on <code>AstryxOS</code></span>
    <span id="clock"></span>
  </footer>
</main>
<script>
(function(){
  var phrases = [
    "An OS that runs the real web.",
    "Rust kernel. Upstream Firefox. Zero patches.",
    "Boots, renders, serves — all by itself.",
    "You found the web server. 👋"
  ], pi=0, ci=0, del=false, el=document.getElementById('tag');
  function type(){
    var p=phrases[pi];
    ci += del?-1:1;
    el.innerHTML = p.slice(0,ci) + '<span class="cur">_</span>';
    if(!del && ci===p.length){ del=true; return setTimeout(type,1700); }
    if(del && ci===0){ del=false; pi=(pi+1)%phrases.length; return setTimeout(type,250); }
    setTimeout(type, del?28:55);
  }
  type();
  document.querySelectorAll('.stat b').forEach(function(b){
    var to=+b.dataset.to, suf=b.dataset.suf||'', t0=null, dur=1100;
    function step(ts){ t0=t0||ts; var k=Math.min(1,(ts-t0)/dur);
      b.textContent = Math.round(to*(1-Math.pow(1-k,3))) + suf;
      if(k<1) requestAnimationFrame(step); }
    requestAnimationFrame(step);
  });
  var lines = [
    ['p','astryx ›',' kernel up · SMP 2 cores · KVM'],
    ['ok','  ✓',' virtio-blk online · ext2 mounted'],
    ['ok','  ✓',' net: e1000 · DHCP 10.0.2.15 · DNS ok'],
    ['ok','  ✓',' dropbear listening on :22'],
    ['ok','  ✓',' WebXO bound 0.0.0.0:8080'],
    ['w','  »',' GET / 200 — that\'s you, right now'],
  ], log=document.getElementById('log'), li=0;
  function emit(){
    if(li>=lines.length){ log.innerHTML += '<span class="p">astryx ›</span> <span class="c">&nbsp;</span>'; return; }
    var L=lines[li++];
    log.innerHTML += '<span class="'+L[0]+'">'+L[1]+'</span>'+L[2]+'\n';
    setTimeout(emit, 520);
  }
  setTimeout(emit, 700);
  var clk=document.getElementById('clock');
  function tick(){ clk.textContent = new Date().toLocaleString(); }
  tick(); setInterval(tick,1000);
})();
</script>
</body>
</html>
HTML
echo "[WEBXO] Staged docroot ${DOCROOT}/index.html"

# Stage the WebXO error pages alongside the docroot so 404/500 render the
# server's own templates rather than a bare status line.
if [ -d "${WEBXO_SRC}/ErrorPages" ]; then
    mkdir -p "${DISK_WWW}/ErrorPages"
    cp -fL "${WEBXO_SRC}/ErrorPages/"*.html "${DISK_WWW}/ErrorPages/" 2>/dev/null || true
    echo "[WEBXO] Staged error pages into ${DISK_WWW}/ErrorPages/"
fi

echo "[WEBXO] === DONE === webxo staged at /usr/bin/webxo, docroot at /var/www/ASTRYX"
echo "[WEBXO]     Launch on the guest with: webxo --basepath=/disk/var/www/ASTRYX --port=8080"
