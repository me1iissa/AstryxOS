#!/usr/bin/env python3
"""serial-web.py — a tiny, dependency-free live dashboard for AstryxOS QEMU
serial logs (read-only; safe alongside live boots).

  GET /                       dashboard (session list + live log viewer)
  GET /api/sessions           JSON: every session + gate/sc/tick for live ones
  GET /api/stream?sid=<sid>   SSE: tail then every newly-appended line

  python3 scripts/serial-web.py [--port 8088] [--host 0.0.0.0]
"""
import os, sys, json, time, glob, argparse, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HARNESS_DIR = os.path.expanduser("~/.astryx-harness")
SID_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
TAIL_BYTES = 96 * 1024
GATE_SCAN_BYTES = 256 * 1024
GATE_SCAN_MAX_AGE = 600          # only compute gate/sc for sessions this fresh (perf)

# render ladder, deepest first (idx, label, substring markers)
GATES = [
    (8, "PNG",               ("89504e47", "out.png written", "kdb-read-png")),
    (7, "drawSnapshot",      ("drawSnapshot", "CrossProcessPaint", "libpng16")),
    (6, "screenshot-actors", ("ScreenshotParent", "getDimensions")),
    (5, "content-proc",      ("isForBrowser",)),
    (4, "network",           ("] Established", "Established →", "[TCP]")),
    (3, "ff-launch",         ("firefox-bin",)),
    (2, "x11",               ("X11 server ready", "Xastryx")),
    (1, "lib-load",          ("libxul",)),
]
GATE_MAX = 8
_SC_RE = re.compile(r"pid=1[^\n]*?sc=(\d+)")
_TICK_RE = re.compile(r"tick=(\d+)")
_PANIC_RE = re.compile(r"PANIC|HEAP GUARD\] overflow|SCHEDULER_DEADLOCK|ke_bugcheck")


def scan_gate(path, size):
    try:
        with open(path, "rb") as f:
            f.seek(max(0, size - GATE_SCAN_BYTES))
            text = f.read().decode("latin-1", "replace")
    except OSError:
        return {}
    gi, gl = 0, "boot"
    for idx, label, marks in GATES:
        if any(m in text for m in marks):
            gi, gl = idx, label
            break
    sc = tick = None
    m = list(_SC_RE.finditer(text))
    if m:
        sc = int(m[-1].group(1))
    t = list(_TICK_RE.finditer(text))
    if t:
        tick = int(t[-1].group(1))
    return {"gate": gl, "gate_idx": gi, "gate_max": GATE_MAX,
            "sc": sc, "tick": tick, "panic": bool(_PANIC_RE.search(text))}


# Ordered bring-up + render milestones. Each: (label, (substring markers,...)).
# Easily extended — add a tuple and it shows up in every session's timeline.
MILESTONES = [
    ("kernel entry",      ("AstryxOS kernel", "kernel_main", "Booting")),
    ("heap guard",        ("[HEAP GUARD] Guard pages installed",)),
    ("APIC init",         ("Phase 5b", "APIC init")),
    ("SMP / scheduler",   ("scheduler online", "SMP", "AP online", "Phase 6")),
    ("drivers",           ("virtio", "e1000", "ahci", "vmware_svga", "Phase 7")),
    ("VFS / mount",       ("mounted", "ext2", "fat32", "rootfs")),
    ("init / userspace",  ("init started", "PID 1", "spawn")),
    ("X11 ready",         ("X11 server ready", "Xastryx")),
    ("firefox exec",      ("firefox-bin",)),
    ("TLS / network",     ("] Established", "[TCP] Established")),
    ("content procs",     ("isForBrowser",)),
    ("screenshot-actors", ("ScreenshotParent", "getDimensions")),
    ("drawSnapshot",      ("drawSnapshot", "CrossProcessPaint", "libpng16")),
    ("PNG write",         ("89504e47", "out.png written")),
    ("exit_group",        ("exit_group",)),
]
# Only the kernel's own tick lines, not arbitrary "tick=" in FF/JS output.
_TICK_KERNEL = re.compile(r"(?:\[HB\]|PROC-METRICS\]) tick=(\d+)")


def scan_milestones(path):
    """FORWARD-ORDERED first-hit timeline. Milestone N+1 is only matched on a
    line at/after milestone N's line — so a marker string appearing early in
    unrelated content (e.g. 'drawSnapshot' inside the serialized JS source, or a
    forkserver's early exit_group) does NOT produce a false 'hit'. Ticks are read
    only from the kernel HB/PROC-METRICS lines."""
    found = {}            # label -> (line, tick)
    idx = 0               # next milestone to look for, in order
    cur_tick = None
    n = 0
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                n += 1
                m = _TICK_KERNEL.search(line)
                if m:
                    cur_tick = int(m.group(1))
                # advance through any milestones this line satisfies, in order
                while idx < len(MILESTONES) and any(s in line for s in MILESTONES[idx][1]):
                    found[MILESTONES[idx][0]] = (n, cur_tick)
                    idx += 1
                if idx >= len(MILESTONES):
                    break
    except OSError:
        pass
    out, prev = [], None
    for lab, _ in MILESTONES:
        h = found.get(lab)
        delta = None
        if h and h[1] is not None and prev is not None:
            delta = h[1] - prev
        if h and h[1] is not None:
            prev = h[1]
        out.append({"label": lab, "hit": h is not None,
                    "line": h[0] if h else None,
                    "tick": h[1] if h else None, "dtick": delta})
    return out


def list_sessions():
    out = []
    logs = glob.glob(os.path.join(HARNESS_DIR, "*.serial.log"))
    logs.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
    now = time.time()
    for log in logs:
        sid = os.path.basename(log)[:-len(".serial.log")]
        try:
            st = os.stat(log)
        except OSError:
            continue
        age = int(now - st.st_mtime)
        feats, running = "", None
        meta = os.path.join(HARNESS_DIR, sid + ".json")
        if os.path.exists(meta):
            try:
                m = json.load(open(meta))
                feats = m.get("features", "") or ""
                running = m.get("running")
            except Exception:
                pass
        s = {"sid": sid, "features": feats, "size": st.st_size,
             "age": age, "active": age < 20, "running": running}
        if age < GATE_SCAN_MAX_AGE:
            s.update(scan_gate(log, st.st_size))
        out.append(s)
    return out


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>AstryxOS · serial monitor</title>
<style>
 :root{--bg:#0b0e14;--panel:#11151f;--edge:#1e2533;--fg:#c9d1d9;--dim:#5c6675;--accent:#39d353}
 *{box-sizing:border-box} html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
   font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
 #app{display:flex;height:100vh}
 #side{width:320px;min-width:320px;border-right:1px solid var(--edge);overflow:auto;background:var(--panel)}
 #shead{padding:10px 12px;border-bottom:1px solid var(--edge);position:sticky;top:0;background:var(--panel);z-index:2}
 #shead h1{font-size:13px;margin:0 0 8px;letter-spacing:.5px} #shead h1 small{color:var(--dim);font-weight:400}
 input,button{background:#0b0e14;border:1px solid var(--edge);color:var(--fg);border-radius:5px;padding:5px 8px;font:inherit}
 #q{width:100%} #shead label{color:var(--dim);font-size:11px;cursor:pointer;display:inline-block;margin-top:6px}
 .s{padding:9px 12px;border-bottom:1px solid var(--edge);cursor:pointer}
 .s:hover{background:#161b27} .s.sel{background:#1b2230;border-left:3px solid var(--accent);padding-left:9px}
 .s .sid{font-weight:600} .s .meta{color:var(--dim);font-size:11px;margin-top:2px}
 .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:#37404f;vertical-align:middle}
 .dot.on{background:var(--accent);box-shadow:0 0 6px var(--accent)} .dot.panic{background:#ff7b72;box-shadow:0 0 6px #ff7b72}
 .gate{margin-top:5px;height:5px;background:#1b2230;border-radius:3px;overflow:hidden}
 .gate>i{display:block;height:100%;background:var(--accent)} .gate.gp>i{background:#d2a8ff} .gate.ge>i{background:#ff7b72}
 .glab{font-size:10px;color:var(--dim);margin-top:3px} .glab b{color:#7ee787}
 #main{flex:1;display:flex;flex-direction:column;min-width:0}
 #bar{padding:7px 12px;border-bottom:1px solid var(--edge);background:var(--panel);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
 #bar .t{font-weight:600} #bar .badge{font-size:11px;color:#7ee787;border:1px solid var(--edge);padding:2px 7px;border-radius:10px}
 #bar .x{color:var(--dim);font-size:11px} #bar label{color:var(--dim);cursor:pointer;font-size:11px}
 #flt{width:160px} #log{flex:1;overflow:auto;padding:8px 12px;white-space:pre-wrap;word-break:break-all}
 #log .l{display:block} #log .l:hover{background:#11151f} #log .l.hide{display:none} mark{background:#7c5cff;color:#fff;border-radius:2px}
 .ff{color:#7ee787} .err{color:#ff7b72;font-weight:600} .warn{color:#f0c674}
 .met{color:#56b6c2} .futex{color:#6b7686} .png{color:#d2a8ff;font-weight:600}
 #empty{color:var(--dim);padding:24px}
 #miles{display:flex;flex-wrap:wrap;gap:6px;padding:8px 12px;border-bottom:1px solid var(--edge);background:#0d111a}
 #miles:empty{display:none}
 .mile{font-size:11px;padding:3px 9px;border-radius:12px;border:1px solid var(--edge);color:var(--dim);background:#11151f;white-space:nowrap}
 .mile.hit{color:#7ee787;border-color:#214a2c;background:#0e1c14} .mile.hit.last{border-color:var(--accent);box-shadow:0 0 6px rgba(57,211,83,.4)}
 .mile.png{color:#d2a8ff;border-color:#3a2a52;background:#160e22} .mile b{color:#56b6c2;font-weight:600}
</style></head><body><div id=app>
 <div id=side>
   <div id=shead><h1>AstryxOS serial <small id=cnt></small></h1>
     <input id=q placeholder="filter sessions (sid / features)…">
     <label><input type=checkbox id=onlyactive checked> active &amp; recent only</label>
     &nbsp;<label><input type=checkbox id=autolive> auto-follow live</label></div>
   <div id=list></div></div>
 <div id=main>
   <div id=bar><span class=t id=title>— select a session —</span>
     <span class=badge id=gate style=display:none></span>
     <span class=x id=sc></span><span class=x id=rate></span>
     <span style=flex:1></span>
     <input id=flt placeholder="filter lines…"><label><input type=checkbox id=follow checked> follow</label></div>
   <div id=miles></div>
   <div id=log><div id=empty>Pick a session on the left to stream its serial output.</div></div>
 </div></div>
<script>
let cur=null,es=null,sessions=[],rate={n:0,t:Date.now()};
const list=document.getElementById('list'),log=document.getElementById('log');
const $=id=>document.getElementById(id);
const fmt=s=>s==null?'':s<60?s+'s':s<3600?(s/60|0)+'m':(s/3600|0)+'h';
const human=n=>n==null?'':n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3|0)+'k':n;
function classify(t){
  if(/PANIC|HEAP GUARD|SCHEDULER_DEADLOCK|bugcheck|\\bFAIL\\b|#PF|#GP|#UD|channel error/.test(t))return'err';
  if(/89504e47|drawSnapshot|out\\.png|libpng|CrossProcessPaint|kdb-read-png/.test(t))return'png';
  if(/^\\[FF\\/|ScreenshotParent|getDimensions|isForBrowser|Established/.test(t))return'ff';
  if(/WARN|WARNING/.test(t))return'warn';
  if(/PROC-METRICS|\\[HB\\] tick/.test(t))return'met';
  if(/FUTEX|CLEARTID|UNIXPOLL/.test(t))return'futex';
  return'';}
function gateClass(s){return s.panic?'gate ge':s.gate_idx>=7?'gate gp':'gate';}
function render(){
  const q=$('q').value.toLowerCase(),onlyA=$('onlyactive').checked;
  let r=sessions.filter(s=>(!onlyA||s.active||s.age<600)&&(!q||s.sid.includes(q)||(s.features||'').toLowerCase().includes(q)));
  $('cnt').textContent='('+r.length+'/'+sessions.length+')';
  list.innerHTML=r.map(s=>{
    const pct=s.gate_idx!=null?Math.round(s.gate_idx/(s.gate_max||8)*100):0;
    const gl=s.gate?`<div class=glab>gate <b>${s.gate}</b> ${s.gate_idx}/${s.gate_max||8}${s.sc!=null?' · sc '+human(s.sc):''}${s.panic?' · ⚠ panic':''}</div>`:'';
    const gb=s.gate_idx!=null?`<div class="${gateClass(s)}"><i style=width:${pct}%></i></div>${gl}`:'';
    return `<div class="s${s.sid===cur?' sel':''}" data-sid="${s.sid}">
     <div class=sid><span class="dot ${s.panic?'panic':s.active?'on':''}"></span>${s.sid}</div>
     <div class=meta>${(s.features||'—').slice(0,40)} · ${(s.size/1024|0)}KB · ${fmt(s.age)} ago${s.active?' · live':''}</div>${gb}</div>`;
  }).join('')||'<div id=empty>No matching sessions.</div>';
  list.querySelectorAll('.s').forEach(e=>e.onclick=()=>openS(e.dataset.sid));
}
async function refresh(){
  try{sessions=await(await fetch('/api/sessions')).json()}catch(e){return}
  if($('autolive').checked){const live=sessions.find(s=>s.active);if(live&&live.sid!==cur)openS(live.sid);}
  const c=sessions.find(s=>s.sid===cur);
  if(c){const g=$('gate');if(c.gate){g.style.display='';g.textContent='gate '+c.gate+' '+c.gate_idx+'/'+(c.gate_max||8);g.style.color=c.panic?'#ff7b72':c.gate_idx>=7?'#d2a8ff':'#7ee787';}
        $('sc').textContent=c.sc!=null?'sc '+human(c.sc):'';}
  render();
}
function openS(sid){
  cur=sid; document.getElementById('title').textContent=sid; log.innerHTML='';
  if(es)es.close(); rate={n:0,t:Date.now()};
  es=new EventSource('/api/stream?sid='+encodeURIComponent(sid));
  es.onmessage=ev=>{
    rate.n++;
    const d=document.createElement('span'); d.className='l '+classify(ev.data); d.dataset.t=ev.data.toLowerCase(); d.textContent=ev.data;
    applyFlt(d); log.appendChild(d);
    if(log.childElementCount>6000)for(let i=0;i<1500;i++)log.removeChild(log.firstChild);
    if($('follow').checked&&!d.classList.contains('hide'))log.scrollTop=log.scrollHeight;
  };
  render(); loadMiles(sid);
}
async function loadMiles(sid){
  let m; try{m=await(await fetch('/api/milestones?sid='+encodeURIComponent(sid))).json()}catch(e){return}
  if(sid!==cur)return;
  let lastHit=-1; m.forEach((x,i)=>{if(x.hit)lastHit=i;});
  $('miles').innerHTML=m.map((x,i)=>{
    const cls='mile'+(x.hit?' hit':'')+(i===lastHit?' last':'')+(/PNG|drawSnapshot/.test(x.label)?' png':'');
    const tk=x.hit&&x.tick!=null?' <b>@'+human(x.tick)+'</b>':'';
    const ti=x.hit?('line '+x.line+(x.tick!=null?' · tick '+x.tick:'')+(x.dtick!=null?' · +'+x.dtick+' ticks':'')):'not reached';
    return '<span class="'+cls+'" title="'+ti+'">'+(x.hit?'✓':'○')+' '+x.label+tk+'</span>';
  }).join('');
}
function applyFlt(el){const f=$('flt').value.toLowerCase();if(!f){el.classList.remove('hide');return;}el.classList.toggle('hide',!el.dataset.t.includes(f));}
$('flt').oninput=()=>{const f=$('flt').value.toLowerCase();log.querySelectorAll('.l').forEach(applyFlt);};
$('q').oninput=render; $('onlyactive').onchange=render; $('autolive').onchange=refresh;
setInterval(()=>{const now=Date.now(),dt=(now-rate.t)/1000;if(dt>=2){$('rate').textContent=cur?(rate.n/dt).toFixed(0)+' ln/s':'';rate={n:0,t:now};}},1000);
refresh(); setInterval(refresh,3000); setInterval(()=>{if(cur)loadMiles(cur);},5000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _hdr(self, code=200, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._hdr(); self.wfile.write(PAGE.encode())
        elif u.path == "/api/sessions":
            self._hdr(ctype="application/json")
            self.wfile.write(json.dumps(list_sessions()).encode())
        elif u.path == "/api/milestones":
            sid = parse_qs(u.query).get("sid", [""])[0]
            if not SID_RE.match(sid):
                self._hdr(400, "text/plain"); self.wfile.write(b"bad sid"); return
            p = os.path.join(HARNESS_DIR, sid + ".serial.log")
            if not os.path.exists(p):
                self._hdr(404, "text/plain"); self.wfile.write(b"no log"); return
            self._hdr(ctype="application/json")
            self.wfile.write(json.dumps(scan_milestones(p)).encode())
        elif u.path == "/api/stream":
            self._stream(parse_qs(u.query).get("sid", [""])[0])
        else:
            self._hdr(404, "text/plain"); self.wfile.write(b"404")

    def _stream(self, sid):
        if not SID_RE.match(sid):
            self._hdr(400, "text/plain"); self.wfile.write(b"bad sid"); return
        path = os.path.join(HARNESS_DIR, sid + ".serial.log")
        if not os.path.realpath(path).startswith(os.path.realpath(HARNESS_DIR)) or not os.path.exists(path):
            self._hdr(404, "text/plain"); self.wfile.write(b"no log"); return
        self._hdr(ctype="text/event-stream", extra={
            "Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - TAIL_BYTES))
                if size > TAIL_BYTES:
                    f.readline()
                buf = b""
                idle = 0
                while True:
                    chunk = f.read(65536)
                    if chunk:
                        idle = 0
                        buf += chunk
                        *lines, buf = buf.split(b"\n")
                        for ln in lines:
                            self.wfile.write(b"data: " + ln.replace(b"\r", b"") + b"\n\n")
                        self.wfile.flush()
                    else:
                        idle += 1
                        if idle % 30 == 0:
                            self.wfile.write(b": ka\n\n"); self.wfile.flush()
                        time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("SERIAL_WEB_PORT", 8088)))
    ap.add_argument("--host", default=os.environ.get("SERIAL_WEB_HOST", "0.0.0.0"))
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), H)
    srv.daemon_threads = True
    print(f"[serial-web] serving {HARNESS_DIR} on http://{a.host}:{a.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
