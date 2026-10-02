"""`aegis serve` -- a local web UI backed by the REAL engine.

Unlike the shareable browser artifact (which ports the analytic core to JS), this
serves the full Python engine -- all detectors plus the trained learned model and
rules -- over http://127.0.0.1. Stdlib only (`http.server`); nothing is uploaded
anywhere, the server binds to localhost by default, and the browser POSTs the
file bytes to the same origin for scoring.
"""

from __future__ import annotations

import io
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, simhash

MAX_UPLOAD = 64 * 1024 * 1024

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS</title><style>
:root{--bg:#eef1f5;--surface:#fff;--s2:#f4f6f9;--fg:#1b2438;--muted:#5a6478;--line:#e0e5ec;
--accent:#0e8f8f;--allow:#1e8449;--review:#b9770e;--block:#c0392b;--escalate:#7d3cb5;
--mono:ui-monospace,Menlo,Consolas,monospace;--sans:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
@media(prefers-color-scheme:dark){:root{--bg:#0e1320;--surface:#161d2d;--s2:#1c2436;--fg:#e8ecf3;
--muted:#94a0b6;--line:#28324a;--accent:#2dd4bf;--allow:#3fcf86;--review:#e3ad45;--block:#ef6f62;--escalate:#b98be6;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.5}
.wrap{max-width:860px;margin:0 auto;padding:24px 16px 56px}
.head{display:flex;align-items:center;gap:11px}
h1{font-size:1.3rem;margin:0}.sub{color:var(--muted);font-size:.82rem}
.pill{margin-left:auto;font-size:.72rem;font-weight:600;color:var(--allow);border:1px solid var(--line);border-radius:999px;padding:4px 9px}
.drop{margin-top:20px;border:1.5px dashed var(--line);border-radius:16px;background:var(--surface);padding:34px;text-align:center;cursor:pointer}
.drop:hover,.drop.over{border-color:var(--accent)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px;font-size:.84rem;color:var(--muted)}
select{font:inherit;color:var(--fg);background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:6px 9px}
.res{margin-top:20px;display:none}.res.show{display:block}
.verdict{display:flex;gap:14px;align-items:center;padding:16px 18px;border:1px solid var(--line);border-top:4px solid var(--muted);border-radius:14px 14px 0 0;background:var(--surface)}
.badge{font-family:var(--mono);font-weight:600;color:#fff;padding:5px 11px;border-radius:999px;font-size:.8rem}
.num{font-family:var(--mono);font-size:1.5rem}
.v-ALLOW .badge{background:var(--allow)}.v-ALLOW.verdict{border-top-color:var(--allow)}
.v-REVIEW .badge{background:var(--review)}.v-REVIEW.verdict{border-top-color:var(--review)}
.v-BLOCK .badge{background:var(--block)}.v-BLOCK.verdict{border-top-color:var(--block)}
.v-ESCALATE .badge{background:var(--escalate)}.v-ESCALATE.verdict{border-top-color:var(--escalate)}
.body{border:1px solid var(--line);border-top:none;border-radius:0 0 14px 14px;background:var(--surface);padding:14px 18px}
.meta{font-family:var(--mono);font-size:.74rem;color:var(--muted);word-break:break-all}
ul{margin:10px 0 0;padding-left:18px}li{font-size:.86rem;margin:3px 0}
.det{display:grid;grid-template-columns:130px 1fr 60px;gap:9px;align-items:center;font-size:.78rem;margin:5px 0}
.det .nm{font-family:var(--mono)}.track{position:relative;height:15px;background:var(--s2);border-radius:5px}
.mid{position:absolute;left:50%;top:0;bottom:0;width:1px;background:var(--line)}
.fill{position:absolute;top:0;bottom:0;border-radius:4px}.pos{left:50%;background:color-mix(in srgb,var(--block) 70%,transparent)}
.neg{right:50%;background:color-mix(in srgb,var(--allow) 65%,transparent)}
.llr{font-family:var(--mono);text-align:right;color:var(--muted)}
.foot{margin-top:24px;color:var(--muted);font-size:.78rem;border-top:1px solid var(--line);padding-top:12px}
</style></head><body><div class="wrap">
<div class="head"><h1>AEGIS</h1><span class="sub">&nbsp;local engine</span><span class="pill">127.0.0.1 - full engine</span></div>
<div class="row">Profile <select id="profile"><option>max</option><option selected>balanced</option><option>relaxed</option></select>
<span id="ver"></span></div>
<div class="drop" id="drop">Drop a file, or click to choose. Scored by the real AEGIS engine on this machine.<input type="file" id="f" hidden></div>
<div class="res" id="res"><div class="verdict" id="vd"><span class="badge" id="badge">-</span>
<div><div class="num" id="pnum">0.000</div><div class="sub">P(malicious)</div></div>
<div style="margin-left:auto;text-align:right"><div id="fn" style="font-family:var(--mono)"></div><div class="sub" id="fs"></div></div></div>
<div class="body"><div class="meta" id="meta"></div><ul id="reasons"></ul><div id="dets" style="margin-top:10px"></div></div></div>
<div class="foot">Files are scored locally and never leave this machine. The full engine (PE/ELF/Mach-O structure, entropy, API-graph, strings/IOC, pickle, macros/PDF, rules, and the trained learned model) runs here.</div>
</div><script>
const $=i=>document.getElementById(i);$("ver").textContent="v"+VERSION;
const drop=$("drop"),f=$("f");drop.onclick=()=>f.click();
f.onchange=()=>f.files[0]&&send(f.files[0]);
["dragenter","dragover"].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.add("over")}));
["dragleave","drop"].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.remove("over")}));
drop.addEventListener("drop",x=>{const file=x.dataTransfer.files[0];if(file)send(file)});
function fmtB(n){return n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(1)+" MB"}
async function send(file){
  const buf=await file.arrayBuffer();
  const r=await fetch("/scan?profile="+encodeURIComponent($("profile").value)+"&name="+encodeURIComponent(file.name),
    {method:"POST",body:buf});
  const v=await r.json();render(v,file.name,file.size);
}
function render(v,name,size){
  $("res").classList.add("show");$("vd").className="verdict v-"+v.decision;
  $("badge").textContent=v.decision;$("pnum").textContent=Number(v.posterior).toFixed(3);
  $("fn").textContent=name;$("fs").textContent=fmtB(size)+" - "+(v.meta&&v.meta.format||"");
  $("meta").textContent=v.meta?("SHA-256 "+v.meta.sha256.slice(0,32)+"...  format "+v.meta.format):"";
  $("reasons").innerHTML="";(v.reasons||[]).forEach(t=>{const li=document.createElement("li");li.textContent=t;$("reasons").appendChild(li)});
  const d=$("dets");d.innerHTML="";const c=v.contributions||[];
  const mx=Math.max(1,...c.map(x=>Math.abs(x[1])));
  c.forEach(x=>{const[nm,llr]=x;const pct=Math.min(Math.abs(llr)/mx*50,50).toFixed(1);
    const row=document.createElement("div");row.className="det";
    row.innerHTML='<span class="nm"></span><div class="track"><div class="mid"></div><div class="fill '+(llr>=0?"pos":"neg")+'" style="width:'+pct+'%"></div></div><span class="llr">'+(llr>=0?"+":"")+llr.toFixed(2)+'</span>';
    row.querySelector(".nm").textContent=nm;d.appendChild(row)});
}
</script></body></html>"""


def scan_to_dict(scanner, name, data):
    """Scan bytes with the real engine, return a JSON-able dict (testable)."""
    v = scanner.scan_bytes(name, data)
    meta = getattr(v, "meta", {}) or {}
    return {
        "decision": v.decision,
        "posterior": round(v.posterior, 6),
        "reasons": v.reasons,
        "contributions": [[n, round(llr, 4)] for n, llr, p, w in v.contributions],
        "meta": {"sha256": meta.get("sha256", ""), "size": meta.get("size", len(data)),
                 "format": meta.get("format", "")},
    }


def _make_handler(build_scanner):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # quiet

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.split("?")[0] in ("/", "/index.html"):
                page = PAGE.replace("VERSION", json.dumps(__version__))
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain")

        def do_POST(self):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            if urlparse(self.path).path != "/scan":
                self._send(404, b"not found", "text/plain"); return
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_UPLOAD:
                self._send(413, b'{"error":"too large"}', "application/json"); return
            data = self.rfile.read(n)
            profile = (q.get("profile", ["balanced"])[0])
            name = (q.get("name", ["upload"])[0])
            try:
                sc = build_scanner(profile)
                out = json.dumps(scan_to_dict(sc, name, data)).encode("utf-8")
                self._send(200, out, "application/json")
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}).encode(), "application/json")
    return H


def serve(host="127.0.0.1", port=8008):
    from .scanner import Scanner, ThreatIntel
    from .learned import Model
    state = Path(os.path.expanduser("~/.aegis"))
    intel = ThreatIntel.load(state / "intel.json")
    model = None
    for p in (state / "model.json", Path(__file__).parent / "data" / "model.json"):
        if p.exists():
            model = Model.load(p); break

    def build_scanner(profile):
        return Scanner(intel=intel, profile=profile if profile in ("max", "balanced", "relaxed") else "balanced",
                       model=model)

    httpd = ThreadingHTTPServer((host, port), _make_handler(build_scanner))
    url = f"http://{host}:{port}"
    print(f"AEGIS web engine on {url}  (Ctrl+C to stop)")
    if host not in ("127.0.0.1", "localhost"):
        print("WARNING: bound to a non-local address -- other machines can reach this scanner.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0
