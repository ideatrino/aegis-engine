"""Self-contained HTML scan report -- light/dark aware, no external assets.

Every verdict renders with its calibrated posterior and a bar per detector
showing that detector's signed log-odds contribution, so a scan result can be
handed to someone who will never read a terminal. (design 4 / 5.6)
"""

from __future__ import annotations

import html
from typing import List

from .core import Verdict

_CSS = """
:root{--bg:#ffffff;--fg:#1a1a2e;--muted:#6b7280;--card:#f6f7f9;--line:#e5e7eb;
--allow:#15803d;--review:#b45309;--block:#b91c1c;--escalate:#6d28d9;
--pos:#dc2626;--neg:#2563eb;}
@media (prefers-color-scheme:dark){:root{--bg:#0f1117;--fg:#e5e7eb;--muted:#9ca3af;
--card:#1a1d27;--line:#2a2f3a;--allow:#4ade80;--review:#fbbf24;--block:#f87171;
--escalate:#c4b5fd;--pos:#f87171;--neg:#60a5fa;}}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);margin:0;
font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 20px;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:14px 16px;margin:0 0 12px}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.path{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all}
.badge{font-weight:600;padding:2px 10px;border-radius:999px;font-size:12px;color:#fff}
.ALLOW{background:var(--allow)}.REVIEW{background:var(--review)}
.BLOCK{background:var(--block)}.ESCALATE{background:var(--escalate)}.ERROR{background:var(--muted)}
.p{font-variant-numeric:tabular-nums;color:var(--muted);font-size:13px}
.reasons{margin:8px 0 0;padding:0 0 0 18px;color:var(--muted);font-size:13px}
.det{margin-top:10px}
.bar{display:grid;grid-template-columns:120px 1fr 60px;align-items:center;gap:8px;
font-size:12px;margin:2px 0}
.track{position:relative;height:12px;background:var(--line);border-radius:6px}
.fill{position:absolute;top:0;height:12px;border-radius:6px}
.fill.pos{background:var(--pos);left:50%}.fill.neg{background:var(--neg);right:50%}
.mid{position:absolute;left:50%;top:-2px;width:1px;height:16px;background:var(--muted);opacity:.4}
.name{color:var(--muted);font-family:ui-monospace,monospace}
.summary{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px}
.stat b{font-size:22px;display:block}
"""


def _bar(name, llr):
    width = min(abs(llr) / 6.0, 1.0) * 50  # half-track max
    cls = "pos" if llr >= 0 else "neg"
    return (f'<div class="bar"><span class="name">{html.escape(name)}</span>'
            f'<span class="track"><span class="mid"></span>'
            f'<span class="fill {cls}" style="width:{width:.1f}%"></span></span>'
            f'<span>{llr:+.2f}</span></div>')


def render(verdicts: List[Verdict], title: str = "AEGIS scan report") -> str:
    counts = {}
    for v in verdicts:
        counts[v.decision] = counts.get(v.decision, 0) + 1
    stats = "".join(
        f'<div class="stat"><b>{counts.get(k,0)}</b>{k}</div>'
        for k in ("ALLOW", "REVIEW", "BLOCK", "ESCALATE", "ERROR") if counts.get(k))
    cards = []
    for v in verdicts:
        if v.decision == "ALLOW":
            continue  # report focuses on what needs a human; full list in JSON/CLI
        dets = "".join(_bar(n, llr) for n, llr, p, w in v.contributions[:9])
        reasons = "".join(f"<li>{html.escape(r)}</li>" for r in v.reasons[:6])
        cards.append(f"""<div class="card">
          <div class="row"><span class="path">{html.escape(v.path)}</span>
          <span class="badge {v.decision}">{v.decision}</span></div>
          <div class="p">P(malicious) = {v.posterior:.4f} &middot; prior {v.prior} &middot; profile {v.profile}</div>
          <ul class="reasons">{reasons}</ul>
          <div class="det">{dets}</div></div>""")
    body = "".join(cards) or '<div class="card">Nothing flagged — all files allowed.</div>'
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>
<h1>{html.escape(title)}</h1>
<p class="sub">{len(verdicts)} files scanned. Calibrated Bayesian consensus; bars are per-detector signed log-odds.</p>
<div class="summary">{stats}</div>
{body}
</body></html>"""
