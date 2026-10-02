"""AEGIS Security Center -- a dependency-free (tkinter) desktop GUI.

tkinter is imported lazily inside launch(), so this module can be imported,
byte-compiled and unit-tested on a headless machine (no display). The scan
worker (`build_scanner`, `iter_scan`) is tk-free and tested directly.

Launch:  python -m aegis gui     |     aegis gui     |     (frozen) AEGIS.exe
"""

from __future__ import annotations

import os
import queue
import threading
from pathlib import Path
from typing import List, Optional

from .scanner import Scanner, ThreatIntel
from .core import PROFILES, DEFAULT_PRIOR, Verdict
from .learned import Model

STATE = Path(os.path.expanduser("~/.aegis"))
INTEL_PATH = STATE / "intel.json"
MODEL_PATH = STATE / "model.json"
BUNDLED_MODEL = Path(__file__).parent / "data" / "model.json"

_COLORS = {            # row foreground by decision (works in light & dark)
    "BLOCK": "#c0392b", "REVIEW": "#b9770e", "ESCALATE": "#8e44ad",
    "ALLOW": "#1e8449", "ERROR": "#7f8c8d",
}


# --------------------------------------------------------------------------- #
#  tk-free core (unit-tested headless)                                          #
# --------------------------------------------------------------------------- #
def load_model() -> Optional[Model]:
    if MODEL_PATH.exists():
        return Model.load(MODEL_PATH)
    if BUNDLED_MODEL.exists():
        return Model.load(BUNDLED_MODEL)
    return None


def build_scanner(profile: str = "balanced", prior: float = DEFAULT_PRIOR,
                  archives: bool = False, dynamic: bool = False) -> Scanner:
    return Scanner(intel=ThreatIntel.load(INTEL_PATH), prior=prior,
                   profile=profile, model=load_model(),
                   archives=archives, dynamic=dynamic)


def iter_scan(scanner: Scanner, path: str, skip_dev_noise: bool = False):
    """Yield verdicts for a file or tree. tk-free, so it is unit-tested."""
    from .cli import DEV_NOISE
    excludes = set(DEV_NOISE) if skip_dev_noise else set()
    yield from scanner.scan_tree(path, excludes=excludes)


# --------------------------------------------------------------------------- #
#  GUI                                                                          #
# --------------------------------------------------------------------------- #
def launch(argv: Optional[List[str]] = None) -> int:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    from . import __version__
    from .report import render
    from . import simhash

    app = tk.Tk()
    app.title(f"AEGIS Security Center  {__version__}")
    app.geometry("1040x660")

    state = {"verdicts": [], "scanning": False, "q": queue.Queue()}

    # ---- top controls ----
    bar = ttk.Frame(app, padding=8)
    bar.pack(fill="x")
    ttk.Label(bar, text="Target:").pack(side="left")
    target = tk.StringVar(value=os.path.expanduser("~"))
    ttk.Entry(bar, textvariable=target, width=58).pack(side="left", padx=4)

    def pick_dir():
        d = filedialog.askdirectory()
        if d:
            target.set(d)

    def pick_file():
        f = filedialog.askopenfilename()
        if f:
            target.set(f)

    ttk.Button(bar, text="Folder...", command=pick_dir).pack(side="left")
    ttk.Button(bar, text="File...", command=pick_file).pack(side="left", padx=4)

    opts = ttk.Frame(app, padding=(8, 0))
    opts.pack(fill="x")
    profile = tk.StringVar(value="balanced")
    ttk.Label(opts, text="Profile:").pack(side="left")
    ttk.Combobox(opts, textvariable=profile, values=list(PROFILES),
                 width=10, state="readonly").pack(side="left", padx=4)
    skip_noise = tk.BooleanVar(value=True)
    arch = tk.BooleanVar(value=False)
    dyn = tk.BooleanVar(value=False)
    flagged_only = tk.BooleanVar(value=False)
    ttk.Checkbutton(opts, text="Skip dev noise", variable=skip_noise).pack(side="left", padx=6)
    ttk.Checkbutton(opts, text="Archives", variable=arch).pack(side="left")
    ttk.Checkbutton(opts, text="Dynamic", variable=dyn).pack(side="left", padx=6)
    ttk.Checkbutton(opts, text="Flagged only", variable=flagged_only).pack(side="left")

    scan_btn = ttk.Button(opts, text="Scan")
    scan_btn.pack(side="right")

    # ---- results table ----
    cols = ("decision", "p", "path")
    tree = ttk.Treeview(app, columns=cols, show="headings", selectmode="browse")
    tree.heading("decision", text="Verdict")
    tree.heading("p", text="P(malicious)")
    tree.heading("path", text="Path")
    tree.column("decision", width=90, anchor="center")
    tree.column("p", width=110, anchor="center")
    tree.column("path", width=800, anchor="w")
    for d, c in _COLORS.items():
        tree.tag_configure(d, foreground=c)
    vsb = ttk.Scrollbar(app, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
    vsb.pack(side="left", fill="y", pady=8)

    # ---- status + actions ----
    side = ttk.Frame(app, padding=8)
    side.pack(side="right", fill="y")
    status = tk.StringVar(value="Ready.")
    ttk.Label(side, textvariable=status, wraplength=170, justify="left").pack(anchor="w")
    counts = tk.StringVar(value="")
    ttk.Label(side, textvariable=counts, wraplength=170, justify="left",
              foreground="#555").pack(anchor="w", pady=(6, 10))

    def selected_path() -> Optional[str]:
        sel = tree.selection()
        return tree.item(sel[0], "values")[2] if sel else None

    def do_inspect(_evt=None):
        p = selected_path()
        if not p or not os.path.isfile(p):
            return
        try:
            data = open(p, "rb").read(64 * 1024 * 1024)
        except OSError as e:
            messagebox.showerror("AEGIS", f"cannot read: {e}")
            return
        v = state["scanner"].scan_bytes(p, data)
        meta = getattr(v, "meta", {})
        win = tk.Toplevel(app)
        win.title("Inspect")
        win.geometry("720x480")
        txt = scrolledtext.ScrolledText(win, font=("Courier", 10))
        txt.pack(fill="both", expand=True)
        lines = [p, "",
                 f"SHA-256 : {meta.get('sha256','')}",
                 f"Size    : {meta.get('size',0)}   Format: {meta.get('format')}",
                 f"CTPH    : {simhash.ctph(data)}",
                 f"Prior   : {v.prior}   Profile: {v.profile}", "",
                 "Per-detector (signed log-odds contribution):",
                 f"  {'detector':14s}{'p(mal)':>9s}{'weight':>8s}{'LLR':>9s}"]
        for name, llr, pp, w in v.contributions:
            lines.append(f"  {name:14s}{pp:9.3f}{w:8.2f}{llr:+9.3f}")
        lines += ["", f"Disagreement : {v.disagreement:.4f}",
                  f"Posterior    : {v.posterior:.4f}",
                  f"DECISION     : {v.decision}", ""]
        lines += [f"  - {r}" for r in v.reasons]
        txt.insert("1.0", "\n".join(lines))
        txt.configure(state="disabled")

    tree.bind("<Double-1>", do_inspect)

    def do_allowlist():
        p = selected_path()
        if not p or not os.path.isfile(p):
            return
        import hashlib
        intel = ThreatIntel.load(INTEL_PATH)
        intel.allow_hashes.add(hashlib.sha256(open(p, "rb").read()).hexdigest())
        intel.save(INTEL_PATH)
        state["scanner"].intel = intel
        status.set(f"Allowlisted:\n{os.path.basename(p)}")

    def do_quarantine():
        p = selected_path()
        if not p or not os.path.isfile(p):
            return
        if not messagebox.askyesno("AEGIS", f"Quarantine (neuter on disk)?\n{p}"):
            return
        from .quarantine import Quarantine
        meta = Quarantine().quarantine(p)
        status.set(f"Quarantined -> {meta['id']}")

    def do_export():
        if not state["verdicts"]:
            return
        f = filedialog.asksaveasfilename(defaultextension=".html",
                                         initialfile="aegis-report.html")
        if not f:
            return
        Path(f).write_text(render(state["verdicts"]), encoding="utf-8")
        status.set(f"Report written:\n{os.path.basename(f)}")

    ttk.Button(side, text="Inspect", command=do_inspect).pack(fill="x")
    ttk.Button(side, text="Allowlist", command=do_allowlist).pack(fill="x", pady=4)
    ttk.Button(side, text="Quarantine", command=do_quarantine).pack(fill="x")
    ttk.Button(side, text="Export HTML", command=do_export).pack(fill="x", pady=4)

    # ---- scanning (threaded; UI updated via queue poll) ----
    def worker(path, scanner, skip):
        try:
            for v in iter_scan(scanner, path, skip_dev_noise=skip):
                state["q"].put(("row", v))
        except Exception as e:                       # never let the thread die silently
            state["q"].put(("error", str(e)))
        state["q"].put(("done", None))

    def start_scan():
        if state["scanning"]:
            return
        path = target.get().strip()
        if not path or not os.path.exists(os.path.expanduser(path)):
            messagebox.showerror("AEGIS", f"No such path:\n{path}")
            return
        tree.delete(*tree.get_children())
        state["verdicts"].clear()
        state.update(scanning=True,
                     counts={"ALLOW": 0, "REVIEW": 0, "BLOCK": 0, "ESCALATE": 0, "ERROR": 0})
        state["scanner"] = build_scanner(profile.get(), DEFAULT_PRIOR,
                                         arch.get(), dyn.get())
        scan_btn.configure(text="Scanning...", state="disabled")
        status.set("Scanning...")
        threading.Thread(target=worker,
                         args=(os.path.expanduser(path), state["scanner"], skip_noise.get()),
                         daemon=True).start()
        app.after(50, poll)

    def poll():
        try:
            while True:
                kind, payload = state["q"].get_nowait()
                if kind == "row":
                    v = payload
                    state["verdicts"].append(v)
                    state["counts"][v.decision] = state["counts"].get(v.decision, 0) + 1
                    if not flagged_only.get() or v.decision != "ALLOW":
                        tree.insert("", "end", values=(v.decision, f"{v.posterior:.4f}", v.path),
                                    tags=(v.decision,))
                elif kind == "error":
                    messagebox.showerror("AEGIS", f"Scan error: {payload}")
                elif kind == "done":
                    state["scanning"] = False
                    scan_btn.configure(text="Scan", state="normal")
                    c = state["counts"]
                    total = sum(c.values())
                    status.set(f"Done: {total} files.")
                    counts.set(f"ALLOW {c['ALLOW']}\nREVIEW {c['REVIEW']}\n"
                               f"BLOCK {c['BLOCK']}\nESCALATE {c['ESCALATE']}\n"
                               f"ERROR {c['ERROR']}")
                    return
        except queue.Empty:
            pass
        if state["scanning"]:
            app.after(80, poll)

    scan_btn.configure(command=start_scan)
    app.mainloop()
    return 0
