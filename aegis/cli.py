"""AEGIS command-line interface.

Commands:
  scan PATH         scan a file or tree   [--profile --prior --archives --dynamic
                    --exclude --skip-dev-noise --rules --html --quarantine
                    --flagged-only --json]
  inspect FILE      full per-detector evidence breakdown
  fuzzy A B         0-100 CTPH similarity
  imphash FILE      a PE's import-hash family fingerprint
  selftest          run build invariants
  train             train the learned detectors  [--corpus DIR --augment]
  make-corpus DIR   write an inert labeled corpus (template for real data)
  evaluate          per-detector + fused metrics  [--corpus DIR --augment]
  watch DIR         poll a directory, scan+quarantine new/changed files
  allowlist add FILE
  blocklist {add FILE|add-hash H|add-ioc STR|import FEED|list}
  rules {list|add FILE|check FILE}
  quarantine {list|restore ID}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, peparse, simhash
from .core import DEFAULT_PRIOR, PROFILES
from .scanner import Scanner, ThreatIntel
from .learned import Model

STATE = Path(os.path.expanduser("~/.aegis"))
INTEL_PATH = STATE / "intel.json"
MODEL_PATH = STATE / "model.json"

DEV_NOISE = {"node_modules", ".venv", "venv", "__pycache__", ".git", "target",
             ".hypothesis", ".ruff_cache", ".cargo", ".gradle", "vendor",
             "dist", "build", ".mypy_cache", ".pytest_cache"}


def _read(path: str) -> bytes:
    p = os.path.expanduser(os.path.expandvars(path))
    if not os.path.exists(p):
        print(f"error: no such file: {path}", file=sys.stderr)
        raise SystemExit(2)
    if not os.path.isfile(p):
        print(f"error: not a regular file: {path}", file=sys.stderr)
        raise SystemExit(2)
    try:
        with open(p, "rb") as fh:
            return fh.read(64 * 1024 * 1024)
    except (OSError, PermissionError) as e:
        print(f"error: cannot read {path}: {e}", file=sys.stderr)
        raise SystemExit(2)


BUNDLED_MODEL = Path(__file__).parent / "data" / "model.json"


def _scanner(args) -> Scanner:
    intel = ThreatIntel.load(INTEL_PATH)
    # user-trained model (~/.aegis) wins; otherwise the bundled model if shipped
    model = None
    if MODEL_PATH.exists():
        model = Model.load(MODEL_PATH)
        # Warn once if the user's trained model is under-grounded -- the thin
        # notion of "normal" that caused the v6.1 compiled-artifact flood.
        try:
            from .train import MIN_GROUNDING
            n = len(getattr(model, "d6_refs", []) or [])
            if model is not None and n < MIN_GROUNDING:
                print(f"note: active model at {MODEL_PATH} has only {n} benign "
                      f"reference points and may over-flag binaries; delete it to "
                      f"use the bundled model, or retrain with more benign data.",
                      file=sys.stderr)
        except Exception:
            pass
    elif BUNDLED_MODEL.exists():
        model = Model.load(BUNDLED_MODEL)
    from .rules import load_rules_files
    extra = []
    rules_dir = STATE / "rules"
    if rules_dir.exists():                         # installed rules always apply
        extra.extend(load_rules_files([str(rules_dir)]))
    if getattr(args, "rules", None):               # plus any passed for this scan
        extra.extend(load_rules_files([args.rules]))
    return Scanner(intel=intel, prior=args.prior, profile=args.profile,
                   extra_rules=extra, model=model,
                   archives=getattr(args, "archives", False),
                   dynamic=getattr(args, "dynamic", False))


def cmd_scan(args) -> int:
    sc = _scanner(args)
    excludes = set(args.exclude or [])
    if args.skip_dev_noise:
        excludes |= DEV_NOISE
    counts = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0, "ESCALATE": 0, "ERROR": 0}
    flagged, results, verdicts = [], [], []
    q = None
    if args.quarantine:
        from .quarantine import Quarantine
        q = Quarantine()
    for v in sc.scan_tree(args.path, excludes=excludes):
        counts[v.decision] = counts.get(v.decision, 0) + 1
        verdicts.append(v)
        if v.decision != "ALLOW":
            flagged.append(v)
        if q and v.decision == "BLOCK" and os.path.isfile(v.path):
            try:
                meta = q.quarantine(v.path)
                v.reasons.insert(0, f"quarantined -> {meta['id']}")
            except OSError:
                pass
        if args.json:
            results.append({"path": v.path, "decision": v.decision,
                            "posterior": round(v.posterior, 6), "reasons": v.reasons})
        elif not args.flagged_only or v.decision != "ALLOW":
            print(v.top_line())
            if v.decision != "ALLOW":
                for r in v.reasons[:4]:
                    print(f"           - {r}")
    if args.html:
        from .report import render
        Path(args.html).write_text(render(verdicts), encoding="utf-8")
        print(f"\nHTML report written to {args.html}")
    if args.json:
        print(json.dumps(results, indent=2))
        return 0
    total = sum(counts.values())
    print(f"\n--- {total} files scanned "
          f"(ALLOW {counts['ALLOW']} | REVIEW {counts['REVIEW']} | "
          f"BLOCK {counts['BLOCK']} | ESCALATE {counts['ESCALATE']} | ERROR {counts['ERROR']}) ---")
    return 0


def cmd_inspect(args) -> int:
    sc = _scanner(args)
    data = _read(args.file)
    v = sc.scan_bytes(args.file, data)
    print(f"File       : {args.file}")
    meta = getattr(v, "meta", {})
    print(f"SHA-256    : {meta.get('sha256', '')}")
    print(f"Size       : {meta.get('size', 0)} bytes   Format: {meta.get('format')}")
    if meta.get("imphash"):
        print(f"imphash    : {meta['imphash']}")
    print(f"CTPH       : {simhash.ctph(data)}")
    print(f"Prior      : {v.prior}    Profile: {v.profile}")
    print("\nPer-detector evidence (signed log-odds contribution):")
    print(f"  {'detector':14s} {'p(mal)':>8s} {'weight':>7s} {'LLR':>8s}")
    if not v.contributions:
        print("    (no fused detector fired)")
    for name, llr, p, w in v.contributions:
        bar = ("+" if llr >= 0 else "-") * min(int(abs(llr) * 4) + (1 if llr else 0), 30)
        print(f"  {name:14s} {p:8.3f} {w:7.2f} {llr:+8.3f}  {bar}")
    print(f"\nDisagreement (variance) : {v.disagreement:.4f}")
    print(f"Fused posterior P(mal)  : {v.posterior:.4f}")
    print(f"DECISION                : {v.decision}")
    for r in v.reasons:
        print(f"  - {r}")
    return 0


def cmd_fuzzy(args) -> int:
    print(f"CTPH similarity: {simhash.similarity(simhash.ctph(_read(args.file1)), simhash.ctph(_read(args.file2)))}/100")
    return 0


def cmd_imphash(args) -> int:
    print(peparse.parse(_read(args.file)).imphash or "(no import table / not a PE)")
    return 0


def cmd_selftest(args) -> int:
    from . import selftest
    return selftest.run()


def cmd_train(args) -> int:
    from . import train as T
    print("Training learned detectors (D4 logistic + D6 anomaly)...")
    model = T.train(corpus_dir=args.corpus, augment=args.augment)
    model.save(MODEL_PATH)
    print(f"Model saved to {MODEL_PATH} (base rate pi_cal={model.pi_cal:.3f}, "
          f"{len(model.d6_refs)} benign refs). Future scans will fuse D4/D6.")
    return 0


def cmd_make_corpus(args) -> int:
    from . import train as T
    info = T.make_corpus(args.dir)
    print(f"Wrote corpus to {info['path']}: benign={info['benign']}, malicious={info['malicious']}")
    print("Drop your own real labeled samples into benign/ and malicious/, then:")
    print(f"  aegis train --corpus {args.dir} --augment")
    return 0


def cmd_evaluate(args) -> int:
    from . import train as T
    print("Evaluating (70/30 split, learned + fused)...")
    m = T.evaluate(corpus_dir=args.corpus, augment=args.augment)
    for k, v in m.items():
        print(f"  {k:16s}: {v}")
    return 0


def cmd_watch(args) -> int:
    sc = _scanner(args)
    from .quarantine import Quarantine
    q = Quarantine()
    audit = STATE / "watch-audit.jsonl"
    STATE.mkdir(parents=True, exist_ok=True)
    seen = {}
    root = os.path.expanduser(args.dir)
    print(f"Watching {root} (Ctrl-C to stop). Blocks are quarantined; audit -> {audit}")
    try:
        while True:
            for dp, dns, fns in os.walk(root):
                dns[:] = [d for d in dns if d not in DEV_NOISE]
                for fn in fns:
                    p = os.path.join(dp, fn)
                    try:
                        mt = os.path.getmtime(p)
                    except OSError:
                        continue
                    if seen.get(p) == mt:
                        continue
                    seen[p] = mt
                    v = sc.scan_file(p)
                    if v.decision != "ALLOW":
                        rec = {"time": time.time(), "path": p, "decision": v.decision,
                               "posterior": round(v.posterior, 4), "reasons": v.reasons[:3]}
                        if v.decision == "BLOCK":
                            try:
                                rec["quarantined"] = q.quarantine(p)["id"]
                            except OSError:
                                pass
                        with open(audit, "a", encoding="utf-8") as fh:
                            fh.write(json.dumps(rec) + "\n")
                        print(f"  {v.top_line()}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def cmd_allowlist(args) -> int:
    intel = ThreatIntel.load(INTEL_PATH)
    sha = hashlib.sha256(_read(args.file)).hexdigest()
    intel.allow_hashes.add(sha)
    intel.save(INTEL_PATH)
    print(f"allowlisted {sha}")
    return 0


def cmd_blocklist(args) -> int:
    intel = ThreatIntel.load(INTEL_PATH)
    if args.action == "add":
        data = _read(args.value)
        intel.bad_hashes.add(hashlib.sha256(data).hexdigest())
        intel.bad_ctph.append(simhash.ctph(data))
        info = peparse.parse(data)
        if info.imphash:
            intel.bad_imphash.add(info.imphash)
        print(f"blocklisted {args.value} (exact + fuzzy + imphash)")
    elif args.action == "add-hash":
        intel.bad_hashes.add(args.value.lower())
        print(f"blocklisted hash {args.value}")
    elif args.action == "add-ioc":
        intel.bad_iocs.append(args.value)
        print(f"added indicator {args.value!r}")
    elif args.action == "import":
        n_h = n_i = 0
        for line in _read(args.value).decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if len(line) == 64 and all(c in "0123456789abcdef" for c in line.lower()):
                intel.bad_hashes.add(line.lower()); n_h += 1
            else:
                intel.bad_iocs.append(line); n_i += 1
        print(f"imported {n_h} hashes + {n_i} indicators")
    elif args.action == "list":
        print(f"hashes={len(intel.bad_hashes)} imphash={len(intel.bad_imphash)} "
              f"ctph={len(intel.bad_ctph)} iocs={len(intel.bad_iocs)} "
              f"allow={len(intel.allow_hashes)}")
    intel.save(INTEL_PATH)
    return 0


def cmd_rules(args) -> int:
    from .rules import BUILTIN_RULES, parse_rules, Rule
    if args.action == "list":
        rdir = STATE / "rules"
        installed = (list(rdir.glob("*.rules")) + list(rdir.glob("*.yar"))
                     + list(rdir.glob("*.yara"))) if rdir.exists() else []
        print("Built-in rules:")
        for r in BUILTIN_RULES:
            print(f"  {r.name}  (severity={r.severity})")
        print(f"Installed rule files: {len(installed)}")
        for p in installed:
            print(f"  {p}")
    elif args.action == "add":
        rdir = STATE / "rules"
        rdir.mkdir(parents=True, exist_ok=True)
        text = _read(args.value).decode("utf-8", "replace")
        rules = parse_rules(text)
        if not rules:
            print("no valid rules parsed; nothing installed")
            return 1
        # normalize to a recognized extension so it auto-loads on every scan
        dest = rdir / (Path(args.value).stem + ".rules")
        dest.write_text(text, encoding="utf-8")
        print(f"installed {len(rules)} rule(s) -> {dest} (now applied on every scan)")
    elif args.action == "check":
        text = _read(args.value).decode("utf-8", "replace")
        rules = parse_rules(text)
        print(f"parsed {len(rules)} rule(s):")
        for r in rules:
            print(f"  {r.name}: {len(r.strings)} strings, severity={r.severity}, "
                  f"condition={r.condition!r}")
    return 0


def cmd_quarantine(args) -> int:
    from .quarantine import Quarantine
    q = Quarantine()
    if args.action == "list":
        items = q.list()
        if not items:
            print("quarantine is empty")
        for m in items:
            print(f"  {m['id']}  {m['orig_path']}  ({m['size']} bytes)")
    elif args.action == "restore":
        res = q.restore(args.value)
        print(f"restored -> {res['restored']} (hash verified: {res['verified']})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="AEGIS reference antivirus")
    p.add_argument("--version", action="version", version=f"AEGIS {__version__}")
    p.add_argument("--profile", choices=list(PROFILES), default="balanced")
    p.add_argument("--prior", type=float, default=DEFAULT_PRIOR)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan")
    sp.add_argument("path")
    sp.add_argument("--exclude", action="append")
    sp.add_argument("--skip-dev-noise", action="store_true")
    sp.add_argument("--archives", action="store_true", help="scan inside zip/tar/gz, model-aware")
    sp.add_argument("--dynamic", action="store_true", help="Stage-3 sandbox for escalated Python samples")
    sp.add_argument("--rules", help="extra rules file or dir for this scan")
    sp.add_argument("--html", help="write a self-contained HTML report")
    sp.add_argument("--quarantine", action="store_true", help="neuter BLOCKed files")
    sp.add_argument("--flagged-only", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("inspect"); sp.add_argument("file"); sp.set_defaults(func=cmd_inspect)
    sp = sub.add_parser("fuzzy"); sp.add_argument("file1"); sp.add_argument("file2"); sp.set_defaults(func=cmd_fuzzy)
    sp = sub.add_parser("imphash"); sp.add_argument("file"); sp.set_defaults(func=cmd_imphash)
    sp = sub.add_parser("selftest"); sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("train")
    sp.add_argument("--corpus"); sp.add_argument("--augment", action="store_true")
    sp.set_defaults(func=cmd_train)
    sp = sub.add_parser("make-corpus"); sp.add_argument("dir"); sp.set_defaults(func=cmd_make_corpus)
    sp = sub.add_parser("evaluate")
    sp.add_argument("--corpus"); sp.add_argument("--augment", action="store_true")
    sp.set_defaults(func=cmd_evaluate)

    sp = sub.add_parser("watch"); sp.add_argument("dir")
    sp.add_argument("--interval", type=float, default=3.0)
    sp.add_argument("--archives", action="store_true"); sp.add_argument("--dynamic", action="store_true")
    sp.add_argument("--rules")
    sp.set_defaults(func=cmd_watch)

    sp = sub.add_parser("allowlist"); sp.add_argument("action", choices=["add"]); sp.add_argument("file")
    sp.set_defaults(func=cmd_allowlist)
    sp = sub.add_parser("blocklist")
    sp.add_argument("action", choices=["add", "add-hash", "add-ioc", "import", "list"])
    sp.add_argument("value", nargs="?", default="")
    sp.set_defaults(func=cmd_blocklist)
    sp = sub.add_parser("rules")
    sp.add_argument("action", choices=["list", "add", "check"])
    sp.add_argument("value", nargs="?", default="")
    sp.set_defaults(func=cmd_rules)
    sp = sub.add_parser("quarantine")
    sp.add_argument("action", choices=["list", "restore"])
    sp.add_argument("value", nargs="?", default="")
    sp.set_defaults(func=cmd_quarantine)
    sp = sub.add_parser("gui", help="launch the desktop Security Center")
    sp.set_defaults(func=cmd_gui)
    sp = sub.add_parser("adversarial", help="prove the ensemble thesis (evade one detector, caught by others)")
    sp.set_defaults(func=cmd_adversarial)
    sp = sub.add_parser("verify-corpus", help="check a corpus for label leakage")
    sp.add_argument("path")
    sp.set_defaults(func=cmd_verify_corpus)
    sp = sub.add_parser("serve", help="local web UI backed by the real engine")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8008)
    sp.set_defaults(func=cmd_serve)
    return p


def cmd_serve(args) -> int:
    from .webserver import serve
    return serve(args.host, args.port)


def cmd_adversarial(args) -> int:
    """Empirically demonstrate the ensemble thesis: an attacker who defeats ONE
    detector family is still caught by the others, because they draw on
    independent mathematics. Each case below neutralizes one signal."""
    from .fixtures import _build_pe, injector_pe, clean_pe
    sc = _scanner(args)
    inj = [("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])]
    cases = [
        ("baseline injector (nothing hidden)", injector_pe()),
        ("low-entropy packer (defeats D2 entropy)",
         _build_pe(imports=inj, text_section=b"\x90" * 6000, text_exec=True, text_write=True)),
        ("string-stripped (defeats D7 IOC strings)",
         _build_pe(imports=inj, text_section=__import__("os").urandom(6000),
                   text_exec=True, text_write=True)),
        ("benign control (must stay ALLOW)", clean_pe()),
    ]
    print("AEGIS adversarial check -- defeat one detector, the others still catch it\n")
    print(f"  {'case':44s}{'verdict':9s} firing detectors")
    all_ok = True
    for label, data in cases:
        v = sc.scan_bytes("adv", data)
        firing = ",".join(n for n, llr, p, w in v.contributions if llr > 0.3) or "-"
        print(f"  {label:44s}{v.decision:9s}{firing}")
        caught = v.decision in ("BLOCK", "REVIEW", "ESCALATE")
        all_ok &= caught if "benign" not in label else (v.decision == "ALLOW")
    print("\n" + ("PASS: every evasion still flagged; benign stayed clean."
                  if all_ok else "FAIL: an evasion slipped through."))
    print("This is the Condorcet/consensus argument (design 3.2) made concrete: no\n"
          "single-family evasion suffices, because the detectors don't share a blind spot.")
    return 0 if all_ok else 1


def cmd_verify_corpus(args) -> int:
    """Corpus hygiene: no file labeled both benign and malicious (label leakage),
    and a count report. A clean split is a precondition for an honest metric."""
    root = Path(os.path.expanduser(os.path.expandvars(args.path)))
    benign_d, mal_d = root / "benign", root / "malicious"
    if not benign_d.is_dir() or not mal_d.is_dir():
        print(f"error: expected {root}/benign and {root}/malicious", file=sys.stderr)
        return 2

    def hashes(d: Path):
        out = {}
        for p in d.rglob("*"):
            if p.is_file():
                out.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(), []).append(p.name)
        return out

    bh, mh = hashes(benign_d), hashes(mal_d)
    overlap = sorted(set(bh) & set(mh))
    print(f"benign files : {sum(len(v) for v in bh.values())} ({len(bh)} unique)")
    print(f"malicious    : {sum(len(v) for v in mh.values())} ({len(mh)} unique)")
    print(f"label leakage: {len(overlap)} content hash(es) in BOTH classes")
    for h in overlap[:10]:
        print(f"  - {h[:16]}  benign={bh[h][0]}  malicious={mh[h][0]}")
    ok = not overlap and len(bh) >= 1 and len(mh) >= 1
    print("\n" + ("PASS: clean split, no label leakage." if ok
                  else "FAIL: fix the leakage above before trusting any metric."))
    return 0 if ok else 1


def cmd_gui(args) -> int:
    try:
        from .gui import launch
        return launch()
    except (ImportError, ModuleNotFoundError) as e:   # tkinter missing on this host
        print(f"error: desktop GUI unavailable ({e}). tkinter isn't installed "
              f"here; the scan/CLI commands work without it.", file=sys.stderr)
        return 2


def main(argv=None) -> int:
    # A scanned path may contain characters the console's legacy code page (e.g.
    # Windows cp1252) cannot encode -- a file literally named with a unicode pi
    # crashed a whole scan. Force UTF-8 with replacement so printing a path can
    # never abort the run. (design 13, generalized from the HTML report to stdout)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
