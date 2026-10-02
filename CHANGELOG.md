# Changelog

All notable changes to this reference implementation. Detection is provably
imperfect (Cohen 1987); "done" means maximum capability + honest limits.

## 6.4.0
### Added
- **Web-oriented AEGIS.** `aegis serve` starts a stdlib-only local web UI
  (`aegis/webserver.py`, `http.server`) backed by the **real** engine — all
  detectors plus the trained model — at `http://127.0.0.1:8008`. Drag a file in
  the browser; it's POSTed to the same-origin `/scan` and scored locally (binds
  localhost by default; warns on a non-local bind). `--host`/`--port` flags.
- A companion **shareable browser scanner** (published separately as an HTML
  artifact) ports the analytic core to client-side JavaScript so a file is scored
  entirely in the browser with nothing uploaded.

## 6.3.1
### Added
- Release polish for a publishable repo: a shield **logo** (`assets/aegis-logo.png`,
  `assets/aegis-icon.png`) and an app **icon** (`aegis.ico`, picked up by
  `build_exe.py` for the frozen `.exe`), README **badges** (CI / MIT / Python /
  stdlib-only / selftest / tests) and header logo, and **`PUBLISHING.md`** with
  exact `git` + `gh` steps. No engine changes.

## 6.3.0
### Added
- **Active-document detector** (`aegis/docscan.py`): the document-malware vector
  the byte/structural ensemble ignored. Flags Office VBA macros (legacy OLE/CFB
  and macro-enabled OOXML `vbaProject.bin`) — stronger when the macro auto-runs
  (`AutoOpen`/`Document_Open`) and reaches a shell/downloader — and PDFs with
  active content (`/OpenAction`+`/JavaScript`, `/Launch`). Surfaced as REVIEW
  (never auto-quarantined; a benign macro-heavy doc shouldn't be deleted on a
  heuristic). Benign `.docx`/`.pdf` trip nothing. Learned detectors abstain on
  OLE/OOXML/PDF (recognized formats).
- **Mach-O recognition** — true PE/ELF/Mach-O coverage. `peparse` identifies
  thin Mach-O (both endian/bitness), parses segments for entropy + W^X, and feeds
  the structural/learned path, so a macOS binary is scrutinized, not treated as a
  dense blob. (CAFEBABE fat is skipped — ambiguous with Java `.class`.)
- **`aegis adversarial`** — empirically proves the ensemble thesis: defeat one
  detector (strip strings, flatten entropy) and the others still flag it; the
  benign control stays ALLOW.
- **`aegis verify-corpus DIR`** — corpus hygiene: reports counts and fails on any
  content hash present in both `benign/` and `malicious/` (label leakage).

## 6.2.0
### Added
- **Desktop Security Center GUI** (`aegis/gui.py`, stdlib `tkinter`): pick a
  folder/file, scan with profile + skip-dev-noise/archives/dynamic toggles,
  color-coded results, double-click to inspect per-detector evidence, and
  allowlist / quarantine / export-HTML actions. Scans run on a background thread.
  Launch with `aegis gui`, `python -m aegis gui`, or the `aegis-gui` command.
- **Frozen app + build script.** `aegis_app.py` (one entry point: GUI when
  double-clicked, CLI with args, and its own dynamic-sandbox child) and
  `build_exe.py` (PyInstaller `--onefile`, collects the bundled model). `dynamic.py`
  re-invokes the frozen exe as the sandbox child so contained analysis works
  inside the `.exe`. PyInstaller is build-time only; the app stays dependency-free.
- Confirmed the threat-intel bridge for real-world coverage without samples:
  `aegis blocklist import FEED` ingests public SHA-256 / IOC feeds (e.g. a
  MalwareBazaar hash export) into the force-block signature set.

## 6.1.3
### Added
- `aegis/__main__.py` so `python -m aegis ...` works (alongside
  `python -m aegis.cli ...` and the installed `aegis` command). No `__main__`
  previously meant `python -m aegis` failed after a pip install.

## 6.1.2
### Fixed
- **Grounding root cause.** `train.host_benign()` sampled benign binaries only
  from Linux paths, so a Windows `train` grounded on ~60 synthetic PEs and
  over-fired. Grounding is now cross-platform (reads `System32`/`SysWOW64` on
  Windows, framework dirs on macOS), taking the reference count to the hundreds.
- **Grounding guard.** `train` warns below `MIN_GROUNDING` (40) benign refs, and
  every scan warns if the active `~/.aegis/model.json` is under-grounded.
- **ASCII console.** The scan summary uses ASCII separators, so a legacy
  (cp1252) console shows no mojibake.
### Added
- **Full malware-class coverage in the bundled model.** `rat_pe` and
  `keylogger_pe` fixtures join training; realistic (>3 KB) malicious fixtures so
  the learned detectors actually run on them. A fresh install now BLOCKs
  injector, RAT, ransomware and keylogger shapes out of the box; clean binaries
  stay ALLOW. Pinned by a test.
- Keystroke-hook cluster is a stronger analytic signal (surfaced even
  analytic-only).
- Repo scaffolding: `pyproject.toml` (installs an `aegis` command), `LICENSE`
  (MIT), `.gitignore`, `SECURITY.md`, `CONTRIBUTING.md`, CI workflow.

## 6.1.1
### Fixed
- **Compiled-artifact false-positive flood.** A thin learned model auto-blocked
  benign build output (COFF `.o`, `ar`/`.rlib`, `.pdb`, caches, compiled exes).
  - **Consensus guarantee:** a posterior BLOCK now requires an analytic
    corroborator outside `{entropy, neural, anomaly}`; learned/entropy alone cap
    to REVIEW, never auto-quarantine.
  - **Build-artifact recognition:** `ar`, MSVC `pdb`, Rust `rmeta`, and COFF
    objects are recognized, so the learned detectors abstain on them.
  - **UTF-8 console:** a path named with a non-cp1252 character can't crash a
    scan.
- `inspect`/`fuzzy`/`imphash` on a missing path now error cleanly (exit 2).

## 6.1.0
### Added
- Learned detectors D4 (logistic) + D6 (kNN anomaly), `train` / `make-corpus` /
  `evaluate`, a bundled trained model, Stage-3 Python sandbox, recursive
  bomb-guarded model-aware archive scanning, rule expression grammar (D8),
  quarantine (neuter + restore), HTML report, `watch` daemon, threat-intel
  blocklist.

## 6.0.0
### Added
- Initial stdlib-only reference: log-odds Bayesian consensus core; analytic
  detectors (structural, entropy, api-graph, signature+fuzzy+imphash, IOC,
  pickle); built-in EICAR rule; CLI; selftest; test suite.
