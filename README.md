<p align="center">
  <img src="assets/aegis-logo.png" alt="AEGIS" width="560">
</p>

<p align="center">
  <img src="https://github.com/ideatrino/aegis-engine/actions/workflows/ci.yml/badge.svg" alt="CI">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/dependencies-none%20(stdlib)-success.svg" alt="stdlib only">
  <img src="https://img.shields.io/badge/selftest-25%2F25-success.svg" alt="selftest 25/25">
  <img src="https://img.shields.io/badge/tests-61%20passing-success.svg" alt="tests 61">
</p>

# AEGIS

### Adaptive Ensemble with Guaranteed-envelope Integrity Scoring

An original antivirus engine grounded in the mathematics of what detection can
and cannot do. A file's verdict is a **calibrated probability**, fused in
log-odds space from detectors drawn from *different mathematical families*,
decided against an **explicit cost model**, and shipped with the evidence that
produced it. **Pure Python, zero dependencies.**

```bash
pip install -e .                 # installs the `aegis` command (stdlib only)

# run it any of three ways:
python -m aegis selftest         # 25 build invariants (no PATH needed)
python -m aegis.cli selftest     # the explicit module path
aegis selftest                   # the installed command (needs Scripts/ on PATH)

python -m aegis scan ~/Downloads --skip-dev-noise
python -m aegis inspect suspect.bin
python -m aegis gui             # desktop Security Center (tkinter)
```

**Desktop app:** `aegis gui` (or `python -m aegis gui`, or the `aegis-gui`
command) opens a Security Center — pick a folder, scan with the profile and
skip-dev-noise/archives/dynamic toggles, see colour-coded verdicts, double-click
to inspect the per-detector evidence, and allowlist / quarantine / export an HTML
report. Build a standalone executable with `pip install pyinstaller && python
build_exe.py` → `dist/AEGIS` (double-click = GUI, `AEGIS.exe scan ...` = CLI).

> On Windows, `pip install` may warn that the `aegis.exe` script dir isn't on
> PATH. You can ignore it and use `python -m aegis ...`, or add that dir to PATH.

A trained model ships in the box (`aegis/data/model.json`), so detection works
on first run with no setup.

---

## 0. The honest premise

You cannot build a *provably perfect* antivirus — it's a theorem, not a gap.
**Cohen (1987):** if `PERFECT(P)` decided whether any program `P` ever behaves
maliciously, a program that calls `PERFECT` on itself and does the opposite
refutes it. Detection reduces to the halting problem. So the only rational goal
is to **shape the error surface deliberately**: decide where false positives and
false negatives go, quantify uncertainty, and never report a verdict as certain.
Every design choice below follows from that.

---

## 1. The mathematics (what actually drives the code)

- **Base rate (Bayes).** Almost every file is benign, so a 99.9%-accurate alarm
  at a 1-in-10,000 base rate is right only ~9% of the time. AEGIS reports the
  **posterior** against an explicit, tunable prior, never a raw score.
- **Consensus (log-odds fusion).** For independent evidence, Bayes' rule is
  addition in log-odds: `logit P(M|E) = logit P(M) + Σ wᵢ·ℓᵢ`, with each
  `ℓᵢ = logit(pᵢ) − logit(π_cal)` (the exact naive-Bayes update).
- **Diversity (Condorcet).** Independent weak detectors beat any one — *if* their
  errors are uncorrelated, so the detectors come from different families.
- **Cost model (decision theory).** "Maximum security" is `C_FN ≫ C_FP`, which
  slides the block threshold down the ROC curve. `--profile` and `--prior` are
  that dial; the same evidence can REVIEW on a desktop and BLOCK at a gateway.

---

## 2. Detectors

| # | Detector | Basis | Role |
|---|---|---|---|
| D1 | structural | PE/ELF grammar: packed sections, W^X, object & signature recognition | LLR |
| D2 | entropy | Shannon info; abstains on known/compiled/text formats | LLR |
| D3 | api-graph | import clusters: injection / RAT / ransomware / keylogger | LLR |
| D4 | neural | logistic byte/structural classifier (learned) | LLR |
| D5 | signature | exact SHA-256 (+ allowlist), fuzzy CTPH, imphash family | override / LLR |
| D6 | anomaly | kNN distance from a benign manifold (learned) | LLR |
| D7 | ioc/strings | curated indicator co-occurrence, execution-composition aware | LLR |
| — | pickle | static `pickletools` scan of the `torch.load` RCE vector | LLR |
| — | docscan | Office VBA macros (OLE/OOXML) + PDF active content | LLR |
| D8 | rules | human-authored YARA-lite layer (grammar), fused; built-in EICAR | override / LLR |

Binary structural analysis covers **PE, ELF and Mach-O**.

**No single family can auto-quarantine.** A BLOCK requires a positive detector
*outside* the byte-histogram family `{entropy, neural, anomaly}`; those three
alone cap to REVIEW. This consensus guarantee is what makes the learned layer
safe even when under-grounded.

---

## 3. Pipeline

```
file ─▶ D1..D8 + pickle ─▶ each emits ℓᵢ
                            │  allowlist?  ──▶ ALLOW   (trust wins)
                            │  known-bad hash / block-rule ──▶ BLOCK
                            ▼
      posterior = σ( logit(prior) + Σ wᵢℓᵢ )
                            ▼
   > τ_high → BLOCK   (text w/ visible IOCs → REVIEW; learned-only → REVIEW)
   < τ_low  → ALLOW   (strong near-signature → REVIEW, never silently allowed)
   between  → REVIEW, or ESCALATE to the Stage-3 sandbox when detectors disagree
```

---

## 4. CLI

```
aegis scan PATH [--profile max|balanced|relaxed] [--prior P]
                [--skip-dev-noise] [--exclude DIR ...] [--archives] [--dynamic]
                [--rules FILE] [--html report.html] [--quarantine]
                [--flagged-only] [--json]
aegis inspect FILE            # per-detector signed contributions + decision
aegis fuzzy A B               # 0-100 CTPH similarity
aegis imphash FILE            # a PE's import-hash family fingerprint
aegis selftest                # 25 build invariants
aegis train [--corpus DIR] [--augment]      # fit D4/D6 (grounds on host binaries)
aegis make-corpus DIR         # write a benign/ + malicious/ template corpus
aegis evaluate [--corpus DIR] # per-detector + fused ROC/PR, confusion matrix
aegis watch DIR               # on-access scan daemon with JSONL audit
aegis allowlist add FILE      # trust a known-good file (force ALLOW)
aegis blocklist add FILE|add-hash H|add-ioc S|import FEED|list   # known-bad intel
aegis rules list|add FILE|check FILE            # the D8 rule layer
aegis quarantine list|restore ID                # neutered store
aegis gui                     # desktop Security Center
aegis serve [--host H] [--port N]   # local web UI backed by the real engine (127.0.0.1:8008)
aegis adversarial             # prove the ensemble thesis (evade one -> caught by others)
aegis verify-corpus DIR       # corpus hygiene: fail on benign/malicious label leakage
```

### Real-world detection without handling samples
`aegis blocklist import FEED` ingests a plain-text feed — 64-hex lines become
force-block SHA-256 signatures, other lines become fused indicators. Point it at
a public malware-hash export (e.g. from MalwareBazaar / abuse.ch) and you get
genuine real-world signature coverage **without downloading a single sample**.
To go further and strengthen the *learned* layer, drop real labeled samples into
a corpus's `malicious/` (in a VM — see `SECURITY.md`) and `aegis train --corpus`.

Per-user state lives in `~/.aegis`. Empty by default — with nothing curated and
no user model, you run the bundled model plus the analytic ensemble.

### Operating tips
- For routine scans add **`--skip-dev-noise`** (prunes `node_modules`, `.venv`,
  `target/`, `__pycache__`, …). For a security audit of untrusted code, omit it.
- To sharpen the learned layer on your own machine: `aegis train --augment`
  (grounds on real OS binaries — System32 on Windows). It warns if grounding is
  too thin to trust.

---

## 5. Measured behaviour

- `aegis selftest` → **25/25**; `pytest` → **61/61**.
- A fresh install blocks every malware shape out of the box — injector, RAT,
  ransomware, keylogger — while a clean binary stays ALLOW (pinned by a test).
- Field-tested on a real Windows disk: **7,000+ genuine files, 0 false positives
  on real code**; every file in the BLOCK list was an actual malware sample.
- Real-host FP scan (1,748 `/usr/bin` + stdlib files): **0 BLOCK / 0 REVIEW** at
  both `balanced` and `max`.

---

## 6. Limits (stated plainly)

- **Not perfect, provably (§0).** AEGIS shapes error; it never eliminates it.
- **Dynamic analysis is Python-only.** The Stage-3 sandbox runs Python samples
  under an audit hook; native binaries are judged statically, never detonated.
- **Signatures are detected, not verified.** A present Authenticode block softens
  a verdict but the chain isn't validated — a stolen cert only softens to REVIEW.
- **Scripts are surfaced, not blocked.** On text, indicator strings are visible
  content, so a malicious script is capped to REVIEW.
- **Learned coverage is only as real as its corpus.** The bundled model is
  trained on inert fixtures + host binaries; feed real labeled malware (in a VM —
  see `SECURITY.md`) to make it real. A thin corpus can over-fire — now capped to
  REVIEW by the consensus guarantee and flagged by the grounding guard.

---

*A calibrated Bayesian consensus over independent detectors from different
mathematical families, decided against an explicit cost model, honest about every
limit. Still not provably perfect — that was never on the table — but it fails in
deliberately chosen places, and it says exactly why, every time.*
