# Contributing

Thanks for improving AEGIS. The project has one firm rule that every change is
judged against:

> **A false positive is fixed by a more honest signal, a more representative
> sample, a repaired blind spot, or a control the user drives — never by a
> fudged constant.**

## Ground rules

- **Stdlib only.** No third-party runtime dependencies. If you reach for numpy,
  stop — the point is a dependency-free, auditable engine.
- **No detector blocks alone.** A verdict is a calibrated Bayesian consensus
  across detectors from different mathematical families. The learned/entropy
  family may never auto-quarantine without an independent analytic corroborator
  (`core._WEAK_ALONE`).
- **Never trust an extension or a path.** Recognize file kinds by content.
- **Every change keeps the guarantees green.** Before opening a PR:

```
python -m aegis.cli selftest     # build invariants
python -m pytest -q              # unit + regression tests
```

Both must pass. If you add a detector or a recognition rule, add a test that
pins the behavior (and, for a false-positive fix, a regression test that fails
before your change).

## Adding a detector

Emit an `Evidence(name, p, pi_cal, weight, kind, reasons)` from a function in
`aegis/detectors/`, wire it into `evidence_for`, and give it a security floor so
a learned weight-fit can't mute it. Keep its errors as uncorrelated as possible
with the detectors already present — that independence is the whole point.
