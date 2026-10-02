"""Invariants that must hold on every build. `python -m aegis.cli selftest`.

Each asserts a property the design promises -- including the self-detection
guard: AEGIS must not flag its own source, which is dense with the very attack
indicators it detects.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .core import fuse, Evidence, logit, sigmoid, DEFAULT_PRIOR
from .scanner import Scanner, ThreatIntel
from .rules import EICAR
from . import simhash


def _ok(cond, msg, results):
    results.append((bool(cond), msg))


def run() -> int:
    results = []

    # 1. logit/sigmoid are inverses
    _ok(abs(sigmoid(logit(0.37)) - 0.37) < 1e-9, "logit/sigmoid inverse", results)

    # 2. base-rate math: a 99.9% detector at a 1e-4 base rate is right ~9% of the time
    e = Evidence("t", p=0.999, pi_cal=0.5, weight=1.0)
    v = fuse("x", [e], prior=1e-4, profile="balanced")
    _ok(0.05 < v.posterior < 0.15, f"base-rate posterior ~0.09 (got {v.posterior:.3f})", results)

    sc = Scanner(profile="balanced")

    # 3. EICAR file (<=128 bytes) is caught
    v = sc.scan_bytes("eicar.com", EICAR.encode())
    _ok(v.decision == "BLOCK", f"EICAR file blocks (got {v.decision})", results)

    # 4. a large file that merely QUOTES EICAR is NOT blocked (self-detection guard)
    quoting = (b"# test fixture\n" + EICAR.encode() + b"\n" + b"x" * 2000)
    v = sc.scan_bytes("quotes_eicar.py", quoting)
    _ok(v.decision != "BLOCK", f"file quoting EICAR not blocked (got {v.decision})", results)

    # 5. ordinary benign text is ALLOWed
    v = sc.scan_bytes("memo.txt", b"Dear team, please review the Q3 report by Friday. Thanks!\n" * 20)
    _ok(v.decision == "ALLOW", f"benign text allowed (got {v.decision})", results)

    # 6. allowlist overrides a known-bad hash
    data = EICAR.encode()
    sha = hashlib.sha256(data).hexdigest()
    intel = ThreatIntel(allow_hashes={sha}, bad_hashes={sha})
    v = Scanner(intel=intel).scan_bytes("eicar.com", data)
    _ok(v.decision == "ALLOW", f"allowlist beats known-bad hash (got {v.decision})", results)

    # 7. known-bad hash forces BLOCK
    benign = b"hello world, just a note\n"
    bsha = hashlib.sha256(benign).hexdigest()
    v = Scanner(intel=ThreatIntel(bad_hashes={bsha})).scan_bytes("n.txt", benign)
    _ok(v.decision == "BLOCK", f"known-bad hash blocks (got {v.decision})", results)

    # 8. a malicious pickle is caught
    import pickle, io
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))
    mal = pickle.dumps(Evil())
    v = sc.scan_bytes("model.pkl", mal)
    _ok(v.decision in ("BLOCK", "REVIEW"), f"malicious pickle flagged (got {v.decision})", results)

    # 9. a benign data pickle is NOT flagged
    good = pickle.dumps({"weights": [1, 2, 3], "name": "layer1"})
    v = sc.scan_bytes("data.pkl", good)
    _ok(v.decision == "ALLOW", f"benign pickle allowed (got {v.decision})", results)

    # 10. a synthetic injector PE blocks; a clean PE does not
    from .fixtures import injector_pe, clean_pe
    v = sc.scan_bytes("inj.exe", injector_pe())
    _ok(v.decision in ("BLOCK", "REVIEW"), f"injector PE flagged (got {v.decision})", results)
    v = sc.scan_bytes("clean.exe", clean_pe())
    _ok(v.decision != "BLOCK", f"clean PE not blocked (got {v.decision})", results)

    # 11. fuzzy CTPH: a 1-byte edit stays highly similar
    a = b"A" * 500 + b"malicious-marker-payload" + b"B" * 500
    b = a[:600] + b"\x00" + a[601:]
    _ok(simhash.similarity(simhash.ctph(a), simhash.ctph(b)) >= 80,
        "fuzzy hash survives 1-byte edit", results)

    # 12. SELF-DETECTION GUARD: AEGIS does not block its own source files
    pkg = Path(__file__).parent
    self_blocked = []
    for src in pkg.rglob("*.py"):
        v = sc.scan_file(str(src))
        if v.decision == "BLOCK":
            self_blocked.append(src.name)
    _ok(not self_blocked, f"no self-detection on own source (blocked: {self_blocked})", results)

    # 13. disagreement raises uncertainty / escalation path exists
    evs = [Evidence("a", p=0.95, pi_cal=0.5, weight=1.0),
           Evidence("b", p=0.05, pi_cal=0.5, weight=1.0)]
    v = fuse("x", evs, prior=0.2, profile="balanced", dynamic_available=True)
    _ok(v.disagreement > 0.1, f"disagreement measured (got {v.disagreement:.3f})", results)

    # 14. empty intel == additive: a plain benign binary allows
    from .fixtures import clean_pe as _c
    v = sc.scan_bytes("c.exe", _c())
    _ok(v.decision != "BLOCK", "clean binary not blocked with empty intel", results)

    # 15. archive scanning finds a malicious member; model-aware skips tensors
    import io, zipfile
    class _Evil2:
        def __reduce__(self):
            import os
            return (os.system, ("echo x",))
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("ok.txt", b"fine")
        z.writestr("p/model.pkl", pickle.dumps(_Evil2()))
    from .archives import iter_members, ArchiveLimits
    members = list(iter_members(zbuf.getvalue(), ArchiveLimits()))
    decs = [sc.scan_bytes(n, m).decision for n, m in members]
    _ok("BLOCK" in decs, f"archive member malware caught (got {decs})", results)

    ck = io.BytesIO()
    with zipfile.ZipFile(ck, "w") as z:
        z.writestr("c/data.pkl", pickle.dumps({"a": 1}))
        for i in range(3):
            z.writestr(f"c/data/{i}", b"\x01\x02\x03\x04" * 300)
    ck_members = [n for n, _ in iter_members(ck.getvalue(), ArchiveLimits())]
    _ok(all("/data/" not in n for n in ck_members),
        f"checkpoint tensor storage skipped (members={ck_members})", results)

    # 16. rule expression grammar: offset + filesize predicate
    from .rules import Rule
    r = Rule(name="t", strings=[("mz", "hex", b"\x4d\x5a")],
             condition="$mz at 0 and filesize < 2MB")
    _ok(r.matches(b"MZ" + b"\x00" * 100) is not None, "rule grammar at/filesize matches", results)
    _ok(r.matches(b"XX" + b"MZ") is None, "rule grammar offset anchor rejects", results)

    # 17. dynamic sandbox: a socket script escapes -> BLOCK; clean -> ALLOW
    from .dynamic import analyze
    from .core import Verdict as _V
    evil = b"import socket\ns=socket.socket()\ns.connect(('10.0.0.1',4444))\n"
    r1 = analyze("e.py", evil, _V("e.py", 0.4, "ESCALATE", [], [], 0.0, 0.3, "balanced"))
    _ok(r1.decision == "BLOCK", f"dynamic escape -> BLOCK (got {r1.decision})", results)
    good = b"t=0\nfor i in range(100):\n    t+=i\n"
    r2 = analyze("g.py", good, _V("g.py", 0.4, "ESCALATE", [], [], 0.0, 0.3, "balanced"))
    _ok(r2.decision == "ALLOW", f"dynamic clean run -> ALLOW (got {r2.decision})", results)

    # 18. quarantine round-trips byte-for-byte
    import tempfile as _tf
    from .quarantine import Quarantine
    with _tf.TemporaryDirectory() as td:
        f = Path(td) / "sample.bin"
        original = b"MZ" + bytes(range(256)) * 8
        f.write_bytes(original)
        q = Quarantine(store=Path(td) / "store")
        meta = q.quarantine(str(f))
        gone = not f.exists()
        q.restore(meta["id"])
        _ok(gone and f.read_bytes() == original, "quarantine neuter+restore byte-for-byte", results)

    # 19. learned detectors abstain where a byte histogram has no signal
    from .features import should_abstain
    _ok(should_abstain(b"def f():\n    return 1\n" * 50), "learned abstains on text", results)
    _ok(should_abstain(b"PK\x03\x04" + b"\x00" * 5000), "learned abstains on zip", results)
    _ok(not should_abstain(injector_pe()), "learned active on a real binary", results)

    passed = sum(1 for ok, _ in results if ok)
    total = len(results)
    for ok, msg in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {msg}")
    print(f"\n{passed}/{total} invariants passed")
    return 0 if passed == total else 1
