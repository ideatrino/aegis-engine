"""Unit tests for the AEGIS reference implementation.  `pytest -q`"""

import hashlib
import pickle
from pathlib import Path

import pytest

from aegis.core import fuse, Evidence, logit, sigmoid, PROFILES
from aegis.scanner import Scanner, ThreatIntel
from aegis import fixtures, simhash, peparse
from aegis.rules import EICAR
from aegis.detectors.static import is_text, known_container_format
from aegis.pickle_scan import scan as pscan


# ------------------------------------------------------------------ math core
def test_logit_sigmoid_inverse():
    for p in (0.01, 0.2, 0.5, 0.73, 0.99):
        assert abs(sigmoid(logit(p)) - p) < 1e-9


def test_base_rate_theorem():
    # a 99.9% detector at a 1-in-10000 base rate is right only ~9% of the time
    e = Evidence("t", p=0.999, pi_cal=0.5, weight=1.0)
    v = fuse("x", [e], prior=1e-4, profile="balanced")
    assert 0.05 < v.posterior < 0.15


def test_llr_is_exact_bayes_update():
    # LLR = logit(p) - logit(pi_cal); with pi_cal=prior the evidence is neutralized
    e = Evidence("t", p=0.3, pi_cal=0.3, weight=1.0)
    assert abs(e.llr()) < 1e-9


def test_fusion_is_additive_in_logodds():
    e1 = Evidence("a", p=0.8, pi_cal=0.5, weight=1.0)
    e2 = Evidence("b", p=0.8, pi_cal=0.5, weight=1.0)
    v = fuse("x", [e1, e2], prior=0.5, profile="balanced")
    expected = sigmoid(logit(0.5) + e1.llr() + e2.llr())
    assert abs(v.posterior - expected) < 1e-9


# ------------------------------------------------------------- overrides / safety
def test_allowlist_beats_known_bad_hash():
    data = EICAR.encode()
    sha = hashlib.sha256(data).hexdigest()
    intel = ThreatIntel(allow_hashes={sha}, bad_hashes={sha})
    assert Scanner(intel=intel).scan_bytes("e", data).decision == "ALLOW"


def test_known_bad_hash_forces_block():
    data = b"totally benign note\n"
    sha = hashlib.sha256(data).hexdigest()
    v = Scanner(intel=ThreatIntel(bad_hashes={sha})).scan_bytes("n.txt", data)
    assert v.decision == "BLOCK"
    assert "signature" in v.reasons[0].lower()


def test_block_reason_names_the_cause_not_a_hash():
    # a rule block must not claim "known-malicious SHA-256" (design v5.1.1)
    v = Scanner().scan_bytes("eicar.com", EICAR.encode())
    assert v.decision == "BLOCK"
    assert any("EICAR" in r or "rule" in r.lower() for r in v.reasons)


# ------------------------------------------------------------------ EICAR / rules
def test_eicar_file_blocks():
    assert Scanner().scan_bytes("eicar.com", EICAR.encode()).decision == "BLOCK"


def test_large_file_quoting_eicar_not_blocked():
    quoting = b"# fixture that documents EICAR:\n" + EICAR.encode() + b"\n" + b"x" * 4000
    assert Scanner().scan_bytes("doc.py", quoting).decision != "BLOCK"


# ------------------------------------------------------------------ pickle vector
def test_malicious_pickle_blocks():
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("id",))
    v = Scanner().scan_bytes("m.pkl", pickle.dumps(Evil()))
    assert v.decision == "BLOCK"


def test_benign_pickle_allowed():
    v = Scanner().scan_bytes("d.pkl", pickle.dumps({"w": [1, 2, 3], "name": "x"}))
    assert v.decision == "ALLOW"


def test_pickle_scanner_detects_import_vs_call():
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("id",))
    rep = pscan(pickle.dumps(Evil()))
    assert rep.malicious and rep.calls_dangerous


# -------------------------------------------------------------------- structural
def test_injector_pe_is_flagged_not_allowed():
    v = Scanner(profile="balanced").scan_bytes("i.exe", fixtures.injector_pe())
    assert v.decision in ("REVIEW", "BLOCK", "ESCALATE")


def test_clean_pe_allowed():
    v = Scanner(profile="balanced").scan_bytes("c.exe", fixtures.clean_pe())
    assert v.decision == "ALLOW"


def test_imphash_clusters_a_family():
    # two injector builds with different bytes share an import-hash fingerprint
    a = peparse.parse(fixtures.injector_pe())
    b = peparse.parse(fixtures.injector_pe())
    assert a.imphash and a.imphash == b.imphash
    assert peparse.parse(fixtures.clean_pe()).imphash != a.imphash


# --------------------------------------------------------------- prior / costmodel
def test_prior_dial_moves_verdict():
    inj = fixtures.injector_pe()
    low = Scanner(prior=1e-3).scan_bytes("i.exe", inj)
    high = Scanner(prior=0.3).scan_bytes("i.exe", inj)
    assert high.posterior > low.posterior
    assert high.decision == "BLOCK"


# ------------------------------------------------------------------- fuzzy hashing
def test_fuzzy_survives_small_edit():
    a = b"A" * 400 + b"payload-marker" + b"B" * 400
    b = a[:500] + b"Z" + a[501:]
    assert simhash.similarity(simhash.ctph(a), simhash.ctph(b)) >= 80


def test_fuzzy_unrelated_is_low():
    a = b"A" * 800
    b = bytes(range(256)) * 4
    assert simhash.similarity(simhash.ctph(a), simhash.ctph(b)) < 50


def test_fuzzy_blocklist_catches_variant():
    orig = b"X" * 300 + b"evil-core-routine" + b"Y" * 300
    variant = orig[:400] + b"!" + orig[401:]           # different SHA-256
    intel = ThreatIntel(bad_ctph=[simhash.ctph(orig)])
    v = Scanner(intel=intel).scan_bytes("variant.bin", variant)
    assert v.decision in ("REVIEW", "BLOCK")


# --------------------------------------------------------------- format / text
def test_text_recognition_tolerates_stray_byte():
    assert is_text(b"def f():\n    return 1  # \xe9 accented\n" * 50)


def test_container_formats_recognized():
    assert known_container_format(b"PK\x03\x04rest") == "zip"
    assert known_container_format(b"\x1f\x8bdata") == "gzip"
    assert known_container_format(b"GGUFxxxx") == "gguf"
    assert known_container_format(b"Coq!....") == "coq-vo"


def test_benign_text_allowed():
    memo = b"Dear team,\nPlease review the Q3 figures before Friday.\nThanks,\nA\n" * 20
    assert Scanner().scan_bytes("memo.txt", memo).decision == "ALLOW"


# --------------------------------------------------------------- self-detection
def test_no_self_detection_on_own_source():
    pkg = Path(__file__).resolve().parent.parent / "aegis"
    sc = Scanner()
    blocked = [p.name for p in pkg.rglob("*.py") if sc.scan_file(str(p)).decision == "BLOCK"]
    assert not blocked


# --------------------------------------------------------------- additivity
def test_empty_intel_is_additive():
    # with nothing curated, a plain clean binary is ALLOW
    assert Scanner().scan_bytes("c.exe", fixtures.clean_pe()).decision == "ALLOW"


def test_disagreement_measured():
    evs = [Evidence("a", p=0.95, pi_cal=0.5), Evidence("b", p=0.05, pi_cal=0.5)]
    v = fuse("x", evs, prior=0.2)
    assert v.disagreement > 0.1


@pytest.mark.parametrize("profile", list(PROFILES))
def test_all_profiles_scan(profile):
    v = Scanner(profile=profile).scan_bytes("c.exe", fixtures.clean_pe())
    assert v.decision in ("ALLOW", "REVIEW", "BLOCK", "ESCALATE")


# ------------------------------------------------------------------- archives
def _zip_of(members):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_archive_finds_malicious_member():
    from aegis.archives import iter_members, ArchiveLimits
    data = _zip_of({"ok.txt": b"fine", "p/model.pkl": pickle.dumps(_evil())})
    sc = Scanner()
    decs = [sc.scan_bytes(n, m).decision for n, m in iter_members(data, ArchiveLimits())]
    assert "BLOCK" in decs


def test_archive_model_aware_skips_tensor_storage():
    from aegis.archives import iter_members, ArchiveLimits
    data = _zip_of({"c/data.pkl": pickle.dumps({"a": 1}),
                    **{f"c/data/{i}": b"\x01\x02\x03\x04" * 300 for i in range(3)}})
    names = [n for n, _ in iter_members(data, ArchiveLimits())]
    assert names == ["c/data.pkl"]


def test_archive_bomb_guard_skips_oversized_member():
    from aegis.archives import iter_members, ArchiveLimits
    data = _zip_of({"big.bin": b"\x00" * 50000})
    lim = ArchiveLimits(max_member=1000)
    assert list(iter_members(data, lim)) == []


def _evil():
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("id",))
    return Evil()


# ------------------------------------------------------------------- rule grammar
def test_rule_grammar_offset_and_filesize():
    from aegis.rules import Rule
    r = Rule(name="t", strings=[("mz", "hex", b"\x4d\x5a")],
             condition="$mz at 0 and filesize < 2MB")
    assert r.matches(b"MZ" + b"\x00" * 50) is not None
    assert r.matches(b"XXMZ") is None


def test_rule_grammar_boolean_and_counts():
    from aegis.rules import Rule
    r = Rule(name="t", strings=[("a", "text", "foo"), ("b", "text", "bar")],
             condition="#a >= 2 and $b")
    assert r.matches(b"foo foo bar") is not None
    assert r.matches(b"foo bar") is None       # only one 'foo'


def test_rule_grammar_malformed_falls_back():
    from aegis.rules import Rule
    r = Rule(name="t", strings=[("a", "text", "foo")],
             condition="$a and and )(", condition_n=1)
    # a broken condition must not raise; it falls back to the count gate
    assert r.matches(b"foo") is not None


def test_rule_file_parse_roundtrip():
    from aegis.rules import parse_rules
    text = '''rule R {
    meta:
        severity = "review"
    strings:
        $a = "beacon.test"
    condition:
        $a
}'''
    rules = parse_rules(text)
    assert len(rules) == 1 and rules[0].severity == "review"
    assert rules[0].matches(b"see beacon.test now") is not None


# ------------------------------------------------------------------- dynamic
def test_dynamic_escape_blocks():
    from aegis.dynamic import analyze
    from aegis.core import Verdict
    evil = b"import socket\ns=socket.socket()\ns.connect(('10.0.0.1',4444))\n"
    v = analyze("e.py", evil, Verdict("e.py", 0.4, "ESCALATE", [], [], 0.0, 0.3, "balanced"))
    assert v.decision == "BLOCK"


def test_dynamic_clean_allows():
    from aegis.dynamic import analyze
    from aegis.core import Verdict
    good = b"t=0\nfor i in range(50):\n    t+=i*i\n"
    v = analyze("g.py", good, Verdict("g.py", 0.4, "ESCALATE", [], [], 0.0, 0.3, "balanced"))
    assert v.decision == "ALLOW"


# ------------------------------------------------------------------- quarantine
def test_quarantine_roundtrip(tmp_path):
    from aegis.quarantine import Quarantine
    f = tmp_path / "s.bin"
    original = b"MZ" + bytes(range(256)) * 6
    f.write_bytes(original)
    q = Quarantine(store=tmp_path / "store")
    meta = q.quarantine(str(f))
    assert not f.exists()                      # neutered + removed
    q.restore(meta["id"])
    assert f.read_bytes() == original          # byte-for-byte


# ------------------------------------------------------------------- intel IOC
def test_intel_ioc_fused_and_text_capped():
    intel = ThreatIntel(bad_iocs=["beacon.attacker.test"])
    # in a binary -> surfaced (REVIEW/BLOCK)
    binv = Scanner(intel=intel).scan_bytes(
        "x.bin", b"\x00\x01beacon.attacker.test\x02" + bytes(range(256)) * 20)
    assert binv.decision in ("REVIEW", "BLOCK")
    # in plain text -> never auto-quarantined
    txtv = Scanner(intel=intel).scan_bytes("notes.txt",
                                           b"IOC to watch: beacon.attacker.test\n" * 5)
    assert txtv.decision != "BLOCK"


# ------------------------------------------------------------------- learned
def test_learned_abstains():
    from aegis.features import should_abstain
    assert should_abstain(b"def f():\n    return 1\n" * 40)
    assert should_abstain(b"PK\x03\x04" + b"\x00" * 5000)
    assert not should_abstain(fixtures.injector_pe())


def test_learned_model_trains_and_fuses():
    from aegis import train as T
    model = T.train(augment=True)
    sc = Scanner(model=model, profile="balanced")
    v = sc.scan_bytes("inj.exe", fixtures.injector_pe())
    names = [n for n, *_ in v.contributions]
    assert "neural" in names and "anomaly" in names
    assert v.decision in ("REVIEW", "BLOCK")
    # a clean binary stays allowed even with the model active
    assert sc.scan_bytes("c.exe", fixtures.clean_pe()).decision != "BLOCK"


# ------------------------------------------------------------------- report
def test_html_report_self_contained():
    from aegis.report import render
    html = render([Scanner().scan_bytes("inj.exe", fixtures.injector_pe())])
    assert "<!doctype html>" in html.lower()
    assert "prefers-color-scheme" in html          # dark-mode aware
    assert "<script" not in html.lower()           # no scripts, fully static
