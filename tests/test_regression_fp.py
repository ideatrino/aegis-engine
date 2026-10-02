"""Regression tests for the compiled-artifact false-positive flood and the
UTF-8 console crash (the v6.1.1 fixes). These lock in that:

  * the learned/entropy family cannot auto-quarantine without an independent
    analytic corroborator (the consensus guarantee);
  * compiled build artifacts (COFF objects, ar archives, PDBs) are recognized
    and so the byte-histogram learners abstain on them;
  * a path with a non-cp1252 character cannot crash a scan.
"""

import struct

from aegis.core import fuse, Evidence
from aegis.detectors.static import known_container_format, is_coff_object


# ---- the consensus guarantee: learned/entropy alone must not BLOCK ----------
def test_learned_only_cannot_block():
    evs = [Evidence("neural", p=0.99, pi_cal=0.474, weight=1.0),
           Evidence("anomaly", p=0.99, pi_cal=0.474, weight=0.8),
           Evidence("entropy", p=0.72, pi_cal=0.5, weight=0.6)]
    v = fuse("dep-graph.bin", evs, prior=1e-3, profile="balanced")
    assert v.decision != "BLOCK"          # surfaced, never auto-quarantined
    assert v.posterior > 0.6              # the posterior really was high


def test_learned_plus_analytic_corroborator_blocks():
    evs = [Evidence("neural", p=0.99, pi_cal=0.474, weight=1.0),
           Evidence("anomaly", p=0.99, pi_cal=0.474, weight=0.8),
           Evidence("api_graph", p=0.88, pi_cal=0.5, weight=1.2, kind="review_only",
                    reasons=["process-injection import cluster"])]
    v = fuse("real_malware.exe", evs, prior=1e-3, profile="balanced")
    assert v.decision == "BLOCK"


def test_max_profile_also_requires_corroboration():
    evs = [Evidence("neural", p=0.99, pi_cal=0.474, weight=1.0),
           Evidence("anomaly", p=0.99, pi_cal=0.474, weight=0.8)]
    v = fuse("x.o", evs, prior=1e-3, profile="max")
    assert v.decision != "BLOCK"


# ---- compiled-artifact recognition -----------------------------------------
def test_coff_object_recognized():
    # machine=x64, 5 sections, SizeOfOptionalHeader=0 -> an object file
    coff = struct.pack("<HHIIIHH", 0x8664, 5, 0, 0x400, 40, 0, 0x0004) + b"\x00" * 2000
    assert is_coff_object(coff)
    assert known_container_format(coff) == "coff-obj"


def test_ar_archive_recognized():
    assert known_container_format(b"!<arch>\n" + b"x" * 100) == "ar"


def test_pdb_recognized():
    assert known_container_format(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS" + b"\x00" * 100) == "pdb"


def test_a_real_image_is_not_mistaken_for_an_object():
    # a normal PE/ELF image must NOT be treated as a COFF object (it has an
    # optional header), so it still gets full scrutiny
    from aegis import fixtures
    assert not is_coff_object(fixtures.clean_pe())


# ---- bundled model blocks every malware class out of the box ----------------
def test_bundled_model_blocks_all_malware_classes():
    """A fresh install (bundled model, no retrain) must BLOCK every malware shape
    and leave a clean binary alone. Guards the v6.1.2 coverage work."""
    from pathlib import Path
    from aegis.learned import Model
    from aegis.scanner import Scanner
    from aegis import fixtures
    bundled = Path(__file__).resolve().parent.parent / "aegis" / "data" / "model.json"
    if not bundled.exists():
        import pytest
        pytest.skip("no bundled model shipped")
    sc = Scanner(model=Model.load(bundled), profile="balanced")
    for name, fn in [("injector", fixtures.injector_pe), ("rat", fixtures.rat_pe),
                     ("ransomware", fixtures.ransomware_pe),
                     ("keylogger", fixtures.keylogger_pe)]:
        v = sc.scan_bytes(name, fn())
        assert v.decision == "BLOCK", f"{name} -> {v.decision} (expected BLOCK)"
    assert sc.scan_bytes("clean.exe", fixtures.clean_pe()).decision == "ALLOW"


# ---- --dynamic actually runs the sandbox on a statically-clean script -------
def test_dynamic_catches_runtime_escape_on_static_allow():
    """A script that imports socket and connects out looks benign statically; with
    --dynamic the sandbox must observe the network escape and BLOCK it, while a
    pure-compute script stays ALLOW."""
    from aegis.scanner import Scanner
    sc = Scanner(dynamic=True, profile="balanced")
    evil = b"import socket\ns = socket.socket()\ns.connect(('1.2.3.4', 80))\n"
    assert sc.scan_bytes("net.py", evil).decision == "BLOCK"
    good = b"def add(a, b):\n    return a + b\nprint(add(2, 3))\n"
    assert sc.scan_bytes("calc.py", good).decision == "ALLOW"


# ---- GUI worker (tk-free) and import without a display ----------------------
def test_gui_imports_without_tkinter():
    # gui.py must import on a headless box (tkinter is lazy-loaded in launch())
    import importlib
    import aegis.gui as g
    importlib.reload(g)
    assert hasattr(g, "launch") and hasattr(g, "iter_scan")


def test_gui_worker_scans_like_the_cli(tmp_path):
    from aegis import gui, fixtures
    (tmp_path / "inj.exe").write_bytes(fixtures.injector_pe())
    (tmp_path / "clean.exe").write_bytes(fixtures.clean_pe())
    sc = gui.build_scanner(profile="balanced")
    decisions = {v.path.split("/")[-1].split("\\")[-1]: v.decision
                 for v in gui.iter_scan(sc, str(tmp_path))}
    assert decisions["inj.exe"] == "BLOCK"
    assert decisions["clean.exe"] == "ALLOW"


# ---- active-document detector (macros / PDF) --------------------------------
def _ole(*markers):
    return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 200 + b"".join(markers) + b"\x00" * 3000

def test_macro_document_is_flagged_not_allowed():
    from aegis.scanner import Scanner
    sc = Scanner()
    v = sc.scan_bytes("m.doc", _ole(b"_VBA_PROJECT", b"AutoOpen", b"Shell", b"powershell"))
    assert v.decision in ("REVIEW", "BLOCK")

def test_benign_office_document_is_allowed():
    import io, zipfile
    from aegis.scanner import Scanner
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>" * 500)
    assert Scanner().scan_bytes("d.docx", buf.getvalue()).decision == "ALLOW"

def test_macro_enabled_ooxml_flagged():
    import io, zipfile
    from aegis.scanner import Scanner
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/vbaProject.bin", b"\x00AutoOpen Shell")
    assert Scanner().scan_bytes("m.docm", buf.getvalue()).decision in ("REVIEW", "BLOCK")

def test_malicious_pdf_flagged_benign_pdf_allowed():
    from aegis.scanner import Scanner
    sc = Scanner()
    evil = b"%PDF-1.5\n1 0 obj<</OpenAction<</S/JavaScript/JS(x)>>>>endobj\n" + b"%" * 2000
    benign = b"%PDF-1.5\n1 0 obj<</Type/Catalog>>endobj\n" + b"text " * 2000
    assert sc.scan_bytes("e.pdf", evil).decision in ("REVIEW", "BLOCK")
    assert sc.scan_bytes("b.pdf", benign).decision == "ALLOW"


# ---- Mach-O recognition -----------------------------------------------------
def test_macho_recognized_as_native():
    import struct
    from aegis import peparse
    macho = b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIII", 0x01000007, 3, 0, 2, 0, 0) + b"\x00" * 200
    assert peparse.identify(macho) == "macho"
    assert peparse.looks_native(macho)


# ---- web server (aegis serve) backed by the real engine ---------------------
def test_webserver_scan_to_dict():
    from aegis import webserver
    from aegis.scanner import Scanner
    from aegis.rules import EICAR
    sc = Scanner(profile="balanced")
    bad = webserver.scan_to_dict(sc, "e.com", EICAR.encode())
    assert bad["decision"] == "BLOCK" and 0.0 <= bad["posterior"] <= 1.0
    good = webserver.scan_to_dict(sc, "m.txt", b"hello team\n" * 40)
    assert good["decision"] == "ALLOW"
    assert isinstance(bad["contributions"], list) and "sha256" in bad["meta"]


def test_webserver_page_renders_version():
    from aegis import webserver
    assert "VERSION" in webserver.PAGE and 'id="drop"' in webserver.PAGE


# ---- UTF-8 path safety ------------------------------------------------------
def test_scan_path_with_non_cp1252_char(tmp_path):
    from aegis.scanner import Scanner
    p = tmp_path / "\U0001d70bthon.bin"       # a file literally named with pi
    p.write_bytes(b"benign content\n" * 100)
    v = Scanner().scan_file(str(p))
    assert v.decision in ("ALLOW", "REVIEW")  # the point is it does not raise
