"""The static ensemble: D1-D3, D5, D7, plus the pickle scanner and D8 rules.

Each detector comes from a *different mathematical family* so their errors are
as uncorrelated as possible (the Condorcet/ensemble argument, design 3.2/4):

  D1 structural   -- grammar / parsing of PE & ELF
  D2 entropy      -- information theory
  D3 api-graph    -- graph theory over the import table
  D5 signature    -- exact SHA-256 + fuzzy CTPH + imphash family fingerprint
  D7 ioc/strings  -- curated indicator co-occurrence
  (pickle)        -- static opcode analysis of the ML supply-chain RCE vector
  D8 rules        -- the human-authored, fused rule layer

An attacker must satisfy all of these contradictory constraints at once:
lowering entropy tends to raise structural regularity; stripping strings doesn't
help the import graph; etc. That coupling is the point.

The two *learned* detectors from the full design -- D4 (neural byte-classifier)
and D6 (anomaly distance on a benign manifold) -- require a trained corpus and
are the documented extension (see README). This reference ships the analytic
ensemble + the teachable rule layer, which run correctly with zero training.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Optional, Tuple

from ..core import Evidence
from ..entropy import shannon_entropy, max_window_entropy
from .. import peparse, simhash, pickle_scan, rules as rules_mod


# --------------------------------------------------------------------------- #
#  Format / text recognition -- "know what kind of thing you are looking at"   #
# --------------------------------------------------------------------------- #
def known_container_format(data: bytes) -> Optional[str]:
    """Recognize dense-but-benign formats so D2 doesn't read them as packed."""
    if len(data) < 4:
        return None
    sigs = {
        b"PK\x03\x04": "zip", b"PK\x05\x06": "zip", b"PK\x07\x08": "zip",
        b"\x1f\x8b": "gzip", b"BZh": "bzip2", b"\xfd7zXZ": "xz",
        b"\x89PNG": "png", b"\xff\xd8\xff": "jpeg", b"%PDF": "pdf",
        b"Caml1999": "ocaml", b"\x84\x95\xa6\xbe": "ocaml-marshal",
        b"Coq!": "coq-vo", b"GGUF": "gguf", b"\x93NUMPY": "npy",
        b"7z\xbc\xaf": "7z", b"Rar!": "rar", b"OggS": "ogg",
        b"\x00\x61\x73\x6d": "wasm",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "ole",   # legacy Office (.doc/.xls)
        # compiled build artifacts -- dense but benign compiler output
        b"!<arch>\n": "ar",                    # static libs, .rlib, .deb
        b"Microsoft C/C++ MSF 7.00": "pdb",    # MSVC debug database
        b"RJVB": "rust-rmeta", b"rust\x00\x00\x00\x00": "rust-rmeta",
    }
    for sig, label in sigs.items():
        if data.startswith(sig):
            return label
    if data[0] == 0x78 and data[1] in (0x01, 0x9C, 0xDA):
        return "zlib"
    if is_coff_object(data):
        return "coff-obj"
    # safetensors: little-endian uint64 header length, then a JSON manifest
    try:
        n = int.from_bytes(data[:8], "little")
        if 0 < n < len(data) and data[8:9] == b"{":
            return "safetensors"
    except Exception:
        pass
    return None


# COFF object files (Windows/MSVC/Rust `.o`) have no magic: they open with a
# 2-byte machine type, and for an *object* (not an image) the optional-header
# size at offset 16 is 0. That pair is a reliable, content-based signal -- these
# are compiler output, not runnable images, so the byte-histogram learners have
# no business judging them (design 17, generalized to the COFF toolchain).
_COFF_MACHINES = {0x014C, 0x8664, 0xAA64, 0x01C0, 0x01C4, 0x0200, 0x0166, 0x5032}


def is_coff_object(data: bytes) -> bool:
    if len(data) < 20:
        return False
    import struct as _s
    try:
        machine, nsec = _s.unpack_from("<HH", data, 0)
        opt_hdr_size = _s.unpack_from("<H", data, 16)[0]
    except Exception:
        return False
    return machine in _COFF_MACHINES and opt_hdr_size == 0 and 0 < nsec <= 96


def is_text(data: bytes, sample: int = 8192) -> bool:
    """UTF-8-aware and tolerant: a unicode-heavy source file -- or one with the
    odd stray byte -- is text, not a binary blob (design 18). Decodes with
    replacement and counts undecodable / non-printable characters; a small bad
    fraction is still text, a NUL or a large one is not."""
    if not data:
        return True
    chunk = data[:sample]
    if b"\x00" in chunk:
        return False
    text = chunk.decode("utf-8", "replace")
    if not text:
        return False
    bad = sum(1 for c in text if c == "�" or not (c.isprintable() or c in "\t\r\n "))
    return bad / len(text) <= 0.10


def is_python_bytecode(data: bytes) -> bool:
    return len(data) >= 16 and data[2:4] == b"\r\n"


# --------------------------------------------------------------------------- #
#  D2 -- Shannon entropy                                                        #
# --------------------------------------------------------------------------- #
def d2_entropy(data: bytes, fmt_known: Optional[str], binfo, text: bool) -> Evidence:
    # Abstain where a byte histogram carries no malware signal: recognized
    # container/compiled formats, text, ELF object files (compiler output).
    if fmt_known or text or (binfo and binfo.is_relocatable_object):
        why = fmt_known or ("text" if text else "object-file")
        return Evidence("entropy", p=0.5, pi_cal=0.5, weight=0.6,
                        reasons=[f"entropy not scored ({why} is dense-but-benign)"])
    # sample-bounded: entropy is a weak detector; a sample is plenty and keeps
    # scanning fast on large files.
    h = shannon_entropy(data[:65536])
    hw = max_window_entropy(data[:262144])
    peak = max(h, hw)
    # weak, smooth mapping; high entropy only nudges
    p = 0.5 + min(max((peak - 6.5) / 1.5, 0.0), 1.0) * 0.22
    reasons = []
    if peak >= 7.5:
        reasons.append(f"high entropy {peak:.2f} bits/byte (packed/encrypted?)")
    return Evidence("entropy", p=p, pi_cal=0.5, weight=0.6, reasons=reasons)


# --------------------------------------------------------------------------- #
#  D1 -- structural (PE / ELF)                                                  #
# --------------------------------------------------------------------------- #
def d1_structural(binfo, text: bool) -> Optional[Evidence]:
    if binfo is None or binfo.fmt == "unknown":
        return None
    reasons: List[str] = []
    p = 0.5
    if binfo.is_relocatable_object:
        return Evidence("structural", p=0.5, pi_cal=0.5, weight=1.0,
                        reasons=["ELF relocatable object (compiler output), not a runnable image"])
    if binfo.max_section_entropy > 7.3:
        p += 0.12
        reasons.append(f"packed code section (entropy {binfo.max_section_entropy:.2f})")
    if binfo.has_wx:
        p += 0.15
        reasons.append("writable+executable section (self-modifying / unpacking stub)")
    if binfo.fmt == "pe" and binfo.signed:
        # Signature is DETECTED, not verified -> soft-benign: downgrade a BLOCK
        # to REVIEW, never trust to a silent ALLOW. (design v4.4)
        return Evidence("structural", p=0.25, pi_cal=0.5, weight=1.0,
                        reasons=["Authenticode signature present (detected, not verified) -> soft-benign"],
                        cap_review=True)
    p = min(p, 0.93)
    return Evidence("structural", p=p, pi_cal=0.5, weight=1.0, reasons=reasons)


# --------------------------------------------------------------------------- #
#  D3 -- API / import-graph                                                     #
# --------------------------------------------------------------------------- #
_INJECTION = {"virtualallocex", "writeprocessmemory", "createremotethread",
              "ntunmapviewofsection", "queueuserapc", "setthreadcontext",
              "rtlcreateuserthread", "ntcreatethreadex"}
_NETWORK = {"connect", "send", "recv", "wsastartup", "internetopenw", "internetopena",
            "internetopenurla", "internetopenurlw", "winhttpopen", "urldownloadtofilew",
            "urldownloadtofilea", "httpsendrequesta", "httpsendrequestw"}
_CRYPTO = {"cryptencrypt", "cryptacquirecontexta", "cryptacquirecontextw",
           "cryptgenkey", "cryptderivekey", "bcryptencrypt", "cryptdecrypt"}
_ENUM = {"findfirstfilew", "findfirstfilea", "findnextfilew", "findnextfilea"}
_KEYLOG = {"getasynckeystate", "setwindowshookexa", "setwindowshookexw", "getkeystate"}


def _func(sym: str) -> str:
    return sym.rsplit(".", 1)[-1].lower()


def d3_api_graph(binfo) -> Optional[Evidence]:
    if binfo is None or not binfo.imports:
        return None
    funcs = {_func(s) for s in binfo.imports}
    inj = len(funcs & _INJECTION)
    net = len(funcs & _NETWORK)
    crypto = len(funcs & _CRYPTO)
    enum = len(funcs & _ENUM)
    keylog = len(funcs & _KEYLOG)

    p = 0.5
    reasons: List[str] = []
    if inj >= 2:
        p = max(p, 0.88)
        reasons.append("process-injection import cluster (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread)")
        if net >= 1:
            p = max(p, 0.90)
            reasons.append("RAT pattern: injection + network")
    if crypto >= 2 and enum >= 1:
        p = max(p, 0.85)
        reasons.append("ransomware shape: crypto APIs + file enumeration")
    if keylog >= 2:
        # a keystroke-hook cluster (GetAsyncKeyState + SetWindowsHookEx) is a
        # strong keylogger signal -> surface it even on an analytic-only verdict
        p = max(p, 0.82)
        reasons.append("keylogger shape: keystroke-hook API cluster")
    elif keylog >= 1:
        p = max(p, 0.68)
        reasons.append("keylogging API present")
    if p == 0.5:
        return Evidence("api_graph", p=0.5, pi_cal=0.5, weight=1.2)
    # Can't detonate a binary here -> surface, never silently allow; but as a
    # non-text binary it CAN contribute to a BLOCK.
    return Evidence("api_graph", p=p, pi_cal=0.5, weight=1.2,
                    kind="review_only", reasons=reasons)


# --------------------------------------------------------------------------- #
#  D7 -- embedded IOC / strings                                                 #
# --------------------------------------------------------------------------- #
_STR_RE = re.compile(rb"[\x20-\x7e]{4,}")
_URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,}")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b[:/]\d")   # IP with a port/path
_B64_RE = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")
# Precise, contiguous indicators -- a word like "powershell" alone (as in a
# detector's own source) is not enough; the suspicious thing is the construction.
_PS_ENC_RE = re.compile(rb"(?i)(powershell[^\n]{0,40}-enc|-encodedcommand\b|frombase64string)")
# A genuine execution-of-fetched-code composition. Indicator LISTS don't contain
# these as live constructs, so a detector's own source won't match (the §18 fix).
_EXEC_COMP_RE = re.compile(
    rb"(?i)(exec\s*\(\s*[a-z_.]*b?64?decode|invoke-expression|\biex\b\s*\(|"
    rb"curl[^\n|]*\|\s*(ba)?sh|wget[^\n|]*\|\s*(ba)?sh|/dev/tcp/\d|"
    rb"bash\s+-i\b|nc\s+-e\b|/bin/sh\s+-i)")


_STR_SAMPLE = 512 << 10  # bound the string-scan cost on very large files


def _extract_strings(data: bytes) -> bytes:
    # Fast: search the raw bytes AND a NUL-stripped copy (which surfaces UTF-16LE
    # text as contiguous ASCII). Both operations are C-level; no per-byte loop.
    sample = data[:_STR_SAMPLE]
    return sample + b"\n" + sample.replace(b"\x00", b"")


def d7_ioc(data: bytes, content_visible: bool) -> Optional[Evidence]:
    """content_visible: the bytes are source/text/bytecode, where indicator
    strings are visible *content*, not payload concealed in a packed binary. On
    such files D7 only goes 'strong' for a real execution composition, and its
    verdict is capped to REVIEW (never auto-quarantine) -- design 18."""
    blob = _extract_strings(data)
    low = blob.lower()
    cats = set()
    reasons: List[str] = []
    if _URL_RE.search(blob) or _IP_RE.search(blob):
        cats.add("c2")
    if b"CurrentVersion\\Run" in blob or b"schtasks /create" in low or b"new-service" in low:
        cats.add("persistence")
    if _PS_ENC_RE.search(blob):
        cats.add("encoded_ps")
    for lb in (b"certutil -decode", b"certutil.exe -decode", b"rundll32 ",
               b"bitsadmin /transfer", b"mshta ", b"regsvr32 /i", b"regsvr32 /s"):
        if lb in low:
            cats.add("lolbin")
            break
    if _EXEC_COMP_RE.search(blob):
        cats.add("shell")
    if _B64_RE.search(blob):
        cats.add("bigb64")

    if not cats:
        return None

    weights = {"c2": 0.08, "persistence": 0.08, "encoded_ps": 0.12,
               "lolbin": 0.10, "shell": 0.12, "bigb64": 0.06}
    p = 0.5 + sum(weights[c] for c in cats)
    # The damning cluster: network/shell co-occurring with exec/persistence.
    strong = bool(("c2" in cats or "shell" in cats) and
                  (cats & {"persistence", "encoded_ps", "lolbin", "shell"}) - {"c2"})
    if content_visible:
        # strings are visible content; only a real execution composition is strong
        strong = strong and "shell" in cats
        if not strong:
            p = min(p, 0.62)        # mere presence of indicator words stays mild
    if strong:
        p += 0.15
    p = min(p, 0.95)
    reasons.append("indicators: " + ", ".join(sorted(cats)))
    kind = "review_only" if strong else "score"
    # On visible text/source, D7 is the AUTOMATIC string detector -> exempt from
    # the never-silently-allowed floor so a file that merely lists indicators
    # (e.g. a detector's own source) is not surfaced. On binaries it is not
    # exempt: a concealed IOC cluster should surface.
    return Evidence("ioc", p=p, pi_cal=0.5, weight=1.0, kind=kind,
                    reasons=reasons, cap_review=content_visible,
                    floor_exempt=content_visible)


# --------------------------------------------------------------------------- #
#  pickle scanner -- the ML supply-chain RCE                                    #
# --------------------------------------------------------------------------- #
def d_pickle(data: bytes) -> Optional[Evidence]:
    rep = pickle_scan.scan(data)
    if not rep.malicious:
        return None
    # A reachable gadget (dangerous global actually invoked via REDUCE/BUILD) is
    # about as close to certain-malicious as static analysis gets -> strong
    # enough to BLOCK through the fusion. A bare import is surfaced for review.
    if rep.calls_dangerous:
        return Evidence("pickle", p=0.98, pi_cal=0.5, weight=2.0, kind="review_only",
                        reasons=rep.reasons)
    return Evidence("pickle", p=0.85, pi_cal=0.5, weight=1.4, kind="review_only",
                    reasons=rep.reasons)


# --------------------------------------------------------------------------- #
#  D5 -- signatures: exact hash, fuzzy CTPH, imphash family                     #
# --------------------------------------------------------------------------- #
def d5_signature(data: bytes, sha256: str, binfo, intel) -> List[Evidence]:
    out: List[Evidence] = []
    if intel is None:
        return out
    if sha256 in intel.allow_hashes:
        out.append(Evidence("allowlist", kind="force_allow",
                            reasons=["allowlisted (known-good SHA-256)"]))
        return out
    if sha256 in intel.bad_hashes:
        out.append(Evidence("signature", kind="force_block",
                            reasons=["SHA-256 matches known-malicious signature"]))
        return out
    # imphash family fingerprint (fused, never force -- toolchains collide)
    if binfo is not None and binfo.imphash and binfo.imphash in intel.bad_imphash:
        out.append(Evidence("imphash", p=0.85, pi_cal=0.5, weight=1.1,
                            kind="review_only",
                            reasons=[f"imphash {binfo.imphash[:12]} matches known malware family"]))
    # fuzzy CTPH near-variant
    if intel.bad_ctph:
        digest = simhash.ctph(data)
        best = max((simhash.similarity(digest, k) for k in intel.bad_ctph), default=0)
        if best >= 80:
            out.append(Evidence("fuzzy", p=0.90, pi_cal=0.5, weight=1.3,
                                kind="review_only",
                                reasons=[f"{best}% CTPH similarity to known-bad file"]))
        elif best >= 50:
            out.append(Evidence("fuzzy", p=0.70, pi_cal=0.5, weight=1.3,
                                kind="review_only",
                                reasons=[f"{best}% CTPH similarity to known-bad file"]))
    return out


def d_intel_ioc(data: bytes, intel, content_visible: bool) -> Optional[Evidence]:
    """A curated indicator (C2 domain, mutex, path) is strong evidence, not
    proof -- a benign security tool can quote a bad domain. So it is FUSED, and
    on visible text it is capped to REVIEW (the §20 identity-vs-indicator line)."""
    if intel is None or not intel.bad_iocs:
        return None
    blob = data[:1 << 20]
    hits = [s for s in intel.bad_iocs if s and s.encode("latin-1", "ignore") in blob]
    if not hits:
        return None
    return Evidence("intel-ioc", p=0.88, pi_cal=0.5, weight=1.2, kind="review_only",
                    reasons=[f"curated threat-intel indicator: {hits[0]!r}"],
                    cap_review=content_visible)


# --------------------------------------------------------------------------- #
#  Orchestration                                                               #
# --------------------------------------------------------------------------- #
def evidence_for(data: bytes, intel=None, extra_rules=None, model=None) -> Tuple[List[Evidence], dict]:
    """Run every static detector over a buffer and return fused Evidence + meta."""
    sha256 = hashlib.sha256(data).hexdigest()
    fmt_known = known_container_format(data)
    binfo = peparse.parse(data) if peparse.looks_native(data) else None
    pybc = is_python_bytecode(data)
    text = is_text(data) and not pybc
    # On source, text, OR python bytecode, indicator strings are visible content,
    # not concealed payload -- D7 stands down on them the same way (design 15/18).
    content_visible = text or pybc

    evs: List[Evidence] = []

    # D5 overrides first (may short-circuit at fusion time)
    evs.extend(d5_signature(data, sha256, binfo, intel))

    e = d1_structural(binfo, text)
    if e:
        evs.append(e)
    evs.append(d2_entropy(data, fmt_known, binfo, text))
    e = d3_api_graph(binfo)
    if e:
        evs.append(e)
    e = d7_ioc(data, content_visible)
    if e:
        evs.append(e)
    e = d_pickle(data)
    if e:
        evs.append(e)
    e = d_intel_ioc(data, intel, content_visible)
    if e:
        evs.append(e)
    from .. import docscan                      # active-document (macro / PDF) detector
    e = docscan.scan_document(data)
    if e:
        evs.append(e)

    # D8: built-in + user rules, fused
    rule_set = None
    if extra_rules is not None:
        rule_set = rules_mod.BUILTIN_RULES + extra_rules
    evs.extend(rules_mod.evaluate_rules(data, rule_set, is_text=content_visible))

    # D4/D6: learned detectors, fused ONLY when a trained model is supplied.
    # Absent -> this appends nothing and the verdict is the analytic engine's.
    if model is not None:
        from ..learned import learned_evidence
        evs.extend(learned_evidence(data, model, binfo, fmt_known, text, pybc))

    meta = {
        "sha256": sha256,
        "size": len(data),
        "format": binfo.fmt if binfo else (fmt_known or ("text" if text else "data")),
        "text": text,
        "imphash": binfo.imphash if binfo else None,
    }
    return evs, meta
