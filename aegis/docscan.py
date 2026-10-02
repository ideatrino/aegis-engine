"""Active-document detector -- Office macros and malicious PDFs.

The biggest real-world infection vector the byte/structural ensemble ignores is
the *document that carries code*: a Word/Excel file with a VBA macro, or a PDF
with auto-running JavaScript / an embedded launcher. These are structured
container formats (the learned byte-histogram detectors abstain on them), so a
dedicated, content-aware detector judges them.

Heuristic by design (fully parsing CFB + compressed VBA, or decrypting PDF
object streams, is out of scope for a stdlib reference), but keyed on the
constructs that actually distinguish a weaponized document from a benign one:
a macro that auto-runs and reaches a shell / downloader, or a PDF that runs
JavaScript on open or launches a program. A plain .docx/.pdf trips nothing.
"""

from __future__ import annotations

import re
from typing import Optional

from .core import Evidence

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"      # legacy .doc/.xls/.ppt (CFB)


def is_document(data: bytes) -> Optional[str]:
    if data[:8] == OLE_MAGIC:
        return "ole"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06") and b"[Content_Types].xml" in data[:1 << 20]:
        return "ooxml"
    return None


# VBA auto-execution entry points and the dangerous calls a weaponized macro makes
_MACRO_AUTOEXEC = (b"AutoOpen", b"AutoExec", b"AutoClose", b"Document_Open",
                   b"Workbook_Open", b"Document_Close", b"Auto_Open")
_MACRO_DANGER = (b"Shell", b"CreateObject", b"WScript.Shell", b"powershell",
                 b"URLDownloadToFile", b"MSXML2", b"XMLHTTP", b"ADODB.Stream",
                 b"WinHttp", b"cmd.exe", b"CreateProcess", b"VirtualAlloc",
                 b"GetObject", b"Environ", b"Base64", b"FromBase64String")
_HAS_VBA = (b"vbaProject.bin", b"_VBA_PROJECT", b"VBAProject", b"\x00Macros",
            b"Attribut\x00e VB_", b"Attribute VB_Name")


def _pdf_markers(data: bytes):
    d = data[:4 << 20]
    hit = {}
    for key, pat in (("js", rb"/JavaScript\b|/JS\b"),
                     ("openaction", rb"/OpenAction\b|/AA\b"),
                     ("launch", rb"/Launch\b"),
                     ("embedded", rb"/EmbeddedFile\b"),
                     ("gotor", rb"/URI\s*\(")):
        if re.search(pat, d):
            hit[key] = True
    return hit


def scan_document(data: bytes) -> Optional[Evidence]:
    kind = is_document(data)
    if kind is None:
        return None
    sample = data[:4 << 20]

    if kind in ("ole", "ooxml"):
        has_macro = (kind == "ooxml" and b"vbaProject.bin" in sample) or \
                    any(m in sample for m in _HAS_VBA)
        if not has_macro:
            return None                      # a plain macro-free document
        autoexec = [m for m in _MACRO_AUTOEXEC if m in sample]
        danger = [m for m in _MACRO_DANGER if m in sample]
        reasons = ["document contains a VBA macro"]
        p = 0.70
        if autoexec:
            p = 0.86
            reasons.append("macro auto-executes on open (" +
                           autoexec[0].decode("latin-1") + ")")
        if danger:
            p = 0.93
            reasons.append("macro reaches dangerous API (" +
                           ", ".join(d.decode('latin-1') for d in danger[:3]) + ")")
        return Evidence("macro", p=p, pi_cal=0.5, weight=1.2, kind="review_only",
                        reasons=reasons)

    if kind == "pdf":
        hit = _pdf_markers(sample)
        if not hit:
            return None
        reasons = ["PDF active content: " + ", ".join(sorted(hit))]
        strong = ("launch" in hit) or ("js" in hit and "openaction" in hit)
        p = 0.85 if strong else 0.62
        if strong:
            reasons.insert(0, "PDF runs code on open / launches a program")
        return Evidence("pdf-active", p=p, pi_cal=0.5, weight=1.1, kind="review_only",
                        reasons=reasons)
    return None
