"""Feature extraction shared by the learned detectors (D4, D6).

A compact, fixed-length numeric vector per file -- entropy, size, byte-class
ratios, and the structural facts the PE/ELF parser already extracts. Kept small
(~27 dims) so the learned models are pure-Python and fast, yet capture the
"benign vs malicious structure" boundary rather than a spurious one.
"""

from __future__ import annotations

import math
from typing import List

from .entropy import shannon_entropy, max_window_entropy
from . import peparse
from .detectors.static import (is_text, is_python_bytecode, known_container_format,
                               _INJECTION, _NETWORK, _CRYPTO, _ENUM, _KEYLOG, _func)

FEATURE_NAMES = [
    "entropy", "max_win_entropy", "printable_ratio", "nul_ratio", "high_ratio",
    "alpha_ratio", "ws_ratio", "size_log",
    "is_pe", "is_elf", "is_text", "is_known_fmt", "is_pybc", "is_obj",
    "sec_count", "max_sec_entropy", "has_wx", "import_count",
    "inj", "net", "crypto", "enum", "keylog", "signed", "entropy_spread",
    "distinct_bytes", "repeat_ratio",
]
N_FEATURES = len(FEATURE_NAMES)


def extract(data: bytes) -> List[float]:
    n = max(len(data), 1)
    sample = data[:65536]
    sn = max(len(sample), 1)
    nul = sample.count(0) / sn
    high = sum(1 for b in sample if b >= 0x80) / sn
    alpha = sum(1 for b in sample if 65 <= b <= 90 or 97 <= b <= 122) / sn
    ws = sum(1 for b in sample if b in (9, 10, 13, 32)) / sn
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / sn
    distinct = len(set(sample)) / 256.0

    h = shannon_entropy(sample)
    hw = max_window_entropy(data[:262144])

    pybc = is_python_bytecode(data)
    text = is_text(data) and not pybc
    fmt_known = known_container_format(data)
    binfo = peparse.parse(data) if peparse.looks_native(data) else None

    is_pe = 1.0 if (binfo and binfo.fmt == "pe") else 0.0
    is_elf = 1.0 if (binfo and binfo.fmt == "elf") else 0.0
    is_obj = 1.0 if (binfo and binfo.is_relocatable_object) else 0.0

    sec_count = max_sec_ent = has_wx = import_count = 0.0
    inj = net = crypto = enum = keylog = signed = ent_spread = 0.0
    if binfo:
        sec_count = len(binfo.sections)
        ents = [s.entropy for s in binfo.sections]
        max_sec_ent = max(ents) if ents else 0.0
        ent_spread = (max(ents) - min(ents)) if ents else 0.0
        has_wx = 1.0 if binfo.has_wx else 0.0
        import_count = len(binfo.imports)
        signed = 1.0 if (binfo.fmt == "pe" and binfo.signed) else 0.0
        funcs = {_func(s) for s in binfo.imports}
        inj = len(funcs & _INJECTION)
        net = len(funcs & _NETWORK)
        crypto = len(funcs & _CRYPTO)
        enum = len(funcs & _ENUM)
        keylog = len(funcs & _KEYLOG)

    # crude repeat ratio: 1 - distinct/len for the sample head
    repeat = 1.0 - (len(set(sample[:4096])) / max(len(sample[:4096]), 1))

    return [
        h / 8.0, hw / 8.0, printable, nul, high, alpha, ws,
        math.log10(n + 1) / 8.0,
        is_pe, is_elf, 1.0 if text else 0.0, 1.0 if fmt_known else 0.0,
        1.0 if pybc else 0.0, is_obj,
        min(sec_count, 16) / 16.0, max_sec_ent / 8.0, has_wx, min(import_count, 256) / 256.0,
        min(inj, 8) / 8.0, min(net, 8) / 8.0, min(crypto, 8) / 8.0,
        min(enum, 8) / 8.0, min(keylog, 8) / 8.0, signed, ent_spread / 8.0,
        distinct, repeat,
    ]


def should_abstain(data: bytes) -> bool:
    """The learned (byte-histogram) detectors carry no signal on text, known
    container/compiled formats, object files, or tiny files -- they abstain
    there toward the base rate, exactly like D2 (design 14/17/18)."""
    if len(data) < 3072:
        return True
    pybc = is_python_bytecode(data)
    if (is_text(data) and not pybc) or pybc:
        return True
    if known_container_format(data):
        return True
    binfo = peparse.parse(data) if peparse.looks_native(data) else None
    if binfo and binfo.is_relocatable_object:
        return True
    return False
