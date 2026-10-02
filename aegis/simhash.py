"""Context-triggered piecewise hashing (CTPH / the ssdeep family).

This is D5's other half: exact hashing answers "is this the identical file?"
(a one-byte change defeats it), while CTPH answers "how similar is this to a
known-bad file?". A rolling hash over a sliding window cuts the file at
content-defined boundaries, so an edit changes only the pieces near it; two
files that are 95% the same produce digests that are 95% the same.

Pure stdlib, no dependencies. Not bit-compatible with ssdeep, but the same idea
and good enough to catch repacked variants as a *fused* (never force) signal.
"""

from __future__ import annotations

from typing import Optional

_WINDOW = 7
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _rolling(data: bytes, block_size: int) -> str:
    """Emit one base64 char per content-defined chunk boundary."""
    out = []
    h = 0
    acc = 0
    window = bytearray()
    for b in data:
        window.append(b)
        if len(window) > _WINDOW:
            window.pop(0)
        # cheap rolling hash
        h = ((h << 1) + b) & 0xFFFFFFFF
        acc = (acc * 33 + b) & 0xFFFFFFFF
        if len(window) == _WINDOW and (h % block_size) == (block_size - 1):
            out.append(_B64[acc % 64])
            acc = 0
    out.append(_B64[acc % 64])
    return "".join(out)


def _block_size(n: int) -> int:
    bs = 3
    while bs * 64 < n:
        bs *= 2
    return max(bs, 3)


def ctph(data: bytes) -> str:
    """Return a 'blocksize:digest' context-triggered piecewise hash."""
    if not data:
        return "3:"
    bs = _block_size(len(data))
    return f"{bs}:{_rolling(data, bs)}"


def _edit_distance_ratio(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    # bounded Levenshtein similarity
    la, lb = len(a), len(b)
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    dist = prev[lb]
    return 1.0 - dist / max(la, lb)


def similarity(h1: str, h2: str) -> int:
    """0..100 similarity between two CTPH digests."""
    try:
        b1, d1 = h1.split(":", 1)
        b2, d2 = h2.split(":", 1)
    except ValueError:
        return 0
    if b1 != b2:
        # different block sizes -> not directly comparable; be conservative
        return 0
    return int(round(_edit_distance_ratio(d1, d2) * 100))
