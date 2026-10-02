"""Shannon entropy -- the information-theoretic packing/encryption signal.

H(X) = -sum_b p(b) log2 p(b),  0 <= H <= 8 bits/byte.

Normal code and text sit well below 8; encrypted or packed payloads push toward
it. Entropy alone is a *weak* detector (plenty of legitimate compressed files
are high-entropy), which is exactly why it belongs in an ensemble and never
decides on its own.
"""

from __future__ import annotations

import math
from typing import List


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def windowed_entropy(data: bytes, window: int = 4096) -> List[float]:
    """Entropy per block -- a packed section hides inside an otherwise calm file."""
    out = []
    for i in range(0, len(data), window):
        out.append(shannon_entropy(data[i:i + window]))
    return out


def max_window_entropy(data: bytes, window: int = 4096) -> float:
    w = windowed_entropy(data, window)
    return max(w) if w else 0.0
