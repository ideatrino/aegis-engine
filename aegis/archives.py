"""Recursive, bomb-guarded, model-aware archive scanning (Stage 0 intake).

Malware does not arrive loose; it arrives inside a release .zip or a nested
.tar.gz. To the byte detectors an archive is one opaque high-entropy blob (D2
correctly discounts its entropy), so its contents are never examined. This
module opens zip / tar(.gz/.bz2/.xz) / gzip and yields each member as its own
sample, recursing into nested archives.

Safety is the whole design, because an archive is hostile input:
  * a total-output cap and a per-member cap defeat a decompression bomb,
  * a nesting-depth limit and a member-count cap bound the work,
  * nothing is ever written to disk and nothing is executed.

Model-aware: a PyTorch checkpoint (.pt/.ckpt) is a zip of a `data.pkl` plus
numbered `data/<n>` tensor-storage members. Descending into the tensor storage
and scoring each weight array is a category error (dense floats read as packed
bytes). So for a recognized checkpoint we yield ONLY the pickle(s) -- which is
exactly where the torch.load RCE lives -- and skip the storage. An `.npz` (a zip
of `.npy` arrays) is pure tensor data and is skipped entirely.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Iterator, Tuple


@dataclass
class ArchiveLimits:
    max_total: int = 200 * 1024 * 1024   # total decompressed bytes across a tree
    max_member: int = 64 * 1024 * 1024    # a single member larger than this is skipped
    max_depth: int = 4                    # nesting depth
    max_members: int = 5000               # member count across a tree


class _Budget:
    def __init__(self, limits: ArchiveLimits):
        self.limits = limits
        self.total = 0
        self.count = 0

    def take(self, n: int) -> bool:
        if self.count >= self.limits.max_members:
            return False
        if self.total + n > self.limits.max_total:
            return False
        self.count += 1
        self.total += n
        return True


def is_archive(data: bytes, name: str = "") -> bool:
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return True
    if data[:2] == b"\x1f\x8b":          # gzip (maybe .tar.gz)
        return True
    if data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
        return True
    # tar magic lives at offset 257
    if len(data) > 262 and data[257:262] in (b"ustar",):
        return True
    return False


def _is_checkpoint(names) -> bool:
    has_pkl = any(n.endswith("data.pkl") or n.endswith(".pkl") for n in names)
    has_storage = any("/data/" in n or n.rsplit("/", 1)[-1].isdigit() for n in names)
    return has_pkl and has_storage


def _is_npz(names) -> bool:
    return bool(names) and all(n.endswith(".npy") for n in names)


def iter_members(data: bytes, limits: ArchiveLimits, depth: int = 0,
                 budget: "_Budget | None" = None, prefix: str = "") -> Iterator[Tuple[str, bytes]]:
    """Yield (logical_path, member_bytes) for every scannable member."""
    budget = budget or _Budget(limits)
    if depth > limits.max_depth:
        return

    # ---- ZIP ----
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = [i.filename for i in zf.infolist() if not i.is_dir()]
            if _is_npz(names):
                return  # pure tensor data; nothing to scan
            checkpoint = _is_checkpoint(names)
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if checkpoint and not name.endswith(".pkl"):
                    continue  # skip tensor storage; scan only the pickle
                if info.file_size > limits.max_member:
                    continue
                if not budget.take(info.file_size):
                    return
                try:
                    member = zf.read(info)
                except Exception:
                    continue
                path = f"{prefix}::{name}" if prefix else name
                yield from _yield_or_recurse(path, member, limits, depth, budget)
        except Exception:
            yield (prefix or "archive", data)  # corrupt -> scan as opaque blob
        return

    # ---- TAR (optionally compressed) ----
    if (data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00"
            or (len(data) > 262 and data[257:262] == b"ustar")):
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data))
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                if m.size > limits.max_member:
                    continue
                if not budget.take(m.size):
                    return
                try:
                    f = tf.extractfile(m)
                    member = f.read() if f else b""
                except Exception:
                    continue
                path = f"{prefix}::{m.name}" if prefix else m.name
                yield from _yield_or_recurse(path, member, limits, depth, budget)
            return
        except tarfile.TarError:
            pass  # fall through to standalone gzip handling

    # ---- standalone gzip / bz2 / xz of a single file ----
    if data[:2] == b"\x1f\x8b":
        member = _safe_decompress(gzip.decompress, data, limits.max_member)
    elif data[:3] == b"BZh":
        member = _safe_decompress(bz2.decompress, data, limits.max_member)
    elif data[:6] == b"\xfd7zXZ\x00":
        member = _safe_decompress(lzma.decompress, data, limits.max_member)
    else:
        return
    if member is not None and budget.take(len(member)):
        path = f"{prefix}::decompressed" if prefix else "decompressed"
        yield from _yield_or_recurse(path, member, limits, depth, budget)


def _safe_decompress(fn, data, cap):
    try:
        out = fn(data)
        return out if len(out) <= cap else None
    except Exception:
        return None


def _yield_or_recurse(path, member, limits, depth, budget):
    if is_archive(member) and depth + 1 <= limits.max_depth:
        yielded = False
        for sub in iter_members(member, limits, depth + 1, budget, prefix=path):
            yielded = True
            yield sub
        if not yielded:
            return
    else:
        yield (path, member)
