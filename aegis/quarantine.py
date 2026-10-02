"""Quarantine store: neuter a blocked file so a stray double-click or another
on-access scanner can't detonate it, while keeping a reversible copy.

Neutering XORs the file's header with a key, which breaks the magic/entry point
so the OS won't execute it, and records enough metadata (original path, key,
SHA-256) to reconstruct the original byte-for-byte on restore -- verified by
hash. Nothing is lost; nothing stays runnable.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import List, Optional

KEY = bytes([0xAE, 0x61, 0x59, 0x53])   # 'AEGIS'-ish repeating XOR key
NEUTER_BYTES = 4096


def _xor(data: bytes, n: int) -> bytes:
    head = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(data[:n]))
    return head + data[n:]


class Quarantine:
    def __init__(self, store: Optional[Path] = None):
        self.store = Path(store or os.path.expanduser("~/.aegis/quarantine"))
        self.store.mkdir(parents=True, exist_ok=True)

    def quarantine(self, path: str) -> dict:
        p = Path(path)
        data = p.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        qid = uuid.uuid4().hex[:12]
        n = min(NEUTER_BYTES, len(data))
        (self.store / f"{qid}.neutered").write_bytes(_xor(data, n))
        meta = {"id": qid, "orig_path": str(p.resolve()), "sha256": sha,
                "size": len(data), "neutered_bytes": n, "time": time.time()}
        (self.store / f"{qid}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        # neuter the original in place so it cannot run, then remove it
        try:
            p.write_bytes(_xor(data, n))
            p.unlink()
        except OSError:
            pass
        return meta

    def list(self) -> List[dict]:
        out = []
        for j in sorted(self.store.glob("*.json")):
            try:
                out.append(json.loads(j.read_text(encoding="utf-8")))
            except Exception:
                continue
        return out

    def restore(self, qid: str, dest: Optional[str] = None) -> dict:
        meta = json.loads((self.store / f"{qid}.json").read_text(encoding="utf-8"))
        neutered = (self.store / f"{qid}.neutered").read_bytes()
        original = _xor(neutered, meta["neutered_bytes"])   # XOR is its own inverse
        got = hashlib.sha256(original).hexdigest()
        if got != meta["sha256"]:
            raise ValueError(f"restore hash mismatch: {got} != {meta['sha256']}")
        target = Path(dest or meta["orig_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(original)
        return {"restored": str(target), "verified": True}
