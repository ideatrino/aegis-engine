"""Scanner orchestration: read a file or tree, fuse the evidence, decide."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set

from .core import Verdict, fuse, DEFAULT_PRIOR, DEFAULT_PROFILE
from .detectors import evidence_for
from . import simhash

MAX_READ = 64 * 1024 * 1024  # never read an unbounded file into memory


@dataclass
class ThreatIntel:
    """Curated, opt-in knowledge. Empty by default == pure analytic engine."""
    allow_hashes: Set[str] = field(default_factory=set)
    bad_hashes: Set[str] = field(default_factory=set)
    bad_imphash: Set[str] = field(default_factory=set)
    bad_ctph: List[str] = field(default_factory=list)
    bad_iocs: List[str] = field(default_factory=list)   # indicator substrings

    @classmethod
    def load(cls, path: Path) -> "ThreatIntel":
        if not path.exists():
            return cls()
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                allow_hashes=set(d.get("allow_hashes", [])),
                bad_hashes=set(d.get("bad_hashes", [])),
                bad_imphash=set(d.get("bad_imphash", [])),
                bad_ctph=list(d.get("bad_ctph", [])),
                bad_iocs=list(d.get("bad_iocs", [])),
            )
        except Exception:
            return cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "allow_hashes": sorted(self.allow_hashes),
            "bad_hashes": sorted(self.bad_hashes),
            "bad_imphash": sorted(self.bad_imphash),
            "bad_ctph": self.bad_ctph,
            "bad_iocs": self.bad_iocs,
        }, indent=2), encoding="utf-8")


class Scanner:
    def __init__(self, intel: Optional[ThreatIntel] = None,
                 prior: float = DEFAULT_PRIOR, profile: str = DEFAULT_PROFILE,
                 extra_rules=None, model=None, archives: bool = False,
                 dynamic: bool = False):
        self.intel = intel or ThreatIntel()
        self.prior = prior
        self.profile = profile
        self.extra_rules = extra_rules or []
        self.model = model          # learned detectors (D4/D6); None = analytic only
        self.archives = archives
        self.dynamic = dynamic

    def scan_bytes(self, path: str, data: bytes) -> Verdict:
        evs, meta = evidence_for(data, intel=self.intel, extra_rules=self.extra_rules,
                                 model=self.model)
        dyn_available = self.dynamic and meta.get("format") == "text"
        v = fuse(path, evs, prior=self.prior, profile=self.profile,
                 dynamic_available=dyn_available)
        # Stage 3: with --dynamic, run the contained behavior-envelope sandbox on
        # any Python sample that is not already blocked (never un-block a
        # force-blocked file). A static-only ALLOW can hide a runtime escape -- a
        # script that imports socket and connects out looks benign until it runs.
        # Also runs on ESCALATE for non-Python (downgrades to REVIEW, no backend).
        if self.dynamic and v.decision != "BLOCK":
            from .dynamic import analyze, _looks_python
            if _looks_python(data) or v.decision == "ESCALATE":
                v = analyze(path, data, v)
        v.meta = meta  # type: ignore[attr-defined]
        return v

    def scan_file(self, path: str) -> Verdict:
        p = Path(path)
        try:
            with open(p, "rb") as fh:
                data = fh.read(MAX_READ)
        except (OSError, PermissionError) as e:
            return Verdict(str(p), 0.0, "ERROR", [f"unreadable: {e}"], [], 0.0,
                           self.prior, self.profile)
        return self.scan_bytes(str(p), data)

    def scan_items(self, path: str):
        """Yield the file's verdict and, if --archives, each member's verdict."""
        v = self.scan_file(path)
        yield v
        if self.archives:
            try:
                with open(path, "rb") as fh:
                    data = fh.read(MAX_READ)
            except OSError:
                return
            from .archives import is_archive, iter_members, ArchiveLimits
            if is_archive(data):
                for name, member in iter_members(data, ArchiveLimits()):
                    yield self.scan_bytes(name, member)

    def scan_tree(self, root: str, excludes: Optional[Iterable[str]] = None):
        excludes = set(excludes or [])
        root_p = Path(os.path.expanduser(os.path.expandvars(root)))
        if root_p.is_file():
            yield from self.scan_items(str(root_p))
            return
        for dirpath, dirnames, filenames in os.walk(root_p):
            dirnames[:] = [d for d in dirnames if d not in excludes]
            for fn in filenames:
                yield from self.scan_items(os.path.join(dirpath, fn))
