"""D4 and D6 -- the learned detectors, in pure Python (no numpy).

D4: a logistic-regression byte/structural classifier.
D6: a kNN anomaly detector -- distance to the nearest benign reference points,
    which handles multimodal "normal" (prose vs code vs binaries) far better than
    one global Gaussian, and avoids the curse-of-dimensionality concentration a
    single Mahalanobis distance suffers (design 8).

Both report a calibrated probability against the corpus base rate (pi_cal) so
their LLRs plug straight into the fusion core. They are fused ONLY when a trained
model is present; with no model, the engine is exactly the analytic ensemble.

Safety: both ABSTAIN (emit nothing) on text, known container/compiled formats,
object files and tiny files -- a byte-frequency model has no signal there, so a
confident verdict would be noise (the lesson behind the 14%->0.2% FP collapse).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .core import Evidence
from . import features as feat

_EPS = 1e-9


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass
class Model:
    pi_cal: float
    mean: List[float]
    std: List[float]
    d4_w: List[float]
    d4_b: float
    d4_platt_a: float
    d4_platt_b: float
    d6_refs: List[List[float]]      # standardized benign reference points
    d6_k: int
    d6_cal_a: float
    d6_cal_b: float

    # ---- persistence ----
    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, text: str) -> "Model":
        return cls(**json.loads(text))

    @classmethod
    def load(cls, path: Path) -> Optional["Model"]:
        try:
            return cls.from_json(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return None

    def save(self, path: Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(self.to_json(), encoding="utf-8")

    # ---- inference ----
    def standardize(self, x: List[float]) -> List[float]:
        return [(xi - m) / (s if s > _EPS else 1.0)
                for xi, m, s in zip(x, self.mean, self.std)]

    def predict_d4(self, xs: List[float]) -> float:
        z = self.d4_b + sum(w * v for w, v in zip(self.d4_w, xs))
        raw = _sigmoid(z)
        # Platt scaling -> calibrated probability
        return _sigmoid(self.d4_platt_a * raw + self.d4_platt_b)

    def predict_d6(self, xs: List[float]) -> float:
        if not self.d6_refs:
            return self.pi_cal
        dists = sorted(_dist(xs, r) for r in self.d6_refs)
        k = min(self.d6_k, len(dists))
        avg = sum(dists[:k]) / k
        return _sigmoid(self.d6_cal_a * avg + self.d6_cal_b)


def _dist(a: List[float], b: List[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def learned_evidence(data: bytes, model: Model, binfo, fmt_known, text, pybc) -> List[Evidence]:
    if feat.should_abstain(data):
        return []       # no signal here -> abstain toward the base rate
    x = feat.extract(data)
    xs = model.standardize(x)
    p4 = min(max(model.predict_d4(xs), 1e-4), 1 - 1e-4)
    p6 = min(max(model.predict_d6(xs), 1e-4), 1 - 1e-4)
    out = [
        Evidence("neural", p=p4, pi_cal=model.pi_cal, weight=1.0, kind="score",
                 reasons=([f"learned byte/structural classifier p={p4:.2f}"] if p4 > 0.6 else [])),
        Evidence("anomaly", p=p6, pi_cal=model.pi_cal, weight=0.8, kind="score",
                 reasons=([f"anomalous vs benign manifold p={p6:.2f}"] if p6 > 0.6 else [])),
    ]
    return out
