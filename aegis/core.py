"""The Bayesian consensus core.

This is the mathematical heart of AEGIS. It implements, exactly:

    logit P(M | E) = logit P(M) + sum_i w_i * l_i

where P(M) is the environment prior (base rate), and each l_i is detector i's
log-likelihood-ratio contribution. Summing in log-odds space *is* Bayes' rule
for independent evidence -- it is not a heuristic.

A detector reports a calibrated probability p_i together with the base rate
pi_cal it was calibrated against; its LLR is then

    l_i = logit(p_i) - logit(pi_cal)

which is the exact naive-Bayes update LR_i = odds(p_i) / odds(pi_cal). This
subtraction is what stops the base rate being counted once per detector (the
"base-rate double-count" bug the design records in v4.2).

The core also encodes the project's hard-won safety rules:
  * an allowlisted file (force_allow) short-circuits to ALLOW before anything;
  * a known-bad hash (force_block) forces BLOCK -- but never over an allowlist;
  * a cap_review signal (text whose "payload" is visible content, not concealed
    bytes) downgrades a would-be BLOCK to REVIEW -- surfaced, never quarantined;
  * when independent detectors disagree, the system distrusts itself and
    escalates rather than guessing.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

_EPS = 1e-6


def logit(p: float) -> float:
    """Log-odds of a probability, clamped away from 0 and 1."""
    p = min(max(p, _EPS), 1.0 - _EPS)
    return math.log(p / (1.0 - p))


def sigmoid(z: float) -> float:
    """Inverse of logit; numerically stable."""
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


# Decision profiles. "Maximum security" and "balanced" are the SAME engine at
# different points on the ROC curve (design 3.4): raising C_FN relative to
# C_FP slides the block threshold down. Nothing else changes.
#   tau_low  : posterior below this -> ALLOW
#   tau_high : posterior above this -> BLOCK (subject to cap_review / allowlist)
#   d_escalate: detector-disagreement variance above which an in-band file is
#               escalated to contained dynamic analysis instead of a guess.
PROFILES = {
    "max":      {"tau_low": 0.02, "tau_high": 0.35, "d_escalate": 0.05},
    "balanced": {"tau_low": 0.10, "tau_high": 0.60, "d_escalate": 0.06},
    "relaxed":  {"tau_low": 0.25, "tau_high": 0.80, "d_escalate": 0.08},
}

DEFAULT_PROFILE = "balanced"

# The base rate of malice in the wild: almost every file is benign. This is the
# prior the base-rate theorem (design 3.1) is built on. It is a dial, not a
# constant -- a server intake raises it, a photo drive lowers it.
DEFAULT_PRIOR = 1e-3

# The byte/structural-learned and entropy detectors form one mathematical family
# (histograms over bytes). A BLOCK must be corroborated by at least one detector
# OUTSIDE this set, so no single family can auto-quarantine on its own.
_WEAK_ALONE = {"entropy", "neural", "anomaly"}


@dataclass
class Evidence:
    """One detector's contribution to the consensus.

    p        : calibrated P(malicious | this detector's view)
    pi_cal   : the base rate p was calibrated against (so the LLR is exact)
    weight   : reliability weight w_i (>= a per-detector security floor; a
               learned fit may raise but never mute a detector -- design 3.2)
    kind     : 'score'        -> an ordinary fused vote
               'review_only'  -> strong evidence, but cannot by itself force a
                                 silent ALLOW; surfaces the file
               'force_block'  -> authoritative known-bad (exact hash)
               'force_allow'  -> authoritative known-good (allowlist)
    cap_review: this signal's "payload" is visible content (text), so a BLOCK it
                would cause is downgraded to REVIEW -- never auto-quarantined.
    """

    name: str
    p: float = 0.5
    pi_cal: float = 0.5
    weight: float = 1.0
    kind: str = "score"
    reasons: List[str] = field(default_factory=list)
    cap_review: bool = False
    # floor_exempt: this strong signal must NOT by itself force a REVIEW on an
    # ALLOW verdict. Set only on the AUTOMATIC text/source string detector (D7),
    # so a detector's own source listing indicator strings is not surfaced --
    # while an analyst's explicit rule or curated IOC still surfaces the file.
    floor_exempt: bool = False

    def llr(self) -> float:
        """Signed log-likelihood-ratio contribution, weighted."""
        if self.kind in ("force_block", "force_allow"):
            return 0.0  # handled as overrides, not as fused evidence
        return self.weight * (logit(self.p) - logit(self.pi_cal))


@dataclass
class Verdict:
    path: str
    posterior: float
    decision: str                      # ALLOW | REVIEW | BLOCK | ESCALATE
    reasons: List[str]
    contributions: List[Tuple[str, float, float, float]]  # name, llr, p, weight
    disagreement: float
    prior: float
    profile: str

    def top_line(self) -> str:
        return f"{self.decision:8s} P(malicious)={self.posterior:.4f}  {self.path}"


def _disagreement(evs: List[Evidence]) -> float:
    """Variance of the firing detectors' individual probabilities.

    High variance == the detectors are fighting. The design's response is to
    *distrust the consensus* and route to dynamic analysis rather than average
    away a real disagreement.
    """
    ps = [e.p for e in evs if e.kind in ("score", "review_only")]
    if len(ps) < 2:
        return 0.0
    mean = sum(ps) / len(ps)
    return sum((x - mean) ** 2 for x in ps) / len(ps)


def fuse(
    path: str,
    evidences: List[Evidence],
    prior: float = DEFAULT_PRIOR,
    profile: str = DEFAULT_PROFILE,
    dynamic_available: bool = False,
) -> Verdict:
    """Combine detector evidence into one calibrated, explainable verdict."""
    prof = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

    force_allow = [e for e in evidences if e.kind == "force_allow"]
    force_block = [e for e in evidences if e.kind == "force_block"]
    fused = [e for e in evidences if e.kind in ("score", "review_only")]

    contributions = [
        (e.name, e.llr(), e.p, e.weight)
        for e in sorted(fused, key=lambda e: -abs(e.llr()))
    ]
    disagreement = _disagreement(fused)

    # --- Override 1: trust wins over everything. An allowlisted file is ALLOW
    #     before any detector or any known-bad hash. (design 11, 20) ---
    if force_allow:
        reasons = [r for e in force_allow for r in e.reasons] or ["allowlisted (known-good hash)"]
        return Verdict(path, 0.0, "ALLOW", reasons, contributions, disagreement, prior, profile)

    # Fuse in log-odds space: the exact Bayes update for independent evidence.
    z = logit(prior) + sum(e.llr() for e in fused)
    posterior = sigmoid(z)

    cap_review = any(e.cap_review for e in fused)

    # --- Override 2: an authoritative known-bad hash forces BLOCK (but an
    #     allowlist, handled above, would already have won). (design 20) ---
    if force_block:
        reasons = [r for e in force_block for r in e.reasons] or ["SHA-256 matches known-malicious signature"]
        # A hash match is identity, not a visible string, so cap_review does
        # NOT soften it -- unlike a fused IOC/rule signal.
        return Verdict(path, max(posterior, 1.0 - _EPS), "BLOCK", reasons,
                       contributions, disagreement, prior, profile)

    # --- Normal decision against the cost-model thresholds. ---
    reasons: List[str] = []
    # Always surface the strongest signals, even on a clear verdict, so the
    # analyst sees *why* a file matters, not just that a number was high.
    for e in fused:
        if e.reasons and (e.kind == "review_only" or abs(e.llr()) > 1.0):
            reasons.extend(e.reasons)

    if posterior >= prof["tau_high"]:
        decision = "BLOCK"
        if cap_review:
            # Text: the indicators ARE the content, not concealed payload.
            # Surface for a human; never auto-quarantine. (design 18)
            decision = "REVIEW"
            reasons.insert(0, "contains attack indicators as visible text -> surfaced, not quarantined")
        elif not any(e.llr() > 0.0 and e.name not in _WEAK_ALONE for e in fused):
            # Consensus guarantee: the learned (byte/structural) and entropy
            # detectors are one family, prone to OOD saturation on unseen benign
            # formats (compiler output, caches). They must not auto-quarantine
            # with no *independent* analytic family corroborating -- that is the
            # single-family blind spot the whole ensemble exists to remove
            # (design 4). Surface it for a human instead of blocking.
            decision = "REVIEW"
            reasons.insert(0, "learned/entropy signal only, no independent corroboration "
                             "-> surfaced, not quarantined")
        else:
            reasons.insert(0, f"posterior {posterior:.3f} >= block threshold {prof['tau_high']}")
    elif posterior <= prof["tau_low"]:
        decision = "ALLOW"
    else:
        # In the uncertain band. If the detectors disagree sharply, escalate to
        # contained dynamic analysis rather than guess; otherwise surface it.
        if disagreement >= prof["d_escalate"] and dynamic_available:
            decision = "ESCALATE"
            reasons.insert(0, f"detectors disagree (var={disagreement:.3f}) -> contained dynamic analysis")
        else:
            decision = "REVIEW"
            reasons.insert(0, f"posterior {posterior:.3f} in uncertain band "
                              f"[{prof['tau_low']}, {prof['tau_high']}]")

    # --- The "never silently allowed" floor. A near-signature-grade static
    #     signal (injection cluster, strong IOC cluster, a reachable pickle
    #     gadget, a high fuzzy/imphash match) cannot be washed out to ALLOW by a
    #     low prior -- it is surfaced for a human. It raises to REVIEW, never
    #     BLOCK, so it never auto-quarantines on a heuristic alone. (design 4, 10)
    if decision == "ALLOW":
        # cap_review evidence (visible text/bytecode) is excluded: its indicators
        # are already-visible content, surfaced by the cap_review rule, and must
        # not force a review purely from strings a file legitimately contains.
        strong = [e for e in fused
                  if e.kind == "review_only" and e.p >= 0.80 and not e.floor_exempt]
        if strong:
            decision = "REVIEW"
            reasons.insert(0, "strong detector signal -> surfaced for review (never silently allowed)")
            for e in strong:
                reasons.extend(r for r in e.reasons if r not in reasons)

    if not reasons:
        reasons = ["no detector fired above its calibration base rate"]
    return Verdict(path, posterior, decision, reasons, contributions, disagreement, prior, profile)
