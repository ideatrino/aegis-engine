"""AEGIS - Adaptive Ensemble with Guaranteed-envelope Integrity Scoring.

An original antivirus architecture grounded in the mathematics of what
detection can and cannot do (Cohen 1987): since perfect classification is
impossible, shape the error surface deliberately. Every verdict is a
*calibrated posterior* fused in log-odds space from several independent
detectors drawn from different mathematical families, decided against an
explicit cost model, and shipped with the evidence that produced it.

This package is a clean, dependency-free (stdlib-only) reference
implementation of that architecture.
"""

__version__ = "6.4.0-ref"

from .core import Evidence, Verdict, fuse, PROFILES, logit, sigmoid

__all__ = ["Evidence", "Verdict", "fuse", "PROFILES", "logit", "sigmoid", "__version__"]
