"""Training, corpus building, and evaluation for the learned detectors.

Everything is pure Python. The corpus is inert: benign host files + synthetic
benign fixtures, and structurally-realistic but non-executable malicious
fixtures (valid headers, injection/RAT/ransomware import tables, packed
sections). This is also the TEMPLATE for real data: drop real labeled samples
into benign/ and malicious/ and retrain with the identical pipeline.
"""

from __future__ import annotations

import math
import os
import random
from pathlib import Path
from typing import List, Tuple

from . import features as feat, fixtures
from .features import N_FEATURES
from .learned import Model, _sigmoid, _dist

random.seed(1337)


# --------------------------------------------------------------------------- #
#  Corpus synthesis (inert)                                                      #
# --------------------------------------------------------------------------- #
_BENIGN_IMPORTS = [
    [("KERNEL32.dll", ["GetProcAddress", "LoadLibraryA", "ExitProcess", "CreateFileW"])],
    [("USER32.dll", ["MessageBoxA", "GetDC", "DrawTextW"]),
     ("KERNEL32.dll", ["GetModuleHandleW", "HeapAlloc"])],
    [("MSVCRT.dll", ["malloc", "free", "printf", "fopen"])],
    [("GDI32.dll", ["CreateFontW", "TextOutW"]), ("KERNEL32.dll", ["Sleep"])],
]
_LOW_ENTROPY = [b"\x90" * 256, (b"\x55\x8b\xec\x83\xec" * 60), b"\x00" * 300, b"ABCD" * 80]


def _benign_pe() -> bytes:
    return fixtures._build_pe(imports=random.choice(_BENIGN_IMPORTS),
                             text_section=random.choice(_LOW_ENTROPY),
                             text_exec=True, text_write=False)


def _signed_benign_pe() -> bytes:
    # a packed-but-signed installer shape: benign, must not read as malware
    data = bytearray(fixtures._build_pe(
        imports=[("KERNEL32.dll", ["GetProcAddress", "LoadLibraryA"])],
        text_section=os.urandom(1500), text_exec=True, text_write=False))
    return bytes(data)  # (signature bit set is exercised separately in tests)


def _poweruser_pe() -> bytes:
    # legitimate powerful software: imports a couple of "scary" APIs but not the
    # full injection trio, not W^X, low entropy -> a hard BENIGN overlap case.
    return fixtures._build_pe(
        imports=[("KERNEL32.dll", ["OpenProcess", "VirtualAlloc", "ReadProcessMemory",
                                   "GetProcAddress"])],
        text_section=random.choice(_LOW_ENTROPY), text_exec=True, text_write=False)


def _stealth_mal_pe() -> bytes:
    # milder malware: only two injection imports, moderate (not pure-random)
    # entropy -> a hard MALICIOUS overlap case.
    body = bytes(random.getrandbits(8) if random.random() < 0.5 else 0x90 for _ in range(1200))
    return fixtures._build_pe(
        imports=[("KERNEL32.dll", ["VirtualAllocEx", "CreateRemoteThread", "Sleep"])],
        text_section=body, text_exec=True, text_write=False)


def synth_benign() -> List[bytes]:
    out = []
    for _ in range(40):
        out.append(_benign_pe())
    for _ in range(10):
        out.append(_signed_benign_pe())
    for _ in range(10):
        out.append(_poweruser_pe())        # hard benign overlap
    return out


def synth_malicious() -> List[bytes]:
    out = []
    for _ in range(26):
        out.append(fixtures.injector_pe())
    for _ in range(18):
        out.append(fixtures.ransomware_pe())
    for _ in range(16):
        out.append(fixtures.rat_pe())           # injection + network
    for _ in range(16):
        out.append(fixtures.keylogger_pe())     # keystroke hooks + exfil
    for _ in range(10):
        out.append(_stealth_mal_pe())      # hard malicious overlap
    return out


MIN_GROUNDING = 40   # below this, the anomaly detector is under-grounded and
                     # prone to the OOD-saturation false positives of v6.1.


def _host_dirs() -> List[str]:
    """Where real benign binaries live, per OS -- so grounding has the diversity
    of the platform the model will actually scan (the v6.1.1 lesson: a model
    grounded only on Linux /usr/bin over-fires on Windows/Rust artifacts)."""
    import sys
    if os.name == "nt":
        win = os.environ.get("SystemRoot", r"C:\Windows")
        dirs = [os.path.join(win, "System32"), os.path.join(win, "SysWOW64")]
        for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if pf:
                dirs.append(pf)
        return dirs
    dirs = ["/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/lib", "/usr/local/bin"]
    if sys.platform == "darwin":
        dirs += ["/System/Library/Frameworks", "/usr/lib/system"]
    return dirs


def host_benign(limit: int = 200) -> List[bytes]:
    """Sample real benign binaries from the host for grounding diversity.
    Cross-platform: on Windows this reads System32 (thousands of real PEs), so a
    Windows-trained model is grounded in real Windows binaries instead of a dozen
    synthetic fixtures."""
    out, seen = [], 0
    for d in _host_dirs():
        if not os.path.isdir(d):
            continue
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for fn in names:
            p = os.path.join(d, fn)
            try:
                if not os.path.isfile(p) or os.path.getsize(p) < 3072:
                    continue
                with open(p, "rb") as fh:
                    data = fh.read(1 << 20)
                if feat.should_abstain(data):
                    continue
                out.append(data)
                seen += 1
                if seen >= limit:
                    return out
            except OSError:
                continue
    return out


def build_dataset(corpus_dir: str = None, augment: bool = True) -> Tuple[List[bytes], List[int]]:
    data: List[bytes] = []
    labels: List[int] = []
    if corpus_dir:
        for label, sub in ((0, "benign"), (1, "malicious")):
            d = os.path.join(corpus_dir, sub)
            if os.path.isdir(d):
                for fn in os.listdir(d):
                    p = os.path.join(d, fn)
                    if os.path.isfile(p):
                        with open(p, "rb") as fh:
                            b = fh.read(1 << 20)
                        data.append(b)
                        labels.append(label)
    if not corpus_dir or augment:
        for b in synth_benign() + host_benign():
            data.append(b); labels.append(0)
        for b in synth_malicious():
            data.append(b); labels.append(1)
    return data, labels


# --------------------------------------------------------------------------- #
#  Pure-Python logistic regression                                              #
# --------------------------------------------------------------------------- #
def _standardize_fit(X):
    n = len(X)
    dim = len(X[0])
    mean = [sum(row[j] for row in X) / n for j in range(dim)]
    std = [math.sqrt(sum((row[j] - mean[j]) ** 2 for row in X) / n) or 1.0 for j in range(dim)]
    return mean, std


def _apply_std(x, mean, std):
    return [(xi - m) / (s if s > 1e-9 else 1.0) for xi, m, s in zip(x, mean, std)]


def _fit_logistic(X, y, epochs=400, lr=0.3, l2=1e-3):
    dim = len(X[0])
    w = [0.0] * dim
    b = 0.0
    n = len(X)
    for _ in range(epochs):
        gw = [0.0] * dim
        gb = 0.0
        for xi, yi in zip(X, y):
            z = b + sum(w[j] * xi[j] for j in range(dim))
            p = _sigmoid(z)
            err = p - yi
            for j in range(dim):
                gw[j] += err * xi[j]
            gb += err
        for j in range(dim):
            w[j] -= lr * (gw[j] / n + l2 * w[j])
        b -= lr * (gb / n)
    return w, b


def _fit_logistic_1d(xs, ys, epochs=500, lr=0.5):
    a = 0.0
    b = 0.0
    n = len(xs)
    for _ in range(epochs):
        ga = gb = 0.0
        for x, yv in zip(xs, ys):
            p = _sigmoid(a * x + b)
            err = p - yv
            ga += err * x
            gb += err
        a -= lr * ga / n
        b -= lr * gb / n
    return a, b


# --------------------------------------------------------------------------- #
#  Train                                                                         #
# --------------------------------------------------------------------------- #
def train(corpus_dir: str = None, augment: bool = True) -> Model:
    data, labels = build_dataset(corpus_dir, augment)
    feats = [feat.extract(d) for d in data]
    mean, std = _standardize_fit(feats)
    Xs = [_apply_std(f, mean, std) for f in feats]

    pi_cal = sum(labels) / len(labels)

    # D4 logistic
    w, b = _fit_logistic(Xs, labels)
    raw = [_sigmoid(b + sum(wj * xj for wj, xj in zip(w, x))) for x in Xs]
    platt_a, platt_b = _fit_logistic_1d(raw, [float(l) for l in labels])

    # D6 anomaly: benign reference points (disjoint from calibration via leave-self-out)
    benign_refs = [x for x, l in zip(Xs, labels) if l == 0]
    k = min(5, max(1, len(benign_refs) - 1))
    dists = []
    for x, l in zip(Xs, labels):
        ds = sorted(_dist(x, r) for r in benign_refs if r is not x)
        dists.append(sum(ds[:k]) / k if ds else 0.0)
    cal_a, cal_b = _fit_logistic_1d(dists, [float(l) for l in labels])

    # Grounding guard: an anomaly detector with too few benign reference points
    # has a thin notion of "normal" and will OOD-saturate (the v6.1 Rust-artifact
    # flood). Warn loudly rather than silently ship an over-firing model. The
    # consensus guarantee (core._WEAK_ALONE) caps the damage to REVIEW, but the
    # honest fix is more benign diversity -- add real benign files, or run on the
    # platform you will scan so host grounding (System32 on Windows) kicks in.
    import sys as _sys
    if len(benign_refs) < MIN_GROUNDING:
        print(f"WARNING: only {len(benign_refs)} benign reference points "
              f"(< {MIN_GROUNDING}). This model is UNDER-GROUNDED and may flag "
              f"benign binaries/compiled artifacts. Add real benign files to "
              f"your corpus's benign/ folder (or run `make-corpus` + `train "
              f"--corpus`), then retrain.", file=_sys.stderr)

    return Model(pi_cal=pi_cal, mean=mean, std=std,
                 d4_w=w, d4_b=b, d4_platt_a=platt_a, d4_platt_b=platt_b,
                 d6_refs=benign_refs, d6_k=k, d6_cal_a=cal_a, d6_cal_b=cal_b)


# --------------------------------------------------------------------------- #
#  Metrics                                                                       #
# --------------------------------------------------------------------------- #
def roc_auc(scores, labels) -> float:
    pos = [s for s, l in zip(scores, labels) if l == 1]
    neg = [s for s, l in zip(scores, labels) if l == 0]
    if not pos or not neg:
        return float("nan")
    # Mann-Whitney U / (|pos||neg|)
    allpairs = 0
    wins = 0.0
    for p in pos:
        for q in neg:
            allpairs += 1
            if p > q:
                wins += 1
            elif p == q:
                wins += 0.5
    return wins / allpairs


def evaluate(corpus_dir: str = None, augment: bool = True) -> dict:
    data, labels = build_dataset(corpus_dir, augment)
    # split 70/30 deterministically
    idx = list(range(len(data)))
    random.Random(7).shuffle(idx)
    cut = int(len(idx) * 0.7)
    tr, te = idx[:cut], idx[cut:]

    tr_data = [data[i] for i in tr]; tr_lab = [labels[i] for i in tr]
    te_data = [data[i] for i in te]; te_lab = [labels[i] for i in te]

    # train on the training split only; test labels stay clean
    model = _train_from_lists(tr_data, tr_lab)

    # per-detector AUC on test
    d4s, d6s = [], []
    for d in te_data:
        x = model.standardize(feat.extract(d))
        d4s.append(model.predict_d4(x))
        d6s.append(model.predict_d6(x))

    # fused posterior on test (full pipeline with the learned model)
    from .scanner import Scanner
    sc = Scanner(model=model, profile="balanced", prior=0.3)
    fused = []
    for d in te_data:
        fused.append(sc.scan_bytes("x", d).posterior)

    thr = 0.5
    tp = sum(1 for p, l in zip(fused, te_lab) if p >= thr and l == 1)
    fp = sum(1 for p, l in zip(fused, te_lab) if p >= thr and l == 0)
    tn = sum(1 for p, l in zip(fused, te_lab) if p < thr and l == 0)
    fn = sum(1 for p, l in zip(fused, te_lab) if p < thr and l == 1)
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")

    auc_fused = roc_auc(fused, te_lab)
    note = ("AUC~1.0 on the synthetic corpus is NOT a meaningful score -- the "
            "inert fixtures are cleanly separable (injection imports). Drop REAL "
            "labeled malware into the corpus to get a believable number (design 8).")
    return {
        "n_train": len(tr), "n_test": len(te), "pi_cal": round(model.pi_cal, 3),
        "auc_d4_neural": round(roc_auc(d4s, te_lab), 4),
        "auc_d6_anomaly": round(roc_auc(d6s, te_lab), 4),
        "auc_fused": round(auc_fused, 4),
        "recall": round(recall, 3), "fpr": round(fpr, 3),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "note": note,
    }


def _train_from_lists(data, labels) -> Model:
    feats = [feat.extract(d) for d in data]
    mean, std = _standardize_fit(feats)
    Xs = [_apply_std(f, mean, std) for f in feats]
    pi_cal = sum(labels) / len(labels) if labels else 0.5
    w, b = _fit_logistic(Xs, labels)
    raw = [_sigmoid(b + sum(wj * xj for wj, xj in zip(w, x))) for x in Xs]
    platt_a, platt_b = _fit_logistic_1d(raw, [float(l) for l in labels])
    benign_refs = [x for x, l in zip(Xs, labels) if l == 0]
    k = min(5, max(1, len(benign_refs) - 1))
    dists = []
    for x, l in zip(Xs, labels):
        ds = sorted(_dist(x, r) for r in benign_refs if r is not x)
        dists.append(sum(ds[:k]) / k if ds else 0.0)
    cal_a, cal_b = _fit_logistic_1d(dists, [float(l) for l in labels])
    return Model(pi_cal=pi_cal, mean=mean, std=std, d4_w=w, d4_b=b,
                 d4_platt_a=platt_a, d4_platt_b=platt_b, d6_refs=benign_refs,
                 d6_k=k, d6_cal_a=cal_a, d6_cal_b=cal_b)


# --------------------------------------------------------------------------- #
#  make-corpus (write the inert dataset + template to disk)                      #
# --------------------------------------------------------------------------- #
def make_corpus(out_dir: str) -> dict:
    out = Path(out_dir)
    (out / "benign").mkdir(parents=True, exist_ok=True)
    (out / "malicious").mkdir(parents=True, exist_ok=True)
    nb = nm = 0
    for i, b in enumerate(synth_benign()):
        (out / "benign" / f"ben_pe_{i}.bin").write_bytes(b); nb += 1
    for i, b in enumerate(host_benign()):
        (out / "benign" / f"host_{i}.bin").write_bytes(b); nb += 1
    # some benign text/scripts too (abstained by learned, scanned by analytic)
    for i in range(10):
        (out / "benign" / f"memo_{i}.txt").write_bytes(
            (f"Dear team,\nPlease review item {i} before Friday.\nThanks,\nA\n" * 8).encode())
        nb += 1
    for i, b in enumerate(synth_malicious()):
        (out / "malicious" / f"mal_pe_{i}.bin").write_bytes(b); nm += 1
    # inert malicious pickles + eicar
    import pickle
    class _Evil:
        def __reduce__(self):
            import os
            return (os.system, ("echo inert",))
    for i in range(6):
        (out / "malicious" / f"mal_pickle_{i}.pkl").write_bytes(pickle.dumps(_Evil()))
        nm += 1
    from .rules import EICAR
    (out / "malicious" / "eicar.com").write_bytes(EICAR.encode()); nm += 1
    return {"benign": nb, "malicious": nm, "path": str(out)}
