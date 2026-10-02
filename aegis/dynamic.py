"""Stage 3 -- contained dynamic analysis, orchestration side.

When the static consensus lands in the uncertain band and the detectors
disagree, the core ESCALATEs. For a Python sample we then run it in the isolated
`sandbox_runner` child and check the recorded action trace against the behavior
envelope S_safe: a plain program may read files and compute; it may NOT open a
socket, spawn a shell, call native code, or destroy files. Any such escape is a
violation observed at runtime -- far stronger than a static string -- so it
drives BLOCK; a clean run settles the file to ALLOW.

Binaries need an OS/VM backend that this reference does not ship, so for them the
escalation is reported honestly as "not run".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

from .core import Verdict


def _looks_python(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if text.startswith("#!") and "python" in text.splitlines()[0]:
        return True
    hints = ("import ", "def ", "print(", "__name__", "exec(", "eval(", "os.",
             "subprocess", "for ", "while ", "class ", "return ", "=", "lambda")
    if sum(1 for h in hints if h in text) < 2:
        return False
    # strongest signal: it actually compiles as Python
    try:
        compile(text, "<sample>", "exec")
        return True
    except SyntaxError:
        return False


def analyze(path: str, data: bytes, verdict: Verdict) -> Verdict:
    if not _looks_python(data):
        verdict.reasons.insert(0, "dynamic analysis: no backend for this file type (not run)")
        # fall back to REVIEW rather than a silent guess
        if verdict.decision == "ESCALATE":
            verdict.decision = "REVIEW"
        return verdict

    runner = os.path.join(os.path.dirname(__file__), "sandbox_runner.py")
    with tempfile.TemporaryDirectory(prefix="aegis_sbx_") as td:
        sample = os.path.join(td, "sample.py")
        with open(sample, "wb") as fh:
            fh.write(data)
        env = dict(os.environ)
        env["AEGIS_SANDBOX_TMP"] = td
        # Frozen (.exe) has no separate `python` or runner .py on disk, so
        # re-invoke the frozen app itself as the sandbox child (aegis_app.py
        # routes AEGIS_SANDBOX_CHILD to sandbox_runner). Otherwise spawn python.
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, sample]
            env["AEGIS_SANDBOX_CHILD"] = "1"
        else:
            cmd = [sys.executable, "-I", runner, sample]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, env=env,
            )
            out = proc.stdout.strip().splitlines()
            result = json.loads(out[-1]) if out else {}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            verdict.reasons.insert(0, f"dynamic analysis inconclusive ({type(e).__name__})")
            if verdict.decision == "ESCALATE":
                verdict.decision = "REVIEW"
            return verdict

    if result.get("escaped"):
        kinds = sorted({v["kind"] for v in result.get("violations", [])})
        verdict.decision = "BLOCK"
        verdict.posterior = max(verdict.posterior, 0.95)
        verdict.reasons.insert(0, "dynamic: behavior-envelope escape at runtime -> "
                                  + ", ".join(kinds))
        for v in result.get("violations", [])[:4]:
            verdict.reasons.append(f"  blocked {v['kind']}: {v['event']}")
    else:
        verdict.decision = "ALLOW"
        verdict.reasons.insert(0, "dynamic: ran cleanly inside the behavior envelope (no OS-facing escape)")
    return verdict
