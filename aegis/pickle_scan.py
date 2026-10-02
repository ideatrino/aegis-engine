"""A static scanner for malicious Python pickles -- the ML supply-chain RCE.

`torch.load`, `joblib.load`, `pickle.load` all run a *stack VM* while
deserializing: the opcodes `GLOBAL 'os' 'system'` then `REDUCE` execute a shell
command the instant the object is loaded. A trojanized model checkpoint trains
fine, eyeballs clean, and owns the machine that opens it.

This scanner decodes opcodes with the stdlib `pickletools.genops` and NEVER
executes them. It is denylist precision, not allowlist paranoia: an ordinary
model pickle importing torch/numpy/collections stays silent; only a reference to
the code-execution surface fires, more strongly when a REDUCE/NEWOBJ/BUILD
actually *calls* it (a working gadget, not a mere import).
"""

from __future__ import annotations

import io
import pickletools
from dataclasses import dataclass, field
from typing import List

# Modules/callables that have no business inside a serialized data object.
DANGEROUS = {
    "os", "subprocess", "sys", "socket", "shutil", "ctypes", "runpy",
    "posix", "nt", "builtins", "__builtin__", "importlib", "pty", "commands",
    "platform", "pickle", "code", "webbrowser", "timeit",
}
DANGEROUS_CALLABLES = {
    "system", "popen", "exec", "eval", "call", "run", "Popen", "check_output",
    "spawn", "spawnl", "spawnv", "fork", "remove", "unlink", "rmtree",
    "getattr", "__import__", "compile", "load", "loads", "check_call",
}


@dataclass
class PickleReport:
    is_pickle: bool = False
    dangerous_globals: List[str] = field(default_factory=list)
    calls_dangerous: bool = False       # a REDUCE/NEWOBJ/BUILD near a bad global
    reasons: List[str] = field(default_factory=list)

    @property
    def malicious(self) -> bool:
        return bool(self.dangerous_globals)


def looks_like_pickle(data: bytes) -> bool:
    if not data:
        return False
    # PROTO opcode, or a classic protocol-0/1 opener.
    return data[0] == 0x80 or data[:1] in (b"(", b"c", b"]", b"}") or data[:2] == b"\x80\x04"


def scan(data: bytes) -> PickleReport:
    rep = PickleReport()
    if not looks_like_pickle(data):
        return rep
    rep.is_pickle = True
    seen_bad = False
    recent_strings = []          # module/name for STACK_GLOBAL arrive separately
    _STR_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
                "SHORT_BINSTRING", "BINSTRING", "STRING"}
    try:
        for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
            name = opcode.name
            if name in _STR_OPS and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 4:
                    recent_strings.pop(0)
                continue
            mod = func = ""
            if name == "GLOBAL" and arg is not None:
                # proto < 4: arg is "module\nname"
                parts = arg.replace("\n", " ").split()
                mod = parts[0] if parts else ""
                func = parts[1] if len(parts) > 1 else ""
            elif name == "STACK_GLOBAL":
                # proto >= 4: the two most recent pushed strings are module, name
                if len(recent_strings) >= 2:
                    mod, func = recent_strings[-2], recent_strings[-1]
            if mod or func:
                top = mod.split(".")[0]
                if top in DANGEROUS or func in DANGEROUS_CALLABLES:
                    entry = f"{mod}.{func}".strip(".")
                    rep.dangerous_globals.append(entry)
                    rep.reasons.append(f"pickle imports code-exec surface: {entry}")
                    seen_bad = True
            elif name in ("REDUCE", "NEWOBJ", "BUILD", "INST", "OBJ") and seen_bad:
                rep.calls_dangerous = True
    except Exception as e:
        # A pickle we cannot fully decode is itself suspicious, but we do not
        # fabricate a verdict -- report what we saw.
        if rep.dangerous_globals:
            rep.reasons.append(f"pickle decode aborted after dangerous import ({e})")
    if rep.calls_dangerous:
        rep.reasons.append("dangerous global is actually invoked (REDUCE/BUILD) -> working gadget")
    return rep
