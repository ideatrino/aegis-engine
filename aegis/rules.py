"""D8: the extensible, human-authored layer -- a YARA-lite rule engine.

A detector you cannot teach is always one step behind the last incident. Rules
let an analyst say "this exact thing is bad" and have it fused -- never
bypassing the ensemble. A rule's severity maps into the core:
  block  -> force_block (but the allowlist still wins)
  review -> review_only  (surfaced, never silently allowed)
  score  -> a plain weighted vote

The condition is a real boolean grammar compiled by a small recursive-descent
parser:  and / or / not, parentheses, occurrence counts (#a >= 2), offset
anchors ($a at 0), set counts (N of them / all of them / any of them), and file
size predicates (filesize < 2MB). A MALFORMED condition is never fatal -- it
falls back to a plain "N of them" count gate, so a typo can't crash a scan.

The built-in EICAR rule ships enabled so AEGIS answers the industry-standard
"is my scanner working?" probe out of the box -- and carries max_filesize=128 so
it detects the 68-byte EICAR *file*, not a file that merely quotes the string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .core import Evidence

_OFFSET_SCAN_CAP = 4096       # how many match offsets to remember per string


# --------------------------------------------------------------------------- #
#  Rule model                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    name: str
    strings: List[tuple]              # (id, kind, value)  kind in {text, regex, hex}
    condition_n: int = 1             # fallback "N of them"; 0 means "all"
    condition: Optional[str] = None  # a real condition expression (preferred)
    severity: str = "score"          # block | review | score
    weight: float = 1.0
    max_filesize: Optional[int] = None
    min_filesize: Optional[int] = None

    def matches(self, data: bytes) -> Optional[int]:
        """Return number of matched strings if the condition holds, else None."""
        if self.max_filesize is not None and len(data) > self.max_filesize:
            return None
        if self.min_filesize is not None and len(data) < self.min_filesize:
            return None
        ctx = _MatchContext(self.strings, data)
        if self.condition:
            try:
                ok = _eval_condition(self.condition, ctx)
            except Exception:
                ok = ctx.hit_count() >= (len(self.strings) if self.condition_n == 0
                                         else self.condition_n)
        else:
            ok = ctx.hit_count() >= (len(self.strings) if self.condition_n == 0
                                     else self.condition_n)
        return ctx.hit_count() if ok else None


# --------------------------------------------------------------------------- #
#  Matching context                                                             #
# --------------------------------------------------------------------------- #
def _compile(kind: str, value) -> "re.Pattern":
    if kind == "text":
        return re.compile(re.escape(value.encode("latin-1", "ignore")))
    if kind == "hex":
        # value already a bytes regex pattern (?? -> . at build time)
        return re.compile(value, re.DOTALL)
    # regex
    pat = value if isinstance(value, bytes) else value.encode("latin-1", "ignore")
    return re.compile(pat, re.DOTALL)


class _MatchContext:
    def __init__(self, strings, data: bytes):
        self.filesize = len(data)
        self.counts: Dict[str, int] = {}
        self.offsets: Dict[str, set] = {}
        self.n = len(strings)
        for sid, kind, value in strings:
            cnt = 0
            offs = set()
            try:
                pat = _compile(kind, value)
                for m in pat.finditer(data):
                    cnt += 1
                    if len(offs) < _OFFSET_SCAN_CAP:
                        offs.add(m.start())
                    if cnt > 100000:
                        break
            except re.error:
                pass
            self.counts[sid] = cnt
            self.offsets[sid] = offs

    def hit_count(self) -> int:
        return sum(1 for c in self.counts.values() if c > 0)


# --------------------------------------------------------------------------- #
#  Condition grammar: recursive-descent over a token stream                     #
# --------------------------------------------------------------------------- #
_SIZE = {"": 1, "KB": 1024, "MB": 1024 * 1024, "GB": 1024 * 1024 * 1024}
_TOKEN_RE = re.compile(
    r"\s*(\(|\)|\$\w+|#\w+|<=|>=|==|=|<|>|\d+(?:KB|MB|GB)?|\w+)", re.I)


def _tokenize(expr: str) -> List[str]:
    out, pos = [], 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            break
        out.append(m.group(1))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, tokens, ctx):
        self.t = tokens
        self.i = 0
        self.ctx = ctx

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        v = self.parse_or()
        if self.i < len(self.t):
            raise ValueError(f"unconsumed tokens: {self.t[self.i:]}")  # -> fallback
        return v

    def parse_or(self):
        v = self.parse_and()
        while (self.peek() or "").lower() == "or":
            self.next()
            v = self.parse_and() or v
        return v

    def parse_and(self):
        v = self.parse_not()
        while (self.peek() or "").lower() == "and":
            self.next()
            r = self.parse_not()
            v = v and r
        return v

    def parse_not(self):
        if (self.peek() or "").lower() == "not":
            self.next()
            return not self.parse_not()
        return self.parse_primary()

    def parse_primary(self):
        tok = self.peek()
        if tok == "(":
            self.next()
            v = self.parse_or()
            if self.peek() == ")":
                self.next()
            return v
        tok = self.next()
        low = tok.lower()
        # N of them / all of them / any of them
        if low in ("all", "any") or tok.isdigit():
            # expect: of them
            nxt = (self.peek() or "").lower()
            if nxt == "of":
                self.next()
                if (self.peek() or "").lower() == "them":
                    self.next()
                matched = self.ctx.hit_count()
                if low == "all":
                    return matched == self.ctx.n
                if low == "any":
                    return matched >= 1
                return matched >= int(tok)
            return bool(tok)
        # filesize predicate
        if low == "filesize":
            op = self.next()
            size = self._size(self.next())
            return self._cmp(self.ctx.filesize, op, size)
        # #id count predicate
        if tok.startswith("#"):
            sid = tok[1:]
            op = self.next()
            num = int(self.next())
            return self._cmp(self.ctx.counts.get(sid, 0), op, num)
        # $id  (optionally: at <offset>)
        if tok.startswith("$"):
            sid = tok[1:]
            if (self.peek() or "").lower() == "at":
                self.next()
                off = int(self.next())
                return off in self.ctx.offsets.get(sid, set())
            return self.ctx.counts.get(sid, 0) > 0
        raise ValueError(f"unexpected token: {tok}")   # malformed -> fallback gate

    @staticmethod
    def _size(tok: str) -> int:
        m = re.match(r"(\d+)(KB|MB|GB)?", tok, re.I)
        if not m:
            return 0
        return int(m.group(1)) * _SIZE[(m.group(2) or "").upper()]

    @staticmethod
    def _cmp(a, op, b):
        return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b,
                "==": a == b, "=": a == b}.get(op, False)


def _eval_condition(expr: str, ctx: _MatchContext) -> bool:
    toks = _tokenize(expr)
    if not toks:
        raise ValueError("empty condition")
    return _Parser(toks, ctx).parse()


# --------------------------------------------------------------------------- #
#  Rule-file parser (forgiving, line-oriented)                                  #
# --------------------------------------------------------------------------- #
def parse_rules(text: str) -> List[Rule]:
    rules: List[Rule] = []
    i = 0
    lines = text.splitlines()
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r"rule\s+(\w+)", line)
        if not m:
            i += 1
            continue
        name = m.group(1)
        strings: List[tuple] = []
        meta = {}
        condition = None
        section = None
        i += 1
        depth = line.count("{")
        while i < len(lines):
            raw = lines[i]
            s = raw.strip()
            depth += raw.count("{") - raw.count("}")
            if s.startswith("meta:"):
                section = "meta"
            elif s.startswith("strings:"):
                section = "strings"
            elif s.startswith("condition:"):
                section = "condition"
                rest = s[len("condition:"):].strip().rstrip("}").strip()
                condition = rest or None
            elif section == "meta" and "=" in s:
                k, _, v = s.partition("=")
                meta[k.strip()] = v.strip().strip('"')
            elif section == "strings" and s.startswith("$"):
                sid, _, val = s.partition("=")
                sid = sid.strip().lstrip("$")
                val = val.strip()
                if val.startswith('"') and val.endswith('"'):
                    strings.append((sid, "text", _unescape(val[1:-1])))
                elif val.startswith("/") and val.rstrip("i").endswith("/"):
                    strings.append((sid, "regex", val.strip("/").encode()))
                elif val.startswith("{") and val.endswith("}"):
                    strings.append((sid, "hex", _hex_to_pattern(val[1:-1])))
            elif section == "condition" and s and not s.startswith("}"):
                condition = ((condition + " ") if condition else "") + s.rstrip("}").strip()
            if depth <= 0 and (s.endswith("}") or s == "}"):
                break
            i += 1
        severity = meta.get("severity", "score").lower()
        if severity not in ("block", "review", "score"):
            severity = "score"
        rules.append(Rule(
            name=name, strings=strings,
            condition=condition,
            condition_n=1,
            severity=severity,
            weight=float(meta.get("weight", 1.0) or 1.0),
            max_filesize=_int_or_none(meta.get("max_filesize")),
            min_filesize=_int_or_none(meta.get("min_filesize")),
        ))
        i += 1
    return rules


def _unescape(s: str) -> str:
    """YARA-style string unescaping: \\\\ -> \\, \\" -> ", \\n/\\t/\\r."""
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append({"\\": "\\", '"': '"', "n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _hex_to_pattern(hexstr: str) -> bytes:
    out = bytearray()
    for tok in hexstr.split():
        if tok == "??":
            out += b"."
        else:
            try:
                out += re.escape(bytes([int(tok, 16)]))
            except ValueError:
                continue
    return bytes(out)


def _int_or_none(v):
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
#  Built-ins + evaluation                                                       #
# --------------------------------------------------------------------------- #
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

BUILTIN_RULES = [
    Rule(
        name="EICAR_Test_File",
        strings=[("eicar", "text", EICAR)],
        condition="$eicar at 0",       # the file STARTS with the string
        condition_n=1,
        severity="block",
        max_filesize=128,
    ),
]


def evaluate_rules(data: bytes, rules: Optional[List[Rule]] = None,
                   is_text: bool = False) -> List[Evidence]:
    rules = BUILTIN_RULES if rules is None else rules
    out: List[Evidence] = []
    for rule in rules:
        hits = rule.matches(data)
        if hits is None:
            continue
        reason = f"custom rule match: {rule.name} ({rule.severity} rule)"
        if rule.severity == "block":
            if rule.max_filesize is not None:
                out.append(Evidence(name=f"rule:{rule.name}", kind="force_block",
                                    reasons=[reason]))
            elif is_text:
                out.append(Evidence(name=f"rule:{rule.name}", p=0.9, pi_cal=0.5,
                                    weight=1.0, kind="review_only",
                                    reasons=[reason], cap_review=True))
            else:
                out.append(Evidence(name=f"rule:{rule.name}", kind="force_block",
                                    reasons=[reason]))
        elif rule.severity == "review":
            out.append(Evidence(name=f"rule:{rule.name}", p=0.85, pi_cal=0.5,
                                weight=1.0, kind="review_only",
                                reasons=[reason], cap_review=is_text))
        else:
            out.append(Evidence(name=f"rule:{rule.name}", p=0.75, pi_cal=0.5,
                                weight=rule.weight, kind="score", reasons=[reason]))
    return out


def load_rules_files(paths) -> List[Rule]:
    rules: List[Rule] = []
    import os
    for path in paths:
        try:
            if os.path.isdir(path):
                for fn in os.listdir(path):
                    if fn.endswith((".rules", ".yar", ".yara")):
                        with open(os.path.join(path, fn), encoding="utf-8") as fh:
                            rules.extend(parse_rules(fh.read()))
            else:
                with open(path, encoding="utf-8") as fh:
                    rules.extend(parse_rules(fh.read()))
        except OSError:
            continue
    return rules
