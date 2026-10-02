"""The sandbox child process. Run as:  python3 -I sandbox_runner.py <sample.py>

It installs a CPython audit hook that RECORDS and BLOCKS OS-facing actions
(network, process/shell, native code, destructive filesystem), applies CPU /
address-space / file-size limits, then executes the sample. The audit hook
raises on a forbidden action, so even a real payload is stopped at the boundary
*before* it acts. It prints a JSON trace to stdout and never writes elsewhere.

Division of labour (design 8/12): the sandbox judges OS-facing BEHAVIOUR; it
does not try to judge code *shape* (that is D3's AST/analytic job). The
interpreter legitimately compiles and imports, so those are not escapes.
"""

import io
import json
import os
import sys

TRACE = []
VIOLATIONS = []

# audit events that constitute leaving the behavior envelope
_NET = ("socket.connect", "socket.bind", "socket.getaddrinfo", "socket.__new__")
_PROC = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
         "os.fork", "os.spawn", "os.startfile")
_NATIVE = ("ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function", "ctypes.cdata")
_FS_DESTRUCTIVE = ("os.remove", "os.unlink", "os.rename", "os.replace",
                   "os.rmdir", "shutil.rmtree", "os.chmod", "os.chown")

_SANDBOX_TMP = os.environ.get("AEGIS_SANDBOX_TMP", "")


def _hook(event, args):
    if event in _NET:
        _violate("network", event, args)
    elif event in _PROC:
        _violate("process/shell", event, args)
    elif event in _NATIVE:
        _violate("native-code", event, args)
    elif event in _FS_DESTRUCTIVE:
        _violate("destructive-fs", event, args)
    elif event == "open":
        try:
            path, mode, _flags = args
        except Exception:
            return
        mode = mode or ""
        if any(c in mode for c in "waxc+") or ("b" in str(mode) and "r" not in str(mode)):
            p = os.path.abspath(str(path)) if path else ""
            if _SANDBOX_TMP and p.startswith(_SANDBOX_TMP):
                return  # writing inside its own sandbox tmp is allowed
            _violate("file-write", event, (str(path), str(mode)))


def _violate(kind, event, args):
    rec = {"kind": kind, "event": event, "args": _safe(args)}
    VIOLATIONS.append(rec)
    TRACE.append(rec)
    raise PermissionError(f"AEGIS sandbox blocked {kind} ({event})")


def _safe(args):
    try:
        return [str(a)[:120] for a in (args or ())]
    except Exception:
        return []


def _limits():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024,) * 2)
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "no sample"}))
        return
    sample = sys.argv[1]
    _limits()
    try:
        with open(sample, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as e:
        print(json.dumps({"error": f"unreadable: {e}"}))
        return

    # timeout backstop
    try:
        import signal
        signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(3)
    except Exception:
        pass

    sys.addaudithook(_hook)
    escaped = False
    err = None
    # silence the sample's own stdout so it can't corrupt our JSON
    real_out = sys.stdout
    sys.stdout = io.StringIO()
    try:
        code = compile(src, "<sample>", "exec")
        exec(code, {"__name__": "__main__"})
    except PermissionError:
        escaped = True
    except Exception as e:
        err = type(e).__name__
    finally:
        sys.stdout = real_out

    print(json.dumps({
        "escaped": bool(VIOLATIONS),
        "violations": VIOLATIONS[:20],
        "sample_error": err,
    }))


if __name__ == "__main__":
    main()
