"""Build a standalone AEGIS executable with PyInstaller.

    pip install pyinstaller
    python build_exe.py

Produces `dist/AEGIS` (or `dist/AEGIS.exe` on Windows): a single-file app that
launches the Security Center GUI when double-clicked, runs the CLI when given
arguments (`AEGIS.exe scan ...`), and serves as its own dynamic-sandbox child.
The bundled model (`aegis/data/model.json`) is collected so detection works
with no setup. PyInstaller is a build-time tool only; the shipped app stays
dependency-free at runtime.
"""

import os
import subprocess
import sys


def main() -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed.  Run:  pip install pyinstaller",
              file=sys.stderr)
        return 2

    sep = ";" if os.name == "nt" else ":"      # --add-data path separator
    args = [
        sys.executable, "-m", "PyInstaller",
        "--name", "AEGIS",
        "--onefile",
        "--noconfirm",
        "--clean",
        # ship the trained model and the rules template with the app
        "--add-data", f"aegis/data/model.json{sep}aegis/data",
        # dynamic imports PyInstaller can't see by static analysis
        "--hidden-import", "aegis.gui",
        "--hidden-import", "aegis.sandbox_runner",
        "--collect-submodules", "aegis",
    ]
    if os.path.exists("aegis.ico"):
        args += ["--icon", "aegis.ico"]
    # GUI app on Windows (no console window); console elsewhere is fine.
    if os.name == "nt":
        args += ["--windowed"]
    args.append("aegis_app.py")

    print("Running:", " ".join(args))
    return subprocess.call(args)


if __name__ == "__main__":
    sys.exit(main())
