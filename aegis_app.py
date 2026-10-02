"""Frozen-app entry point for AEGIS (the PyInstaller target).

A single entry point that does the right thing whether it is run as the desktop
app or re-invoked by the Stage-3 dynamic sandbox as a child process:

  * If AEGIS_SANDBOX_CHILD is set, run the sandbox runner on the sample path
    (so contained dynamic analysis works inside the frozen .exe, where there is
    no separate `python` to spawn).
  * If CLI arguments are given, dispatch to the normal CLI.
  * Otherwise, launch the desktop Security Center GUI.
"""

import os
import sys


def main() -> int:
    # Child process for the dynamic sandbox (set by aegis/dynamic.py when frozen).
    # sandbox_runner.main() reads the sample path from sys.argv[1] itself.
    if os.environ.get("AEGIS_SANDBOX_CHILD"):
        from aegis import sandbox_runner
        return sandbox_runner.main() or 0

    # Explicit CLI use (AEGIS.exe scan ..., selftest, etc.)
    if len(sys.argv) > 1:
        from aegis.cli import main as cli_main
        return cli_main(sys.argv[1:])

    # Bare launch -> GUI
    from aegis.gui import launch
    return launch()


if __name__ == "__main__":
    sys.exit(main())
