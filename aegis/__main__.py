"""Enable `python -m aegis ...` (equivalent to `python -m aegis.cli ...` and the
installed `aegis` command)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
