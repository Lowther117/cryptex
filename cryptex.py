#!/usr/bin/env python3
"""Cryptex — encoder / decoder toolbox.

  python cryptex.py             run from source
  python cryptex.py selftest    run every tool, write cryptex-selftest.txt, exit
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptexlib import registry  # noqa: E402,F401  (registers every tool)
from cryptexlib.ui import launch  # noqa: E402

if __name__ == "__main__":
    if sys.argv[1:] and sys.argv[1].lower() in ("selftest", "--selftest", "-t"):
        from cryptexlib.selftest import run
        sys.exit(run(verbose=True))
    launch()
