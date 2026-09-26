#!/usr/bin/env python3
"""Cryptex — encoder / decoder toolbox.

  python cryptex.py             run from source
  python cryptex.py selftest    run every tool, write cryptex-selftest.txt, exit
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptexlib import registry  # noqa: E402,F401  (registers every tool)

if __name__ == "__main__":
    if sys.argv[1:] and sys.argv[1].lower() in ("selftest", "--selftest", "-t"):
        # the self-test needs no window, so the UI (and Tk) is only imported
        # when the app is actually being opened - it then runs on a server or
        # a Python without tkinter too
        from cryptexlib.selftest import run
        sys.exit(run(verbose=True))
    from cryptexlib.ui import launch
    launch()
