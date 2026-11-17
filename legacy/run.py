#!/usr/bin/env python3
"""Launcher for the btcminer package: ``python run.py --help``."""

import multiprocessing
import sys

from btcminer.cli import main

if __name__ == "__main__":
    # Required on Windows when the miner is frozen into an executable and
    # harmless otherwise.
    multiprocessing.freeze_support()
    sys.exit(main())
