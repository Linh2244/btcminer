"""A small CPU Bitcoin (SHA-256d) miner that speaks Stratum v1.

The package is intentionally dependency free: everything is built on the
Python standard library (``hashlib`` for hashing, ``multiprocessing`` for
parallel workers and a plain TCP socket for the pool connection).
"""

__version__ = "1.0.0"

#: Kept under a separate name so ``from btcminer import VERSION`` reads well.
VERSION = __version__

__all__ = ["VERSION", "__version__"]
