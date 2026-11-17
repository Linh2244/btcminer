"""Low level helpers: hashing, endianness and difficulty math.

Bitcoin has three different "byte orders" in play and stratum only makes this
worse, so the conversions live in one place:

* **wire order** - bytes exactly as they appear inside the 80 byte block
  header (32-bit integers are little endian).
* **display order** - the same value read as a big endian number, which is how
  hashes and targets are normally printed.
* **stratum prevhash order** - the previous block hash with the bytes of every
  32-bit word reversed.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal
from fractions import Fraction

#: Target of difficulty 1, shared by all Bitcoin pools.
DIFF1_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
MAX_TARGET = (1 << 256) - 1
NONCE_SPACE = 1 << 32


def sha256d(data: bytes) -> bytes:
    """Bitcoin's double SHA-256, returned in wire order."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def word_swap(data: bytes) -> bytes:
    """Reverse the bytes inside every 4-byte word.

    ``mining.notify`` sends the previous block hash in internal (little endian)
    order with every 32-bit word byte reversed.  Applying this function once
    turns it into the 32 bytes that belong in the block header, and applying it
    again returns the original string.
    """
    if len(data) % 4:
        raise ValueError("length must be a multiple of 4 bytes")
    out = bytearray(len(data))
    for i in range(0, len(data), 4):
        out[i:i + 4] = data[i:i + 4][::-1]
    return bytes(out)


def difficulty_to_target(difficulty) -> int:
    """Convert a stratum share difficulty into a 256 bit target.

    ``difficulty`` may be an ``int``, ``float`` or a numeric string.  Floats are
    converted through their decimal representation so that values such as
    ``0.001`` do not lose precision.
    """
    if difficulty is None:
        raise ValueError("difficulty cannot be None")
    if isinstance(difficulty, bool):
        raise ValueError("difficulty cannot be a bool")
    try:
        if isinstance(difficulty, int):
            value = Fraction(difficulty, 1)
        else:
            value = Fraction(Decimal(str(difficulty)))
    except (ArithmeticError, ValueError) as exc:  # InvalidOperation is a ValueError
        raise ValueError("invalid difficulty %r: %s" % (difficulty, exc)) from exc
    if value <= 0:
        raise ValueError("difficulty must be positive, got %r" % (difficulty,))
    target = int(Fraction(DIFF1_TARGET, 1) / value)
    if target < 1:
        return 1
    if target > MAX_TARGET:
        return MAX_TARGET
    return target


def target_to_difficulty(target: int) -> float:
    """Inverse of :func:`difficulty_to_target` (used for "best share" stats)."""
    if target <= 0:
        return float("inf")
    return float(Fraction(DIFF1_TARGET, 1) / Fraction(int(target), 1))


def format_hashrate(hashes_per_second: float) -> str:
    """Human readable hashrate, e.g. ``1.42 MH/s``."""
    units = (
        ("EH/s", 1e18),
        ("PH/s", 1e15),
        ("TH/s", 1e12),
        ("GH/s", 1e9),
        ("MH/s", 1e6),
        ("kH/s", 1e3),
    )
    for name, scale in units:
        if hashes_per_second >= scale:
            return "%.2f %s" % (hashes_per_second / scale, name)
    return "%.1f H/s" % hashes_per_second


def format_difficulty(difficulty: float) -> str:
    """Compact difficulty formatting for log lines."""
    if difficulty == float("inf"):
        return "inf"
    if difficulty >= 1e6 or difficulty < 1e-3:
        return "%.2e" % difficulty
    text = "%.4f" % difficulty
    return text.rstrip("0").rstrip(".") or "0"
