"""Stratum job parsing and block header assembly."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .util import NONCE_SPACE, sha256d, word_swap

__all__ = ["Job", "Work", "parse_notify"]


@dataclass(frozen=True)
class Job:
    """A fully decoded ``mining.notify`` job.

    All byte strings are already in *wire order*, ready to be hashed.  Counters
    keep their integer value so they can be re-serialised for ``mining.submit``.
    """

    job_id: str
    prevhash: bytes          # 32 bytes, header ready (word swap applied)
    coinb1: bytes
    coinb2: bytes
    branches: tuple          # tuple[bytes, ...] merkle path, natural order
    version: int             # block version as an integer (0x20000000 ...)
    nbits: int               # compact target
    ntime: int               # unix timestamp
    clean: bool
    extranonce1: bytes
    extranonce2_size: int

    def __post_init__(self) -> None:
        if len(self.prevhash) != 32:
            raise ValueError("prevhash must be 32 bytes")
        if self.extranonce2_size < 0 or self.extranonce2_size > 32:
            raise ValueError("unsupported extranonce2 size %d" % self.extranonce2_size)

    # -- coinbase / merkle ------------------------------------------------
    def coinbase(self, extranonce2: bytes) -> bytes:
        """Assemble the generation transaction for one extranonce2 value."""
        if len(extranonce2) != self.extranonce2_size:
            raise ValueError(
                "extranonce2 must be %d bytes, got %d"
                % (self.extranonce2_size, len(extranonce2))
            )
        return self.coinb1 + self.extranonce1 + extranonce2 + self.coinb2

    def merkle_root(self, coinbase: bytes) -> bytes:
        """Fold the coinbase through the pool's merkle branch list."""
        root = sha256d(coinbase)
        for branch in self.branches:
            root = sha256d(root + branch)
        return root

    # -- block header -----------------------------------------------------
    def header_prefix(self, extranonce2: bytes) -> bytes:
        """First 76 bytes of the header; the 4 nonce bytes come from workers."""
        header = (
            struct.pack("<I", self.version)
            + self.prevhash
            + self.merkle_root(self.coinbase(extranonce2))
            + struct.pack("<I", self.ntime)
            + struct.pack("<I", self.nbits)
        )
        assert len(header) == 76
        return header

    @property
    def ntime_hex(self) -> str:
        """The ntime exactly as the pool writes it (big endian hex)."""
        return "%08x" % self.ntime


@dataclass(frozen=True)
class Work:
    """A picklable unit of work handed to the worker processes."""

    job_id: str
    prefix: bytes          # 76 header bytes
    target: bytes          # 32 byte target in display order
    target_int: int
    ntime_hex: str
    extranonce2_hex: str
    generation: int


def _hex(value, size, name):
    if not isinstance(value, str):
        raise ValueError("%s must be a hex string, got %r" % (name, type(value).__name__))
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("%s is not valid hex: %s" % (name, exc)) from exc
    if size is not None and len(raw) != size:
        raise ValueError("%s must be %d bytes, got %d" % (name, size, len(raw)))
    return raw


def _int(value, name):
    if isinstance(value, bool):
        raise ValueError("%s must be an integer/hex string" % name)
    if isinstance(value, int):
        if value < 0:
            raise ValueError("%s must not be negative" % name)
        return value
    try:
        return int(value, 16)
    except (TypeError, ValueError) as exc:
        raise ValueError("%s is not a valid hex integer: %r" % (name, value)) from exc


def parse_notify(params, extranonce1: bytes, extranonce2_size: int) -> Job:
    """Decode the parameter list of a ``mining.notify`` notification.

    Order is defined by the stratum protocol::

        [job_id, prevhash, coinb1, coinb2, merkle_branches,
         version, nbits, ntime, clean_jobs]
    """
    if not isinstance(params, (list, tuple)) or len(params) < 8:
        raise ValueError("mining.notify needs at least 8 parameters")
    job_id = params[0]
    if not isinstance(job_id, str):
        raise ValueError("job id must be a string")

    branches = params[4] or []
    if not isinstance(branches, (list, tuple)):
        raise ValueError("merkle branches must be a list")

    return Job(
        job_id=job_id,
        prevhash=word_swap(_hex(params[1], 32, "prevhash")),
        coinb1=_hex(params[2], None, "coinb1"),
        coinb2=_hex(params[3], None, "coinb2"),
        branches=tuple(_hex(branch, 32, "merkle branch") for branch in branches),
        version=_int(params[5], "version"),
        nbits=_int(params[6], "nbits"),
        ntime=_int(params[7], "ntime"),
        clean=bool(params[8]) if len(params) > 8 else True,
        extranonce1=bytes(extranonce1),
        extranonce2_size=int(extranonce2_size),
    )


def nonce_hex(nonce: int) -> str:
    """Format a nonce the way ``mining.submit`` expects it."""
    if not 0 <= nonce < NONCE_SPACE:
        raise ValueError("nonce out of range")
    return "%08x" % nonce
