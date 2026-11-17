#!/usr/bin/env python3
"""Prints the same vectors as cpp/tools/check.cpp using the Python miner."""

import sys

from btcminer import util
from btcminer.job import parse_notify

PARAMS = [
    "6ae40f5a0000d3a1",
    "a461c910f70acbd25a6d639f971fcc7682486e5400004d9a0000000000000000",
    "0100000001000000000000000000000000000000000000000000000000000000"
    "0000000000ffffffff360355e50e0004d5c2fb6a032c2e590c",
    "0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe031dea41"
    "12000000001976a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888acd1625f0000"
    "00000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24"
    "aa21a9ed67d7289be2e77bf3b6ca77f25f935192ce1b5c38eaacd309adbcc8b457c52e4454"
    "e50e00",
    [
        "27c65dfc7456846c34a94841441975c5920c51690efedeab9f4e90c2aec77def",
        "142c6597b19d5a91e31d656e7b55e1ab45fe6d21b56366eac76f2b5a4d2f1ed7",
        "efe428e3daad508f5dfcb271a67dc5f2b07c031a63c9f008b8ceda722950923c",
        "0fed01d3cec710d96ffda5f4296904ec71f52e13324ebf165fef83396c4602c8",
        "c942275e942d05577c938de14387b03d9d84cb30353ae71b4d410232449180c3",
        "191c8085cd5128b1f4f9a5c7675d7c9111afe28290478d4de5203ed4b304061c",
    ],
    "20000000",
    "17021673",
    "6afbc2d5",
    True,
]


def main():
    for difficulty in (1, 1e-5, 10000, 0.5):
        target = util.difficulty_to_target(difficulty)
        print("target %g = %064x" % (difficulty, target))

    job = parse_notify(PARAMS, bytes.fromhex("bd4c926e"), 8)
    print("prevhash =", job.prevhash.hex())
    header = job.header_prefix(bytes.fromhex("0011223344556677"))
    print("header   =", header.hex())
    full = header + bytes.fromhex("78563412")
    digest = util.sha256d(full)[::-1].hex()
    print("hash1234 =", digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
