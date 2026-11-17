"""Test suite for the CPU BTC miner.

Run from the project root with::

    python -m unittest discover -v
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import struct
import threading
import time
import unittest

from btcminer import util
from btcminer.cli import REFERENCE_HASH, REFERENCE_HEADER, _setup_logging
from btcminer.job import Work, nonce_hex, parse_notify
from btcminer.miner import Miner, MinerConfig
from btcminer.stratum import StratumClient
from btcminer.worker import WorkerPool

# ---------------------------------------------------------------------------
# A real mining.notify captured from solo.ckpool.org (job of height 976725).
# It is used as an external test vector for the stratum byte order rules.
# ---------------------------------------------------------------------------
CKPOOL_JOB = [
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
CKPOOL_EXTRANONCE1 = bytes.fromhex("bd4c926e")
CKPOOL_EXTRANONCE2_SIZE = 8
#: Block the captured job was built on top of (verified on the public chain).
CKPOOL_PARENT_HASH = (
    "000000000000000000004d9a82486e54971fcc765a6d639ff70acbd2a461c910"
)


# ---------------------------------------------------------------------------
# hashing / target math
# ---------------------------------------------------------------------------
class UtilTests(unittest.TestCase):
    def test_reference_block_header(self):
        self.assertEqual(
            util.sha256d(REFERENCE_HEADER)[::-1].hex(), REFERENCE_HASH
        )

    def test_word_swap(self):
        data = bytes(range(32))
        self.assertEqual(util.word_swap(util.word_swap(data)), data)
        self.assertEqual(util.word_swap(b"\x00\x01\x02\x03"), b"\x03\x02\x01\x00")
        with self.assertRaises(ValueError):
            util.word_swap(b"\x00")

    def test_difficulty_to_target(self):
        self.assertEqual(util.difficulty_to_target(1), util.DIFF1_TARGET)
        self.assertEqual(util.difficulty_to_target(2), util.DIFF1_TARGET // 2)
        self.assertEqual(util.difficulty_to_target("0.5"), util.DIFF1_TARGET * 2)
        self.assertEqual(util.difficulty_to_target(1e-12), util.MAX_TARGET)
        self.assertEqual(util.difficulty_to_target(10 ** 80), 1)
        for bad in (0, -1, None, "abc"):
            with self.assertRaises(ValueError):
                util.difficulty_to_target(bad)

    def test_target_to_difficulty(self):
        for difficulty in (1, 2, 0.001, 10000, 1e-5):
            target = util.difficulty_to_target(difficulty)
            self.assertAlmostEqual(
                util.target_to_difficulty(target) / difficulty, 1.0, places=6
            )

    def test_formatting(self):
        self.assertEqual(util.format_hashrate(1500), "1.50 kH/s")
        self.assertEqual(util.format_hashrate(2.5e6), "2.50 MH/s")
        self.assertEqual(util.format_hashrate(5), "5.0 H/s")
        self.assertEqual(util.format_difficulty(10000), "10000")
        self.assertEqual(util.format_difficulty(1e-9), "1.00e-09")


# ---------------------------------------------------------------------------
# job parsing / header assembly
# ---------------------------------------------------------------------------
class JobTests(unittest.TestCase):
    def setUp(self):
        self.job = parse_notify(CKPOOL_JOB, CKPOOL_EXTRANONCE1, CKPOOL_EXTRANONCE2_SIZE)

    def test_notify_fields(self):
        job = self.job
        self.assertEqual(job.job_id, "6ae40f5a0000d3a1")
        self.assertEqual(job.version, 0x20000000)
        self.assertEqual(job.nbits, 0x17021673)
        self.assertEqual(job.ntime, 0x6AFBC2D5)
        self.assertEqual(job.ntime_hex, "6afbc2d5")
        self.assertTrue(job.clean)
        self.assertEqual(len(job.branches), 6)
        self.assertEqual(job.extranonce1, CKPOOL_EXTRANONCE1)

    def test_prevhash_matches_the_chain(self):
        expected = bytes.fromhex(CKPOOL_PARENT_HASH)[::-1]
        self.assertEqual(self.job.prevhash, expected)

    def test_header_layout(self):
        extranonce2 = bytes.fromhex("0011223344556677")
        header = self.job.header_prefix(extranonce2)
        self.assertEqual(len(header), 76)
        self.assertEqual(header[0:4], b"\x00\x00\x00\x20")
        self.assertEqual(header[4:36], self.job.prevhash)
        self.assertEqual(header[36:68], self.job.merkle_root(
            self.job.coinbase(extranonce2)))
        self.assertEqual(header[68:72], struct.pack("<I", 0x6AFBC2D5))
        self.assertEqual(header[72:76], struct.pack("<I", 0x17021673))

    def test_coinbase_contains_extranonces(self):
        extranonce2 = bytes.fromhex("aabbccddeeff0011")
        coinbase = self.job.coinbase(extranonce2)
        self.assertEqual(
            coinbase,
            self.job.coinb1 + CKPOOL_EXTRANONCE1 + extranonce2 + self.job.coinb2,
        )
        with self.assertRaises(ValueError):
            self.job.coinbase(b"\x00")

    def test_merkle_root_matches_naive_fold(self):
        coinbase = self.job.coinbase(bytes(8))
        root = hashlib.sha256(hashlib.sha256(coinbase).digest()).digest()
        for branch in self.job.branches:
            root = hashlib.sha256(hashlib.sha256(root + branch).digest()).digest()
        self.assertEqual(self.job.merkle_root(coinbase), root)

    def test_malformed_notify(self):
        with self.assertRaises(ValueError):
            parse_notify(["only", "two"], b"", 4)
        with self.assertRaises(ValueError):
            parse_notify(CKPOOL_JOB[:7], b"", 4)
        with self.assertRaises(ValueError):
            parse_notify(CKPOOL_JOB[:1] + ["zz"] + CKPOOL_JOB[2:], b"", 4)

    def test_nonce_hex(self):
        self.assertEqual(nonce_hex(0x12345678), "12345678")
        self.assertEqual(nonce_hex(0), "00000000")
        with self.assertRaises(ValueError):
            nonce_hex(1 << 32)


# ---------------------------------------------------------------------------
# worker processes
# ---------------------------------------------------------------------------
class WorkerTests(unittest.TestCase):
    def test_worker_finds_and_hashes_valid_shares(self):
        log = logging.getLogger("btcminer.tests")
        prefix = os.urandom(76)
        target_int = util.difficulty_to_target(1e-5)
        work = Work(
            job_id="job-1",
            prefix=prefix,
            target=target_int.to_bytes(32, "big"),
            target_int=target_int,
            ntime_hex="5f2a1b2c",
            extranonce2_hex="00112233",
            generation=7,
        )
        pool = WorkerPool(1, log, seed=1234)
        shares = []
        pool.start()
        try:
            pool.broadcast(work)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and len(shares) < 5:
                time.sleep(0.1)
                shares.extend(item for item in pool.drain() if item[0] == "share")
        finally:
            pool.stop()

        self.assertTrue(shares, "no share found within 30 s")
        for item in shares:
            _, worker, nonce, hash_hex, received = item
            digest = util.sha256d(prefix + struct.pack("<I", nonce))[::-1]
            self.assertEqual(digest.hex(), hash_hex)
            self.assertLessEqual(int(hash_hex, 16), target_int)
            self.assertLess(nonce, 1 << 32)
            self.assertEqual(received.job_id, "job-1")
            self.assertEqual(received.extranonce2_hex, "00112233")
            self.assertEqual(received.generation, 7)


# ---------------------------------------------------------------------------
# stratum client
# ---------------------------------------------------------------------------
class StratumClientTests(unittest.TestCase):
    def test_request_keeps_pipelined_messages(self):
        """A response and notifications in one TCP read must all be kept."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            payload = (
                b'{"id":1,"result":true,"error":null}\n'
                b'{"id":null,"method":"mining.set_difficulty","params":[8]}\n'
                b'{"id":null,"method":"mining.notify","params":["j"]}\n'
            )
            conn.sendall(payload)
            time.sleep(0.5)
            conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = StratumClient("127.0.0.1", port, logging.getLogger("btcminer.tests"))
        try:
            client.connect()
            self.assertIs(client.request("mining.authorize", ["u", "p"]), True)
            backlog = client.take_backlog()
            self.assertEqual(
                [message.get("method") for message in backlog],
                ["mining.set_difficulty", "mining.notify"],
            )
        finally:
            client.close()
            server.close()


# ---------------------------------------------------------------------------
# end to end: miner <-> fake stratum pool
# ---------------------------------------------------------------------------
class FakePool(threading.Thread):
    """Minimal stratum server that validates the share it receives.

    The validation code deliberately rebuilds the header with an independent
    formulation (``bytes.fromhex(ntime)[::-1]`` instead of ``struct.pack``) so
    an endianness mistake in the miner cannot hide behind shared helpers.
    """

    def __init__(self):
        super().__init__(daemon=True)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]

        self.difficulty = 1e-5
        self.extranonce1 = "f00dbabe"
        self.extranonce2_size = 4
        self.notify = [
            "fake-job-0001",
            os.urandom(32).hex(),
            (b"\x01\x00\x00\x00" + os.urandom(48)).hex(),
            os.urandom(24).hex(),
            [os.urandom(32).hex() for _ in range(3)],
            "20000000",
            "17021673",
            "%08x" % int(time.time()),
            True,
        ]
        self.share_params = None
        self.share_valid = None
        self.share_hash = None
        self.error = None
        self.stop_flag = threading.Event()

    # -- server loop ------------------------------------------------------
    def run(self):
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        conn.settimeout(60)
        buffer = b""
        try:
            while not self.stop_flag.is_set():
                try:
                    chunk = conn.recv(65536)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.strip():
                        try:
                            self._on_message(conn, json.loads(line))
                        except (OSError, ValueError):
                            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _send(self, conn, payload):
        conn.sendall(json.dumps(payload).encode() + b"\n")

    def _on_message(self, conn, message):
        method = message.get("method")
        request_id = message.get("id")
        if method == "mining.subscribe":
            self._send(conn, {
                "id": request_id,
                "error": None,
                "result": [
                    [["mining.notify", "sub-1"], ["mining.set_difficulty", "sub-2"]],
                    self.extranonce1,
                    self.extranonce2_size,
                ],
            })
        elif method == "mining.authorize":
            self._send(conn, {"id": request_id, "error": None, "result": True})
            self._send(conn, {
                "id": None, "method": "mining.set_difficulty",
                "params": [self.difficulty],
            })
            self._send(conn, {
                "id": None, "method": "mining.notify", "params": self.notify,
            })
        elif method == "mining.submit":
            self.share_params = list(message.get("params") or [])
            try:
                self.share_valid, self.share_hash = self._verify(self.share_params)
            except Exception as exc:                     # noqa: BLE001 - reported below
                self.error = exc
                self.share_valid = False
            self._send(conn, {
                "id": request_id,
                "result": self.share_valid,
                "error": None if self.share_valid else ["invalid share"],
            })
        else:
            self._send(conn, {"id": request_id, "error": None, "result": None})

    # -- independent share verification -----------------------------------
    def _verify(self, params):
        user, job_id, extranonce2_hex, ntime_hex, nonce_hex_str = params[:5]
        if job_id != self.notify[0]:
            raise ValueError("wrong job id %r" % (job_id,))
        if ntime_hex != self.notify[7]:
            raise ValueError("ntime %r must equal the job ntime %r"
                             % (ntime_hex, self.notify[7]))

        coinbase = (
            bytes.fromhex(self.notify[2])
            + bytes.fromhex(self.extranonce1)
            + bytes.fromhex(extranonce2_hex)
            + bytes.fromhex(self.notify[3])
        )
        root = hashlib.sha256(hashlib.sha256(coinbase).digest()).digest()
        for branch in self.notify[4]:
            root = hashlib.sha256(
                hashlib.sha256(root + bytes.fromhex(branch)).digest()
            ).digest()

        prevhash = b"".join(
            bytes.fromhex(self.notify[1])[i:i + 4][::-1] for i in range(0, 32, 4)
        )
        header = (
            bytes.fromhex(self.notify[5])[::-1]
            + prevhash
            + root
            + bytes.fromhex(self.notify[7])[::-1]
            + bytes.fromhex(self.notify[6])[::-1]
            + struct.pack("<I", int(nonce_hex_str, 16))
        )
        digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]
        target = util.difficulty_to_target(self.difficulty)
        return int(digest.hex(), 16) <= target, digest.hex()


class EndToEndTests(unittest.TestCase):
    def test_miner_against_fake_pool(self):
        log = _setup_logging("INFO")
        fake_pool = FakePool()
        fake_pool.start()
        config = MinerConfig(
            url="stratum+tcp://127.0.0.1:%d" % fake_pool.port,
            user="test.worker",
            password="x",
            processes=1,
            stats_interval=5.0,
            duration=60.0,
        )
        miner = Miner(config, log)
        runner = threading.Thread(target=miner.run, daemon=True)
        runner.start()
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline and fake_pool.share_valid is None:
                time.sleep(0.1)
        finally:
            miner.request_stop()
            runner.join(timeout=20)
            fake_pool.stop_flag.set()
            try:
                fake_pool.server.close()
            except OSError:
                pass

        self.assertIsNone(fake_pool.error, "verification crashed: %r" % (fake_pool.error,))
        self.assertIsNotNone(fake_pool.share_valid, "the miner never submitted a share")
        self.assertTrue(
            fake_pool.share_valid,
            "the fake pool rejected the share: params=%r hash=%r"
            % (fake_pool.share_params, fake_pool.share_hash),
        )
        self.assertGreaterEqual(miner.accepted, 1)
        self.assertEqual(miner.rejected, 0)
        self.assertFalse(runner.is_alive(), "miner did not shut down")


if __name__ == "__main__":       # pragma: no cover
    unittest.main(verbosity=2)
