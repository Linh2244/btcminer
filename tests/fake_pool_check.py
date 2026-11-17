#!/usr/bin/env python3
"""End-to-end check: run the C++ miner against a fake Stratum pool.

The fake pool rebuilds every submitted header with its own, independent code
path (``bytes.fromhex(...)[::-1]`` instead of the miner's ``struct.pack``) so an
endianness bug cannot hide behind shared helpers.

Usage::

    python tests/fake_pool_check.py [path-to-exe]
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time

DIFFICULTY = 1e-5
EXTRANONCE1 = "f00dbabe"
EXTRANONCE2_SIZE = 4

NONCE_SPACE_TARGET = int(0xFFFF * 2**208 / DIFFICULTY)


def bits_to_target(difficulty: float) -> int:
    return int(0xFFFF * 2**208 / difficulty)


class FakePool(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]

        self.notify = [
            "cpp-job-0001",
            os.urandom(32).hex(),
            (b"\x01\x00\x00\x00" + os.urandom(48)).hex(),
            os.urandom(24).hex(),
            [os.urandom(32).hex() for _ in range(3)],
            "20000000",
            "17021673",
            "%08x" % int(time.time()),
            True,
        ]
        self.valid = 0
        self.invalid = 0
        self.errors = []
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()

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
                    if not line.strip():
                        continue
                    try:
                        self._process(conn, json.loads(line))
                    except (OSError, ValueError) as exc:
                        # The miner closing the socket at the end of the run is
                        # normal, not a protocol error.
                        if self.stop_flag.is_set() or isinstance(
                            exc, (ConnectionResetError, ConnectionAbortedError)
                        ):
                            return
                        self.errors.append(repr(exc))
                        return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _send(self, conn, payload):
        conn.sendall(json.dumps(payload).encode() + b"\n")

    def _process(self, conn, message):
        method = message.get("method")
        request_id = message.get("id")
        if method == "mining.subscribe":
            self._send(conn, {
                "id": request_id,
                "error": None,
                "result": [
                    [["mining.notify", "sub-1"], ["mining.set_difficulty", "sub-2"]],
                    EXTRANONCE1,
                    EXTRANONCE2_SIZE,
                ],
            })
        elif method == "mining.extranonce.subscribe":
            self._send(conn, {"id": request_id, "error": None, "result": True})
        elif method == "mining.authorize":
            self._send(conn, {"id": request_id, "error": None, "result": True})
            self._send(conn, {
                "id": None, "method": "mining.set_difficulty",
                "params": [DIFFICULTY],
            })
            self._send(conn, {
                "id": None, "method": "mining.notify", "params": self.notify,
            })
        elif method == "mining.submit":
            ok, detail = self._verify(message.get("params") or [])
            with self.lock:
                if ok:
                    self.valid += 1
                else:
                    self.invalid += 1
                    self.errors.append(detail)
            self._send(conn, {
                "id": request_id,
                "result": ok,
                "error": None if ok else ["invalid share", detail, None],
            })
        else:
            self._send(conn, {"id": request_id, "error": None, "result": None})

    def _verify(self, params):
        try:
            _user, job_id, en2_hex, ntime_hex, nonce_hex = params[:5]
            if job_id != self.notify[0]:
                return False, "wrong job id %r" % (job_id,)
            if ntime_hex != self.notify[7]:
                return False, "ntime %r != %r" % (ntime_hex, self.notify[7])

            coinbase = (
                bytes.fromhex(self.notify[2])
                + bytes.fromhex(EXTRANONCE1)
                + bytes.fromhex(en2_hex)
                + bytes.fromhex(self.notify[3])
            )
            root = hashlib.sha256(hashlib.sha256(coinbase).digest()).digest()
            for branch in self.notify[4]:
                root = hashlib.sha256(
                    hashlib.sha256(root + bytes.fromhex(branch)).digest()
                ).digest()

            prevhash = b"".join(
                bytes.fromhex(self.notify[1])[i:i + 4][::-1]
                for i in range(0, 32, 4)
            )
            header = (
                bytes.fromhex(self.notify[5])[::-1]
                + prevhash
                + root
                + bytes.fromhex(self.notify[7])[::-1]
                + bytes.fromhex(self.notify[6])[::-1]
                + struct.pack("<I", int(nonce_hex, 16))
            )
            digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]
            value = int(digest.hex(), 16)
            target = bits_to_target(DIFFICULTY)
            if value > target:
                return False, "hash %s above target; header %s" % (
                    digest.hex(), header.hex())
            return True, digest.hex()
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            return False, "exception: %r" % (exc,)


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else os.path.join("dist", "btcminer.exe")
    exe = os.path.abspath(exe)
    if not os.path.isfile(exe):
        print("FAIL: executable not found:", exe)
        return 2

    pool = FakePool()
    pool.start()
    url = "stratum+tcp://127.0.0.1:%d" % pool.port
    print("fake pool on", url)

    proc = subprocess.run(
        [
            exe, "-o", url, "-u", "test.worker", "-p", "x", "-t", "2",
            "--duration", "12", "--stats-interval", "5", "--log-level", "INFO",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    pool.stop_flag.set()
    try:
        pool.server.close()
    except OSError:
        pass

    output = proc.stdout + proc.stderr
    accepted = output.count("share accepted")
    print("--- miner output ---")
    print(output.strip())
    print("--- fake pool ---")
    print("valid shares:", pool.valid, "invalid:", pool.invalid)
    for error in pool.errors[:5]:
        print("  ", error)

    ok = (
        proc.returncode == 0
        and pool.valid >= 1
        and pool.invalid == 0
        and accepted >= 1
    )
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())



