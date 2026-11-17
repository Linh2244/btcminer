#!/usr/bin/env python3
"""End-to-end check: run the C++ miner against a fake Stratum pool.

The fake pool rebuilds every submitted header with its own, independent code
path (``bytes.fromhex(...)[::-1]`` instead of the miner's ``struct.pack``) so an
endianness bug cannot hide behind shared helpers.

Usage::

    python tests/fake_pool_check.py [path-to-exe]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

DIFFICULTY = 1e-5
EXTRANONCE1 = "f00dbabe"
EXTRANONCE2_SIZE = 4
VERSION_MASK = 0x1FFFE000


def bits_to_target(difficulty: float) -> int:
    return int(0xFFFF * 2**208 / difficulty)


def stop_pool(pool: "FakePool") -> None:
    pool.stop_flag.set()
    try:
        pool.server.close()
    except OSError:
        pass


def run_miner(exe, url, seconds, extra=()):
    command = [
        exe, "-o", url, "-u", "test.worker", "-p", "x", "-t", "2",
        "--duration", str(seconds), "--stats-interval", "5",
        "--log-level", "INFO", "--no-api",
    ]
    command.extend(extra)
    return subprocess.run(
        command, capture_output=True, text=True, timeout=120,
    )


class FakePool(threading.Thread):
    def __init__(self, version_rolling: bool = False, tls_context=None):
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
        self.version_rolling = version_rolling
        self.tls_context = tls_context
        if tls_context is not None:
            tls_context.sni_callback = self._record_sni
        self.sni = None
        self.handshake_errors = []
        self.connections = 0
        self.configure_seen = False
        self.version_params = 0
        self.valid = 0
        self.invalid = 0
        self.errors = []
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()

    def _record_sni(self, _ssl_object, server_name, _context):
        self.sni = server_name
        return None

    def run(self):
        while not self.stop_flag.is_set():
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            if self.tls_context is not None:
                conn.settimeout(30)
                try:
                    conn = self.tls_context.wrap_socket(conn, server_side=True)
                except (OSError, ValueError) as exc:
                    self.handshake_errors.append(repr(exc))
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            self.connections += 1
            try:
                self._serve(conn)
            except (OSError, ValueError) as exc:
                if not self.stop_flag.is_set():
                    self.errors.append(repr(exc))

    def _serve(self, conn):
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
                    self._process(conn, json.loads(line))
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
        elif method == "mining.configure":
            self.configure_seen = True
            result = {"version-rolling": False}
            if self.version_rolling:
                result = {
                    "version-rolling": True,
                    "version-rolling.mask": "%08x" % VERSION_MASK,
                }
            self._send(conn, {
                "id": request_id, "error": None, "result": result,
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

            base_version = int(self.notify[5], 16)
            if self.version_rolling:
                if len(params) < 6:
                    return False, "mining.submit is missing the version"
                version = int(params[5], 16)
                self.version_params += 1
                if version & ~VERSION_MASK != base_version & ~VERSION_MASK:
                    return False, "version %08x does not keep the base bits" % version
                if version & VERSION_MASK:
                    return False, "unexpected rolled version bits %08x" % version
            else:
                version = base_version
                if len(params) != 5:
                    return False, "unexpected 6th submit parameter %r" % (params[5],)

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
                version.to_bytes(4, "little")
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


def make_test_certificate():
    """Creates a self-signed localhost certificate for the TLS test."""
    import datetime
    import ipaddress
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    folder = tempfile.mkdtemp(prefix="btcminer-tls-")
    certfile = os.path.join(folder, "cert.pem")
    keyfile = os.path.join(folder, "key.pem")
    with open(certfile, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as handle:
        handle.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return certfile, keyfile


def run_tls_case(exe, version_rolling):
    import ssl

    certfile, keyfile = make_test_certificate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    failures = 0

    print("== TLS with certificate checks disabled ==")
    pool = FakePool(version_rolling=version_rolling, tls_context=context)
    pool.start()
    url = "stratum+ssl://localhost:%d" % pool.port
    print("fake TLS pool on", url)
    proc = run_miner(exe, url, 12, ["--tls-insecure"])
    stop_pool(pool)

    output = proc.stdout + proc.stderr
    accepted = output.count("share accepted")
    print("--- miner output ---")
    print(output.strip())
    print("--- fake pool ---")
    print("valid:", pool.valid, "invalid:", pool.invalid, "sni:", pool.sni)
    for error in pool.errors[:5]:
        print("  ", error)

    version_ok = True
    if version_rolling:
        version_ok = pool.configure_seen and pool.version_params >= 1
        print("version rolling negotiated:", pool.configure_seen,
              "| submits with version:", pool.version_params)

    ok = (
        proc.returncode == 0
        and pool.valid >= 1
        and pool.invalid == 0
        and accepted >= 1
        and pool.sni == "localhost"
        and "certificate validation is disabled" in output
        and version_ok
    )
    if not ok:
        failures += 1
    print("insecure run:", "PASS" if ok else "FAIL")

    print()
    print("== TLS with certificate checks enabled (must reject) ==")
    pool2 = FakePool(version_rolling=version_rolling, tls_context=context)
    pool2.start()
    url2 = "stratum+ssl://localhost:%d" % pool2.port
    proc2 = run_miner(exe, url2, 6)
    stop_pool(pool2)

    output2 = proc2.stdout + proc2.stderr
    print(output2.strip())
    rejected = (
        proc2.returncode == 0
        and pool2.valid == 0
        and output2.count("share accepted") == 0
        and "certificate" in output2.lower()
    )
    if not rejected:
        failures += 1
    print("verified run rejects the self-signed certificate:",
          "PASS" if rejected else "FAIL")

    print("RESULT:", "PASS" if failures == 0 else "FAIL")
    return 0 if failures == 0 else 1


def run_status_api_case(exe):
    import urllib.error
    import urllib.request
    import tempfile

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        api_port = probe.getsockname()[1]

    pool = FakePool()
    pool.start()
    url = "stratum+tcp://127.0.0.1:%d" % pool.port
    command = [
        exe, "-o", url, "-u", "test.worker", "-p", "x", "-t", "2",
        "--duration", "10", "--stats-interval", "5", "--log-level", "INFO",
        "--api-bind", "127.0.0.1:%d" % api_port,
    ]
    def get(path):
        with urllib.request.urlopen(
            "http://127.0.0.1:%d%s" % (api_port, path), timeout=1,
        ) as response:
            return response.status, response.read().decode()

    status = None
    health_ok = False
    missing_is_404 = False
    hashes_refresh = False
    deadline = time.monotonic() + 13
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as output_file:
        proc = subprocess.Popen(
            command, stdout=output_file, stderr=subprocess.STDOUT, text=True,
        )
        try:
            while time.monotonic() < deadline and proc.poll() is None:
                try:
                    health_ok = get("/healthz") == (200, "ok")
                    code, body = get("/status")
                    if code == 200:
                        candidate = json.loads(body)
                        if candidate.get("job_id") == "cpp-job-0001":
                            status = candidate
                            try:
                                get("/missing")
                            except urllib.error.HTTPError as error:
                                missing_is_404 = error.code == 404
                            refresh_deadline = time.monotonic() + 2
                            while time.monotonic() < refresh_deadline:
                                time.sleep(0.2)
                                _, refreshed_body = get("/status")
                                refreshed = json.loads(refreshed_body)
                                if refreshed["hashes"] > status["hashes"]:
                                    status = refreshed
                                    hashes_refresh = True
                                    break
                            break
                except (OSError, urllib.error.URLError, json.JSONDecodeError):
                    time.sleep(0.1)

            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)
            stop_pool(pool)
            output_file.seek(0)
            output = output_file.read()

    required_fields = {
        "version", "uptime", "pool", "kernel", "threads", "hashrate",
        "hashes", "shares_found", "accepted", "rejected", "stale",
        "best_share", "pool_difficulty", "job_id", "version_mask",
        "switch_count",
    }
    pool_status = status.get("pool", {}) if status else {}
    ok = (
        proc.returncode == 0
        and health_ok
        and missing_is_404
        and hashes_refresh
        and status is not None
        and required_fields.issubset(status)
        and status["version"].startswith("btcminer 1.3.0")
        and status["uptime"] > 0
        and pool_status.get("url") == url
        and pool_status.get("user") == "test.worker"
        and pool_status.get("index") == 1
        and pool_status.get("count") == 1
        and status["threads"] == 2
        and status["job_id"] == "cpp-job-0001"
        and pool.valid >= 1
        and pool.invalid == 0
    )
    if not ok:
        print("--- status API miner output ---")
        print(output[-4000:].strip())
        print("--- status API pool ---")
        print("valid:", pool.valid, "invalid:", pool.invalid)
    print("healthz:", "PASS" if health_ok else "FAIL")
    print("status fields and pool state:", "PASS" if status else "FAIL")
    print("status hashes refresh while mining:", "PASS" if hashes_refresh else "FAIL")
    print("unknown path returns 404:", "PASS" if missing_is_404 else "FAIL")
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def run_failover_case(exe):
    import tempfile

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]

    pool = FakePool()
    pool.start()
    primary_url = "stratum+tcp://127.0.0.1:%d" % dead_port
    backup_url = "stratum+tcp://127.0.0.1:%d" % pool.port
    config = {
        "pools": [
            {"url": primary_url},
            {"url": backup_url},
        ],
    }

    with tempfile.TemporaryDirectory(prefix="btcminer-failover-") as folder:
        config_path = os.path.join(folder, "config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        proc = run_miner(
            exe, primary_url, 15, ["-c", config_path],
        )
    stop_pool(pool)

    output = proc.stdout + proc.stderr
    switch_position = output.find("switching to pool 2/2")
    failures_before_switch = output[:switch_position].count(
        "connecting to 127.0.0.1:%d" % dead_port
    ) if switch_position >= 0 else 0
    ok = (
        proc.returncode == 0
        and switch_position >= 0
        and failures_before_switch == 2
        and "connecting to 127.0.0.1:%d" % pool.port in output
        and pool.valid >= 1
        and pool.invalid == 0
    )
    if not ok:
        print("--- failover miner output ---")
        print(output[-4000:].strip())
        print("--- backup pool ---")
        print("valid:", pool.valid, "invalid:", pool.invalid)
    print(
        "switched after two primary failures:",
        "PASS" if failures_before_switch == 2 else "FAIL",
    )
    print(
        "backup accepted valid shares:",
        "PASS" if pool.valid >= 1 and pool.invalid == 0 else "FAIL",
    )
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "exe", nargs="?", default=os.path.join("dist", "btcminer.exe"),
        help="path to btcminer.exe",
    )
    parser.add_argument(
        "--version-rolling", action="store_true",
        help="advertise BIP310 version rolling in the fake pool",
    )
    parser.add_argument(
        "--tls", action="store_true",
        help="test stratum+ssl with a self-signed certificate",
    )
    parser.add_argument(
        "--status-api", action="store_true",
        help="test /status, /healthz, and the unknown-path response",
    )
    parser.add_argument(
        "--failover", action="store_true",
        help="test ordered failover after two failed primary connections",
    )
    args = parser.parse_args()

    exe = os.path.abspath(args.exe)
    if not os.path.isfile(exe):
        print("FAIL: executable not found:", exe)
        return 2

    if args.tls:
        return run_tls_case(exe, args.version_rolling)
    if args.status_api:
        return run_status_api_case(exe)
    if args.failover:
        return run_failover_case(exe)

    pool = FakePool(version_rolling=args.version_rolling)
    pool.start()
    url = "stratum+tcp://127.0.0.1:%d" % pool.port
    print("fake pool on", url)

    proc = run_miner(exe, url, 12)
    stop_pool(pool)

    output = proc.stdout + proc.stderr
    accepted = output.count("share accepted")
    print("--- miner output ---")
    print(output.strip())
    print("--- fake pool ---")
    print("valid shares:", pool.valid, "invalid:", pool.invalid)
    for error in pool.errors[:5]:
        print("  ", error)
    print("version rolling negotiated:", pool.configure_seen,
          "| submits with version:", pool.version_params)

    version_ok = True
    if args.version_rolling:
        version_ok = (
            pool.configure_seen
            and pool.version_params >= 1
            and "version rolling enabled" in output
        )

    ok = (
        proc.returncode == 0
        and pool.valid >= 1
        and pool.invalid == 0
        and accepted >= 1
        and version_ok
    )
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())



