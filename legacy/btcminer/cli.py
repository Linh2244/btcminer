"""Command line entry point: argument parsing, config file and self-test."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

from . import VERSION, util
from .miner import Miner, MinerConfig
from .stratum import parse_url
from .worker import WorkerPool

#: Block 125552 header - the classic SHA-256d reference vector.
REFERENCE_HEADER = bytes.fromhex(
    "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
    "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
    "c7f5d74df2b9441a42a14695"
)
REFERENCE_HASH = "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d"

DEFAULT_CONFIG_FILE = "config.json"

SETTINGS = (
    "url",
    "user",
    "password",
    "processes",
    "user_agent",
    "log_level",
    "stats_interval",
    "idle_timeout",
    "duration",
    "suggest_difficulty",
    "seed",
)

__all__ = ["main", "build_parser"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="btcminer",
        description="CPU SHA-256d Bitcoin miner speaking Stratum v1.",
        epilog=(
            "Example: python run.py -o stratum+tcp://solo.ckpool.org:3333 "
            "-u <your-btc-address>.cpu -t 4"
        ),
    )
    parser.add_argument("-o", "--url", help="pool URL, e.g. stratum+tcp://host:3333")
    parser.add_argument("-u", "--user", help="worker name, usually <btc-address>[.<worker>]")
    parser.add_argument("-p", "--password", help="worker password (pools usually ignore it)")
    parser.add_argument(
        "-t", "--processes", type=int,
        help="number of mining processes (default: number of CPUs)",
    )
    parser.add_argument("-c", "--config", help="JSON config file (default: ./config.json)")
    parser.add_argument(
        "--duration", type=float,
        help="stop after N seconds (useful for testing)",
    )
    parser.add_argument("--stats-interval", type=float, help="seconds between hashrate reports")
    parser.add_argument(
        "--idle-timeout", type=float,
        help="reconnect when the pool is silent for N seconds",
    )
    parser.add_argument(
        "--suggest-difficulty", type=float,
        help="ask the pool for this share difficulty",
    )
    parser.add_argument("--user-agent", help="version string sent to the pool")
    parser.add_argument("--seed", type=int, help="RNG seed (reproducible nonce start)")
    parser.add_argument(
        "--benchmark", type=float, nargs="?", const=30.0, metavar="SECONDS",
        help="hash locally for N seconds (default 30) without connecting to a pool",
    )
    parser.add_argument(
        "--self-test", action="store_true",
        help="verify hashing, target math and a real mining run, then exit",
    )
    parser.add_argument(
        "--log-level", default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging verbosity (default: INFO)",
    )
    parser.add_argument("--version", action="version", version="btcminer " + VERSION)
    return parser


def _setup_logging(level: str = "INFO") -> logging.Logger:
    numeric = getattr(logging, str(level).upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s  %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        force=True,
    )
    logger = logging.getLogger("btcminer")
    logger.setLevel(numeric)
    return logger


def _collect_settings(args) -> dict:
    settings = {}
    path = args.config
    if path is None and os.path.isfile(DEFAULT_CONFIG_FILE):
        path = DEFAULT_CONFIG_FILE
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except OSError as exc:
            raise ValueError("cannot read %s: %s" % (path, exc)) from exc
        except json.JSONDecodeError as exc:
            raise ValueError("cannot parse %s: %s" % (path, exc)) from exc
        if not isinstance(data, dict):
            raise ValueError("%s must contain a JSON object" % path)
        settings.update({key: value for key, value in data.items() if value is not None})
        settings["_config"] = path
    for key in SETTINGS:
        value = getattr(args, key, None)
        if value is not None:
            settings[key] = value
    return settings


def _self_test(config: MinerConfig, log: logging.Logger) -> int:
    failures = 0

    log.info("self-test 1/3: SHA-256d reference vector (block 125552)")
    digest = util.sha256d(REFERENCE_HEADER)[::-1].hex()
    if digest == REFERENCE_HASH:
        log.info("  OK   header hashes to %s", digest)
    else:
        log.error("  FAIL expected %s, got %s", REFERENCE_HASH, digest)
        failures += 1

    log.info("self-test 2/3: difficulty <-> target conversion")
    checks = (
        (1, util.DIFF1_TARGET),
        (2, util.DIFF1_TARGET // 2),
        ("0.5", util.DIFF1_TARGET * 2),
    )
    for difficulty, expected in checks:
        actual = util.difficulty_to_target(difficulty)
        if actual != expected:
            log.error("  FAIL difficulty %r -> %064x", difficulty, actual)
            failures += 1
    if not failures:
        log.info("  OK   diff 1 = 0x%064x", util.DIFF1_TARGET)

    log.info(
        "self-test 3/3: mining an easy share (%d process(es), difficulty 1e-05)",
        config.processes,
    )
    prefix = os.urandom(76)
    target_int = util.difficulty_to_target(1e-5)
    work = WorkStub(prefix, target_int)
    pool = WorkerPool(config.processes, log, seed=config.seed)
    shares = []
    started = time.monotonic()
    try:
        pool.start()
        pool.broadcast(work)
        deadline = started + 30.0
        while time.monotonic() < deadline and len(shares) < 3:
            time.sleep(0.2)
            shares.extend(item for item in pool.drain() if item[0] == "share")
    finally:
        pool.stop()

    if not shares:
        log.error("  FAIL no share found in 30 s")
        failures += 1
    else:
        for item in shares:
            _, worker, nonce, hash_hex, _ = item
            digest = util.sha256d(prefix + nonce.to_bytes(4, "little"))[::-1]
            if digest.hex() != hash_hex or int(hash_hex, 16) > target_int:
                log.error("  FAIL invalid share (nonce %08x)", nonce)
                failures += 1
                break
        else:
            log.info(
                "  OK   %d share(s) verified in %.1f s",
                len(shares), time.monotonic() - started,
            )

    if failures:
        log.error("self-test FAILED (%d problem(s))", failures)
        return 1
    log.info("self-test PASSED")
    return 0


class WorkStub:
    """Duck-typed stand-in for :class:`btcminer.job.Work` (self-test only)."""

    def __init__(self, prefix: bytes, target_int: int):
        self.job_id = "self-test"
        self.prefix = prefix
        self.target = target_int.to_bytes(32, "big")
        self.target_int = target_int
        self.ntime_hex = "00000000"
        self.extranonce2_hex = ""
        self.generation = 1


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = _collect_settings(args)
    except ValueError as exc:
        print("btcminer: %s" % exc, file=sys.stderr)
        return 2

    log = _setup_logging(settings.get("log_level") or "INFO")
    if settings.get("_config"):
        log.debug("configuration loaded from %s", settings["_config"])

    try:
        config = MinerConfig(
            url=settings.get("url"),
            user=settings.get("user") or "",
            password=settings.get("password") or "x",
            processes=settings.get("processes") or (os.cpu_count() or 1),
            user_agent=settings.get("user_agent") or ("btcminer-cpu/" + VERSION),
            log_level=str(settings.get("log_level") or "INFO"),
            stats_interval=float(settings.get("stats_interval") or 30.0),
            idle_timeout=float(settings.get("idle_timeout") or 300.0),
            duration=float(settings["duration"]) if settings.get("duration") else None,
            suggest_difficulty=(
                float(settings["suggest_difficulty"])
                if settings.get("suggest_difficulty") else None
            ),
            seed=int(settings["seed"]) if settings.get("seed") is not None else None,
        )
    except (TypeError, ValueError) as exc:
        log.error("invalid configuration: %s", exc)
        return 2

    if args.self_test:
        return _self_test(config, log)

    miner = Miner(config, log)
    if args.benchmark is not None:
        miner.benchmark(args.benchmark)
        return 0

    if not config.url:
        log.error("missing pool URL: pass -o/--url or create config.json")
        return 2
    if not config.user:
        log.error("missing worker name: pass -u/--user")
        return 2
    try:
        parse_url(config.url)
    except ValueError as exc:
        log.error("invalid pool URL: %s", exc)
        return 2

    try:
        miner.run()
    except KeyboardInterrupt:
        log.info("interrupted by user")
    return 0


if __name__ == "__main__":       # pragma: no cover
    sys.exit(main())
