"""Stratum session handling + CPU mining orchestration."""

from __future__ import annotations

import collections
import json
import os
import threading
import time
from dataclasses import dataclass

from . import VERSION, util
from .job import Job, Work, parse_notify
from .stratum import StratumClient, StratumDisconnected, StratumError, parse_url
from .worker import WorkerPool

#: Difficulty assumed if a pool sends a job before ``mining.set_difficulty``.
DEFAULT_DIFFICULTY = 1.0

__all__ = ["Miner", "MinerConfig"]


@dataclass
class MinerConfig:
    url: str | None = None
    user: str = ""
    password: str = "x"
    processes: int = 1
    user_agent: str = "btcminer-cpu/" + VERSION
    log_level: str = "INFO"
    stats_interval: float = 30.0
    idle_timeout: float = 300.0
    duration: float | None = None
    suggest_difficulty: float | None = None
    seed: int | None = None

    def __post_init__(self) -> None:
        self.processes = int(self.processes or 1)
        if self.processes < 1:
            raise ValueError("processes must be >= 1")


class Miner:
    """One pool connection, N worker processes, and the share plumbing."""

    def __init__(self, config: MinerConfig, log):
        self.config = config
        self.log = log
        self.pool = WorkerPool(config.processes, log, seed=config.seed)

        self.client: StratumClient | None = None
        self.job: Job | None = None
        self._raw_notify = None

        self.extranonce1 = b""
        self.extranonce2_size = 4
        self.extranonce2 = b""

        self.difficulty: float | None = None
        self.target_int: int | None = None
        self.generation = 0
        self.pending = {}
        self._work_key = None

        self.hash_total = 0
        self.samples = collections.deque()
        self.accepted = 0
        self.rejected = 0
        self.stale = 0
        self.shares_found = 0
        self.best_difficulty = 0.0

        self.last_rx = 0.0
        self.last_stats = 0.0
        self.started_at = time.monotonic()
        self._stop = threading.Event()
        self._warned_default_diff = False

    # ------------------------------------------------------------------ api
    def request_stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        cfg = self.config
        self.log.info(
            "btcminer %s | pool %s | worker %s | %d process(es)",
            VERSION, cfg.url, cfg.user, cfg.processes,
        )
        self.pool.start()
        backoff = 2.0
        try:
            while not self._stop.is_set() and not self._time_exceeded():
                session_started = time.monotonic()
                try:
                    self._session()
                except (StratumDisconnected, StratumError, OSError, TimeoutError) as exc:
                    self.log.warning("%s", exc)
                finally:
                    self._close_session()
                if self._stop.is_set() or self._time_exceeded():
                    break
                if time.monotonic() - session_started > 120:
                    backoff = 2.0
                self.log.info("reconnecting in %.0f s", backoff)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 60.0)
        finally:
            self.pool.stop()
            self._drain_final()
            self._print_summary()

    def benchmark(self, seconds: float) -> None:
        """Hash locally for ``seconds`` without touching the network."""
        self.log.info(
            "benchmark mode: hashing locally for %.0f s with %d process(es)",
            seconds, self.config.processes,
        )
        self.pool.start()
        work = Work(
            job_id="benchmark",
            prefix=os.urandom(76),
            target=b"\x00" * 32,          # impossible target: no share is ever found
            target_int=0,
            ntime_hex="00000000",
            extranonce2_hex="",
            generation=1,
        )
        self.pool.broadcast(work)
        start = time.monotonic()
        warm_at = None
        warm_hashes = 0
        last_report = start
        try:
            while not self._stop.is_set():
                if time.monotonic() - start >= seconds:
                    break
                time.sleep(0.25)
                self._drain_workers()
                now = time.monotonic()
                if warm_at is None and now - start >= min(2.0, seconds / 2.0):
                    warm_at, warm_hashes = now, self.hash_total
                if warm_at is not None and now - last_report >= 5.0:
                    last_report = now
                    self.log.info(
                        "benchmark: %s",
                        util.format_hashrate(
                            (self.hash_total - warm_hashes) / max(now - warm_at, 1e-9)
                        ),
                    )
        finally:
            self.pool.stop()
            self._drain_final()

        end = time.monotonic()
        base_at, base_hashes = (warm_at, warm_hashes) if warm_at else (start, 0)
        hashes = self.hash_total - base_hashes
        elapsed = max(end - base_at, 1e-9)
        self.log.info(
            "benchmark result: %s average over %.1f s (%d hashes, %d process(es))",
            util.format_hashrate(hashes / elapsed), elapsed,
            self.hash_total, self.config.processes,
        )

    # -------------------------------------------------------------- session
    def _session(self) -> None:
        cfg = self.config
        if not cfg.url:
            raise StratumError("no pool URL configured")
        scheme, host, port = parse_url(cfg.url)
        client = StratumClient(host, port, self.log, cfg.user_agent)
        self.client = client
        self.log.info("connecting to %s:%d (%s)", host, port, scheme)
        client.connect()

        result = client.request("mining.subscribe", [cfg.user_agent])
        self._apply_subscription(result)

        if cfg.suggest_difficulty:
            try:
                client.request("mining.suggest_difficulty", [cfg.suggest_difficulty], timeout=5.0)
            except (StratumError, TimeoutError) as exc:
                self.log.debug("pool ignored suggest_difficulty: %s", exc)

        authorized = client.request("mining.authorize", [cfg.user, cfg.password])
        if authorized is not True:
            raise StratumError("pool refused the worker credentials (%r)" % cfg.user)

        self.log.info(
            "authorized | extranonce1=%s | extranonce2_size=%d",
            self.extranonce1.hex() or "-", self.extranonce2_size,
        )

        # Fire and forget: most pools never answer this one, but those that do
        # may rotate our extranonce on long sessions.
        try:
            client.send("mining.extranonce.subscribe", [])
        except OSError as exc:
            self.log.debug("could not enable extranonce subscription: %s", exc)

        now = time.monotonic()
        self.last_rx = now
        self.last_stats = now
        self.samples.clear()
        self.samples.append((now, self.hash_total))

        while not self._stop.is_set() and not self._time_exceeded():
            messages = client.poll(0.5)
            backlog = client.take_backlog()
            if messages or backlog:
                self.last_rx = time.monotonic()
            # Older backlog messages first: they arrived before the current read.
            for message in backlog + messages:
                self._handle_message(message)
            self._drain_workers()
            self._stats_tick()
            if time.monotonic() - self.last_rx > cfg.idle_timeout:
                raise TimeoutError(
                    "no data from pool for %.0f s" % cfg.idle_timeout
                )

    def _close_session(self) -> None:
        self.pool.pause()
        if self.client is not None:
            self.client.close()
            self.client = None
        if self.pending:
            self.log.warning(
                "%d submitted share(s) still unconfirmed", len(self.pending)
            )
            self.pending.clear()

    def _apply_subscription(self, result) -> None:
        try:
            subscriptions, extranonce1, extranonce2_size = result[0], result[1], result[2]
        except (TypeError, IndexError, KeyError) as exc:
            raise StratumError("unexpected mining.subscribe result: %r" % (result,)) from exc
        if extranonce1 is None:
            raise StratumError("pool did not provide an extranonce1")
        try:
            self.extranonce1 = bytes.fromhex(extranonce1)
        except (TypeError, ValueError) as exc:
            raise StratumError("invalid extranonce1 %r" % (extranonce1,)) from exc
        try:
            self.extranonce2_size = int(extranonce2_size)
        except (TypeError, ValueError) as exc:
            raise StratumError("invalid extranonce2 size %r" % (extranonce2_size,)) from exc
        if not 0 <= self.extranonce2_size <= 32:
            raise StratumError("unsupported extranonce2 size %d" % self.extranonce2_size)
        self.log.debug("subscriptions: %s", subscriptions)
        self._work_key = None

    # -------------------------------------------------------- pool messages
    def _handle_message(self, message) -> None:
        if not isinstance(message, dict):
            return
        method = message.get("method")
        if method:
            params = message.get("params") or []
            if method == "mining.notify":
                self._on_notify(params)
            elif method == "mining.set_difficulty":
                self._on_set_difficulty(params)
            elif method == "mining.set_extranonce":
                self._on_set_extranonce(params)
            elif method == "client.get_version":
                self.client.respond(message.get("id"), self.config.user_agent)
            elif method == "client.show_message":
                self.log.info("pool message: %s", params[0] if params else "")
            elif method == "client.reconnect":
                raise StratumDisconnected("pool requested a reconnect")
            elif method in ("mining.set_version_mask", "mining.ping", "mining.set_goal"):
                self.log.debug("ignoring %s: %s", method, params)
            else:
                self.log.debug("unhandled pool method %s: %s", method, params)
            return

        request_id = message.get("id")
        if request_id in self.pending:
            self._on_submit_response(self.pending.pop(request_id), message)
        elif message.get("error"):
            self.log.warning("pool error: %s", json.dumps(message["error"]))

    def _on_notify(self, params) -> None:
        if self.difficulty is None:
            if not self._warned_default_diff:
                self.log.info(
                    "job arrived before the first mining.set_difficulty, "
                    "using difficulty %g until the pool sends one",
                    DEFAULT_DIFFICULTY,
                )
                self._warned_default_diff = True
            self._set_difficulty(DEFAULT_DIFFICULTY)
        try:
            job = parse_notify(params, self.extranonce1, self.extranonce2_size)
        except ValueError as exc:
            self.log.error("bad mining.notify: %s", exc)
            return
        self._raw_notify = list(params)
        self.job = job
        size = self.extranonce2_size
        self.extranonce2 = os.urandom(size) if size else b""
        if job.clean:
            self.log.debug("clean job %s", job.job_id)
        self._publish_work()

    def _on_set_difficulty(self, params) -> None:
        if not params:
            self.log.warning("empty mining.set_difficulty")
            return
        try:
            difficulty = float(params[0])
        except (TypeError, ValueError):
            self.log.warning("bad mining.set_difficulty: %r", params)
            return
        previous = self.target_int
        try:
            self._set_difficulty(difficulty)
        except ValueError as exc:
            self.log.warning("ignoring difficulty: %s", exc)
            return
        if previous == self.target_int:
            self.log.debug(
                "pool repeated difficulty %s, nothing to do",
                util.format_difficulty(difficulty),
            )
            return
        self.log.info("pool difficulty set to %s", util.format_difficulty(difficulty))
        if self.job is not None:
            # Republish so the workers start using the new target right away.
            self._publish_work()

    def _on_set_extranonce(self, params) -> None:
        if len(params) < 2:
            self.log.warning("bad mining.set_extranonce: %r", params)
            return
        try:
            self.extranonce1 = bytes.fromhex(params[0] or "")
            self.extranonce2_size = int(params[1])
        except (TypeError, ValueError) as exc:
            self.log.warning("bad mining.set_extranonce: %s", exc)
            return
        self.log.info(
            "extranonce changed | extranonce1=%s | extranonce2_size=%d",
            self.extranonce1.hex() or "-", self.extranonce2_size,
        )
        self._work_key = None
        if self._raw_notify is not None:
            self._on_notify(self._raw_notify)

    def _set_difficulty(self, difficulty: float) -> None:
        target = util.difficulty_to_target(difficulty)
        self.difficulty = float(difficulty)
        self.target_int = target

    # --------------------------------------------------------------- shares
    def _publish_work(self) -> None:
        if self.job is None or self.target_int is None:
            return
        try:
            prefix = self.job.header_prefix(self.extranonce2)
        except ValueError as exc:
            self.log.error("cannot build block header: %s", exc)
            return
        target = min(max(self.target_int, 1), util.MAX_TARGET)
        key = (self.job.job_id, self.extranonce2, target, self.job.ntime)
        if key == self._work_key:
            return
        self._work_key = key
        self.generation += 1
        work = Work(
            job_id=self.job.job_id,
            prefix=prefix,
            target=target.to_bytes(32, "big"),
            target_int=target,
            ntime_hex=self.job.ntime_hex,
            extranonce2_hex=self.extranonce2.hex(),
            generation=self.generation,
        )
        self.pool.broadcast(work)
        self.log.debug(
            "job %s published | difficulty %s | extranonce2 %s",
            self.job.job_id, util.format_difficulty(self.difficulty),
            self.extranonce2.hex() or "-",
        )

    def _drain_workers(self) -> None:
        for item in self.pool.drain():
            kind = item[0]
            if kind == "stat":
                self.hash_total += int(item[2])
            elif kind == "share":
                self._on_share(item[1], item[2], item[3], item[4])

    def _drain_final(self) -> None:
        """Collect the hash counters workers flush while shutting down."""
        for item in self.pool.take_final():
            if item[0] == "stat":
                self.hash_total += int(item[2])

    def _on_share(self, worker_index, nonce, hash_hex, work: Work) -> None:
        value = int(hash_hex, 16)
        share_difficulty = (
            float("inf") if value == 0 else util.target_to_difficulty(value)
        )
        self.shares_found += 1
        self.best_difficulty = max(self.best_difficulty, share_difficulty)
        self.log.info(
            "share found | worker %d | job %s | nonce %08x | difficulty %s",
            worker_index, work.job_id, nonce, util.format_difficulty(share_difficulty),
        )
        if self.client is None:
            self.log.warning("no active pool connection, share dropped")
            return
        params = [
            self.config.user,
            work.job_id,
            work.extranonce2_hex,
            work.ntime_hex,
            "%08x" % nonce,
        ]
        try:
            request_id = self.client.send("mining.submit", params)
        except OSError as exc:
            self.log.warning("could not submit share: %s", exc)
            return
        self.pending[request_id] = {
            "job_id": work.job_id,
            "difficulty": share_difficulty,
            "hash": hash_hex,
            "found_at": time.monotonic(),
        }

    def _on_submit_response(self, share, message) -> None:
        if message.get("result") is True:
            self.accepted += 1
            self.log.info(
                "share accepted | difficulty %s | accepted %d / rejected %d",
                util.format_difficulty(share["difficulty"]),
                self.accepted, self.rejected,
            )
            return
        self.rejected += 1
        detail = message.get("error")
        text = detail if isinstance(detail, str) else json.dumps(detail)
        lowered = (text or "").lower()
        if "stale" in lowered or "job not found" in lowered:
            self.stale += 1
        self.log.warning("share rejected: %s", text or "no reason given")

    # ---------------------------------------------------------------- stats
    def _stats_tick(self) -> None:
        now = time.monotonic()
        interval = max(5.0, float(self.config.stats_interval))
        if now - self.last_stats < interval:
            return
        self.last_stats = now
        self.samples.append((now, self.hash_total))
        while len(self.samples) > 2 and now - self.samples[0][0] > interval * 3:
            self.samples.popleft()
        t0, h0 = self.samples[0]
        rate = (self.hash_total - h0) / max(now - t0, 1e-9)
        self.log.info(
            "%s | accepted %d | rejected %d | best share %s | difficulty %s | job %s",
            util.format_hashrate(rate),
            self.accepted,
            self.rejected,
            util.format_difficulty(self.best_difficulty) if self.best_difficulty else "-",
            util.format_difficulty(self.difficulty) if self.difficulty else "-",
            self.job.job_id[:16] if self.job else "-",
        )
        dead = self.pool.dead_workers()
        if dead:
            self.log.warning("%d worker process(es) are no longer running", dead)

    def _print_summary(self) -> None:
        elapsed = max(time.monotonic() - self.started_at, 1e-9)
        self.log.info(
            "stopped | %s average | %d hashes | %d share(s) found | %d accepted | "
            "%d rejected | best share %s",
            util.format_hashrate(self.hash_total / elapsed),
            self.hash_total,
            self.shares_found,
            self.accepted,
            self.rejected,
            util.format_difficulty(self.best_difficulty) if self.best_difficulty else "-",
        )

    def _time_exceeded(self) -> bool:
        if self.config.duration is None:
            return False
        return time.monotonic() - self.started_at >= float(self.config.duration)
