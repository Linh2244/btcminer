"""CPU workers: one operating system process per mining thread.

``hashlib`` releases the GIL while hashing, but the per-nonce loop is Python
code, so processes scale much better than threads here.  Each worker walks its
own slice of the 32 bit nonce space (``index, index+stride, ...``) and reports
shares and hash counters back to the parent through queues.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import queue
import random
import struct
import time

from .job import Work
from .util import NONCE_SPACE

#: Nonces hashed between two checks for a newer job.
CHUNK = 20_000
#: How often a worker reports its hash counter.
STAT_INTERVAL = 1.0

__all__ = ["WorkerPool", "mining_worker", "CHUNK"]


def _newest(job_queue):
    """Drain a queue and keep only the last item (jobs arrive in bursts)."""
    latest = None
    while True:
        try:
            latest = job_queue.get_nowait()
        except queue.Empty:
            return latest
        except (EOFError, OSError, ValueError):
            return latest


def mining_worker(index: int, stride: int, job_queue, result_queue, stop_event, seed: int):
    """Hash nonces and push ``("share", ...)`` / ``("stat", ...)`` messages."""
    rng = random.Random(seed + index)
    sha256 = hashlib.sha256
    pack_into = struct.pack_into

    work = None
    pending = 0
    last_stat = time.monotonic()
    while not stop_event.is_set():
        # Block only when there is nothing to do, otherwise just poll for a
        # newer job so a fresh block is picked up within one chunk.
        if work is None:
            try:
                work = job_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            except (EOFError, OSError, ValueError):
                return
        else:
            newer = _newest(job_queue)
            if newer is not None:
                work = newer

        if work is None:          # idle marker, wait for the next real job
            continue

        header = bytearray(work.prefix)
        header += b"\x00\x00\x00\x00"
        target = work.target
        # Start at a random 32 bit offset so two miners on one job do not
        # necessarily collide, then keep the same stride across workers.
        nonce = (rng.randrange(NONCE_SPACE) // stride) * stride + index

        while not stop_event.is_set():
            limit = nonce + CHUNK * stride
            if limit > NONCE_SPACE:
                limit = NONCE_SPACE
            for n in range(nonce, limit, stride):
                pack_into("<I", header, 76, n)
                digest = sha256(sha256(header).digest()).digest()
                # The hash is displayed big endian, and so is the target.
                if digest[::-1] <= target:
                    result_queue.put(("share", index, n, digest[::-1].hex(), work))
            pending += (limit - nonce + stride - 1) // stride
            nonce = limit
            if nonce >= NONCE_SPACE:      # wrap around the nonce space
                nonce = (rng.randrange(NONCE_SPACE) // stride) * stride + index

            newer = _newest(job_queue)
            if newer is not None:
                work = newer
                break

            now = time.monotonic()
            if now - last_stat >= STAT_INTERVAL:
                result_queue.put(("stat", index, pending))
                pending = 0
                last_stat = now

    # Flush the last partial interval so the parent's counters are exact.
    if pending:
        try:
            result_queue.put(("stat", index, pending))
        except (OSError, ValueError):
            pass


class WorkerPool:
    """Owns the worker processes, their job queues and the result queue."""

    def __init__(self, processes: int, log, seed: int | None = None):
        self.log = log
        self.count = max(1, min(int(processes), 1024))
        self.seed = seed if seed is not None else random.randrange(1 << 31)
        self._ctx = mp.get_context()
        self.work_queues = [self._ctx.Queue() for _ in range(self.count)]
        self.result_queue = self._ctx.Queue()
        self.stop_event = self._ctx.Event()
        self.processes = []
        self.final_messages = []

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self.processes:
            return
        for index in range(self.count):
            process = self._ctx.Process(
                target=mining_worker,
                args=(
                    index,
                    self.count,
                    self.work_queues[index],
                    self.result_queue,
                    self.stop_event,
                    self.seed,
                ),
                name="btcminer-%d" % index,
            )
            process.daemon = True
            process.start()
            self.processes.append(process)
        self.log.debug("%d worker process(es) started", self.count)

    def stop(self) -> None:
        self.stop_event.set()
        self.broadcast(None)      # unblock workers waiting on an empty queue
        for process in self.processes:
            process.join(timeout=3.0)
        for process in self.processes:
            if process.is_alive():
                process.terminate()
        for process in self.processes:
            try:
                process.join(timeout=1.0)
            except (AssertionError, ValueError):
                pass
        self.processes.clear()
        # Workers flush their last hash counter right before exiting.
        self.final_messages = self.drain()
        for q in self.work_queues + [self.result_queue]:
            try:
                q.close()
                q.join_thread()
            except (OSError, ValueError):
                pass

    def take_final(self):
        """Messages produced during shutdown (mostly the last hash counters)."""
        messages, self.final_messages = self.final_messages, []
        return messages

    # -- job distribution -------------------------------------------------
    def broadcast(self, work: Work | None) -> None:
        """Publish a job (or ``None`` to pause) to every worker."""
        for q in self.work_queues:
            _newest(q)
            try:
                q.put_nowait(work)
            except (queue.Full, OSError, ValueError):
                pass

    def pause(self) -> None:
        self.broadcast(None)

    def drain(self):
        """Return every message workers produced since the last call."""
        messages = []
        while True:
            try:
                messages.append(self.result_queue.get_nowait())
            except queue.Empty:
                return messages
            except (EOFError, OSError, ValueError):
                return messages

    def dead_workers(self) -> int:
        return sum(1 for process in self.processes if not process.is_alive())
