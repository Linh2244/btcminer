"""Minimal Stratum v1 client (newline delimited JSON-RPC over TCP)."""

from __future__ import annotations

import json
import select
import socket
import time
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 120.0
_READ_SIZE = 65536

__all__ = ["StratumClient", "StratumError", "StratumDisconnected", "parse_url"]


class StratumError(Exception):
    """The pool answered with an error or an unusable payload."""


class StratumDisconnected(StratumError):
    """The TCP connection to the pool is gone."""


def parse_url(url: str):
    """Split a pool URL into ``(scheme, host, port)``.

    Accepted forms::

        stratum+tcp://pool.example.com:3333
        stratum://pool.example.com:3333
        tcp://pool.example.com:3333
        pool.example.com:3333
    """
    if not url:
        raise ValueError("pool URL is empty")
    if "://" not in url:
        url = "stratum+tcp://" + url
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme in ("stratum+ssl", "stratum+tls", "ssl", "tls"):
        raise ValueError("TLS pools are not supported, use stratum+tcp")
    if scheme not in ("stratum", "stratum+tcp", "tcp"):
        raise ValueError("unsupported URL scheme %r" % parts.scheme)
    host = parts.hostname
    if not host:
        raise ValueError("pool URL has no host")
    port = parts.port or 3333
    return scheme, host, port


class StratumClient:
    """Tiny blocking client with an explicit read buffer.

    The client never runs a background thread: the caller drives it with
    :meth:`poll`, which keeps shutdown and reconnects predictable.
    """

    def __init__(self, host: str, port: int, log, user_agent: str = "btcminer/1.0",
                 timeout: float = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.log = log
        self.user_agent = user_agent
        self.timeout = timeout
        self.sock = None
        self.backlog = []
        self._buf = b""
        self._next_id = 0

    # -- connection management -------------------------------------------
    def connect(self) -> None:
        self.close()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise StratumDisconnected(
                "cannot connect to %s:%s: %s" % (self.host, self.port, exc)
            ) from exc
        for option in (socket.TCP_NODELAY,):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, option, 1)
            except OSError:
                pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
        sock.settimeout(None)
        self.sock = sock
        self._buf = b""
        self.backlog.clear()
        self.log.debug("TCP connection established to %s:%s", self.host, self.port)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self._buf = b""

    # -- sending ----------------------------------------------------------
    def _send_raw(self, payload: dict) -> int:
        if self.sock is None:
            raise StratumDisconnected("not connected")
        blob = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
        try:
            self.sock.sendall(blob)
        except OSError as exc:
            raise StratumDisconnected("send failed: %s" % exc) from exc
        self.log.debug("--> %s", blob.decode(errors="replace").strip())
        return payload.get("id")

    def send(self, method: str, params) -> int:
        """Send a request without waiting; returns the request id."""
        self._next_id += 1
        request_id = self._next_id
        self._send_raw({"id": request_id, "method": method, "params": params})
        return request_id

    def respond(self, request_id, result) -> None:
        """Answer a request initiated by the pool (e.g. ``client.get_version``)."""
        self._send_raw({"id": request_id, "result": result, "error": None})

    def request(self, method: str, params, timeout: float = 30.0):
        """Send a request and wait for its response.

        Notifications that arrive in the meantime are kept in ``backlog`` so
        that no job or difficulty update is ever lost.
        """
        request_id = self.send(method, params)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StratumError("timed out waiting for %s response" % method)
            batch = self._recv_messages(remaining)
            for index, message in enumerate(batch):
                if message.get("id") == request_id:
                    # Keep everything that arrived after the response (a pool
                    # often pipelines set_difficulty/notify right behind it).
                    self.backlog.extend(batch[index + 1:])
                    if message.get("error"):
                        raise StratumError(
                            "%s failed: %s" % (method, json.dumps(message["error"]))
                        )
                    return message.get("result")
                self.backlog.append(message)

    # -- receiving --------------------------------------------------------
    def _recv_messages(self, timeout: float):
        if self.sock is None:
            raise StratumDisconnected("not connected")
        try:
            readable, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        except (OSError, ValueError) as exc:
            raise StratumDisconnected("select failed: %s" % exc) from exc
        if not readable:
            return []
        try:
            chunk = self.sock.recv(_READ_SIZE)
        except OSError as exc:
            raise StratumDisconnected("receive failed: %s" % exc) from exc
        if not chunk:
            raise StratumDisconnected("pool closed the connection")
        self._buf += chunk

        messages = []
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                messages.append(json.loads(line))
            except json.JSONDecodeError:
                self.log.warning("ignoring malformed line from pool: %r", line[:200])
        for message in messages:
            self.log.debug("<-- %s", json.dumps(message)[:500])
        return messages

    def poll(self, timeout: float = 0.5):
        """Wait up to ``timeout`` seconds for pool messages."""
        return self._recv_messages(timeout)

    def take_backlog(self):
        """Return (and clear) messages buffered inside :meth:`request`."""
        messages, self.backlog = self.backlog, []
        return messages
