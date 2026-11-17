# btcminer 1.3.0: transport, pool and operations design

Status: approved (2026-11-17)
Target release: 1.3.0

## Goal

Turn the 1.2.0 miner into a deployable tool by adding the features a real
mining deployment needs: TLS pools, BIP310 version rolling, pool failover, a
local status API and CPU controls. Behaviour of existing flags stays
compatible; the binary stays a single static Windows x64 executable using
C++17, Winsock2 and Windows system libraries only.

## Scope

In scope:

1. TLS transport for `stratum+ssl://` and `stratum+tls://` pools.
2. BIP310 version rolling (`mining.configure`, `mining.set_version_mask`).
3. Ordered multi-pool failover.
4. Local HTTP status endpoint.
5. CPU affinity, process/thread priority and a duty-cycle CPU limit.

Out of scope: TLS for the HTTP API, authentication for the API, log files,
Windows service integration, BIP310 `mining.set_goal`, proxy support.

## Architecture

```
cpp/
  stratum.{h,cpp}   transport selection (plain TCP or TLS), framing unchanged
  tls.{h,cpp}       SChannel client session (handshake, encrypt, decrypt,
                    chain + hostname validation, SNI)
  http.{h,cpp}      StatusServer: loopback HTTP/1.1, GET /status, /healthz
  cpu.{h,cpp}       affinity parsing, priority classes, thread pinning,
                    duty-cycle throttle
  miner.{h,cpp}     pool failover, version-rolling negotiation, stats snapshot
  worker.{h,cpp}    per-thread version rolling, throttling, pinning
  main.cpp          config/CLI plumbing and validation
```

`StratumClient` keeps its public surface (`connect`, `request`, `poll`,
`send_request`, `respond`, `backlog`). Internally it holds the socket plus an
optional `TlsSession`; all reads and writes go through small private helpers so
the miner never sees transport details.

Dependencies are Windows system libraries only: `ws2_32`, `secur32`,
`crypt32` (the last two for TLS). Binary size grows slightly; the build stays
`-static -static-libgcc -static-libstdc++`.

## 1. TLS

- `TlsSession(uintptr_t socket, std::string host, bool verify)` owns a
  credential handle and a security context.
- Handshake: `AcquireCredentialsHandle` with `SCHANNEL_CRED`
  (`SCH_CRED_AUTO_CRED_VALIDATION` when verifying), then
  `InitializeSecurityContext` until `SEC_E_OK`. The host is passed as the
  target name, which makes SChannel send SNI.
- Stream sizes come from `SECPKG_ATTR_STREAM_SIZES`; writes are chunked to
  `cbMaximumMessage` and wrapped with `EncryptMessage`; reads call
  `DecryptMessage` and keep `SECBUFFER_EXTRA` bytes for the next record.
  `SEC_E_INCOMPLETE_MESSAGE` waits for more bytes; `SEC_I_CONTEXT_EXPIRED`
  is a clean disconnect.
- Certificate policy: after the handshake, when verifying, obtain
  `SECPKG_ATTR_SERVER_CERT` and run `CertVerifyCertificateChainPolicy` with
  `CERT_CHAIN_POLICY_SSL`, `AUTHTYPE_SERVER` and `pwszServerName`, so both the
  chain and the hostname are checked. Failures abort before any credentials
  are sent.
- `tls_verify: false` (config) / `--tls-insecure` disables validation and is
  documented as test-only.
- Errors map to `StratumDisconnected`, so TLS failures participate in
  failover and backoff exactly like TCP failures.
- `parse_url` accepts `stratum+ssl`, `stratum+tls`, `ssl`, `tls` and marks the
  endpoint as TLS; plain schemes keep working.

Testing: a Python TLS fake pool with a generated self-signed certificate,
run with `--tls-insecure`; the test asserts handshake success, SNI equals the
connect host, a full authorize/notify/submit cycle and `/status` access.

## 2. BIP310 version rolling

- After `mining.subscribe`, when enabled, send
  `mining.configure` with `["version-rolling"]` and
  `{"version-rolling.mask": "1fffe000", "version-rolling.min-bit-count": 2}`.
  A result with `"version-rolling": true` supplies the negotiated mask;
  otherwise rolling stays off and the miner logs why.
- `mining.set_version_mask` updates the mask for later jobs. A mask of zero
  disables rolling.
- `Work` gains `header[80]` (nonce zeroed), `version` (job base version) and
  `version_mask`; `Share` gains the `version` actually hashed and a copy of
  the midstate used, so re-verification and submission cannot mix versions.
- Each worker keeps a private roll counter. When it wraps its nonce range it
  increments the counter, maps it into the mask with bit deposit
  (`version = (base & ~mask) | deposit_bits(roll, mask)`) and rebuilds the
  midstate from the header prefix. One extra compression per nonce-range wrap
  is negligible.
- `mining.submit` gains the sixth parameter (8 lowercase hex digits of the
  version) only while a mask is active.
- Self-test: `deposit_bits` known values plus a check that the midstate built
  for a rolled version hashes identically to a full 80-byte hash.

## 3. Failover

- Config gains `pools`: an ordered array of `{url, user, password}`. The
  top-level `url`/`user`/`password` still work and become the first pool.
- Every endpoint is validated at startup; an invalid entry is a fatal config
  error, not a runtime surprise.
- On session failure the miner advances to the next pool after two
  consecutive failed attempts; a session that lasted more than 120 s resets
  the failure count and returns to the primary pool.
- Backoff remains 2 s to 60 s; pool switches are logged with `pool i/n`.
- The status API reports the active pool and the switch count.

## 4. HTTP status API

- `StatusServer` binds `127.0.0.1:4068` by default; `--api-bind HOST:PORT`
  changes it, `--no-api` disables it, and `api.enabled` exists in config.
  Failure to bind is a warning: mining continues.
- One listener thread with a 250 ms accept poll. Requests are limited to 8 KB
  and one read; only `GET`/`HEAD` are answered; the connection closes after
  the response.
- `GET /status` returns JSON: version, uptime, pool (url/user/index/count),
  kernel, threads, hashrate, hashes, shares found/accepted/rejected/stale,
  best share, pool difficulty, job id, version mask and switch count.
  `GET /healthz` returns `ok`; anything else returns 404.
- `Miner` maintains a mutex-guarded snapshot that is refreshed every loop
  iteration; the HTTP thread only reads the snapshot, so there is no shared
  mutable state between threads beyond that copy.
- The API is unauthenticated by design and binds loopback by default; the
  README states this explicitly.

## 5. CPU controls

- `--affinity 0-3,6` or a hex mask (`0xF`) restricts worker threads to the
  selected CPUs, assigned round-robin. When `--threads` is not given, the
  default becomes the number of selected CPUs.
- `--priority {idle,below,normal,above,high,realtime}` sets the process
  priority class and the matching thread priority for workers.
- `--cpu-limit 1..100` (default 100) implements an approximate duty cycle:
  after each 8192-nonce chunk the worker sleeps for
  `elapsed * (100 - limit) / limit`, capped so job changes stay responsive.
  Documentation states that the limit is approximate.
- Invalid values are rejected during argument/config validation with a clear
  message.

## Error handling

| Failure | Behaviour |
| --- | --- |
| DNS/TCP/TLS/handshake error | warn, close, failover logic, backoff |
| Certificate or hostname mismatch | clear error naming the host, no credentials sent |
| API bind failure | warn once, mining continues |
| `mining.configure` rejected | rolling disabled for the session, logged |
| Malformed version mask | ignore update, keep previous mask, warn |
| Affinity/priority failure | warn, continue with defaults |
| `--cpu-limit` out of range | startup error |

## Testing

| Test | Coverage |
| --- | --- |
| `--self-test` | SHA-256d kernels, target math, mining run, rolled-version midstate equivalence, deposit_bits vectors |
| `build\bench.exe` | kernel speed and cross-checks (unchanged) |
| `tests\fake_pool_check.py` | end-to-end TCP pool, plus `--version-rolling` (mask honoured, header rebuilt with the submitted version), `--tls` (self-signed + `--tls-insecure`, SNI asserted), `/status` consistency |
| CPU controls | run `--benchmark` in the background, verify `ProcessorAffinity` and `PriorityClass` through PowerShell |
| Intel SDE `-tgl` | bench and `--self-test` again to prove SHA-NI is unaffected |
| Real pool | short ckpool TCP session plus a TLS handshake against a reachable TLS endpoint when available |

## Delivery

Version 1.3.0, commits by phase: plumbing, CPU controls, version rolling,
failover, TLS, HTTP + docs. README and README.vi.md updated in the same
release; release notes ASCII-only; asset
`btcminer-v1.3.0-windows-x64.exe`.
