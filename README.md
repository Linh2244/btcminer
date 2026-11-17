# btcminer

**A CPU SHA-256d Bitcoin miner for Windows, speaking Stratum v1 — shipped as a single static executable.**

![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D4)
![Language](https://img.shields.io/badge/C%2B%2B-17-00599C)
![Kernel](https://img.shields.io/badge/SHA--256d-SHA--NI%20%7C%20AVX2%20%7C%20scalar-6E4C13)
![Protocol](https://img.shields.io/badge/Stratum-v1-F7931A)
![Binary](https://img.shields.io/badge/binary%20size-2.85%20MB-lightgrey)
![Dependencies](https://img.shields.io/badge/dependencies-none-success)
![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/github/v/release/Linh2244/btcminer)

`btcminer` connects to any Stratum v1 pool, builds the 80-byte block header from
the pool's job, scans the nonce space with an SHA-NI or 8-lane AVX2 SHA-256d
kernel, and submits shares that meet the pool's target. It is written in C++17
with no third-party libraries — only Winsock2.

> **This is a learning project.** CPU mining has not been profitable for a
> decade. At the hashrate this miner reaches (~5–20 MH/s), the expected time to
> find a solo block is measured in millions of years. Use it to study the
> Stratum protocol, to test pool infrastructure, or on regtest/testnet — not to
> make money.

**Other languages:** [Tiếng Việt](README.vi.md)

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Build from source](#build-from-source)
- [Usage](#usage)
  - [Configuration file](#configuration-file)
  - [Command-line reference](#command-line-reference)
  - [Examples](#examples)
- [Performance](#performance)
- [Testing](#testing)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Features

- **Single static binary** — `dist/btcminer.exe` is 2.85 MB and depends only on
  Windows system DLLs (`KERNEL32`, `WS2_32`, UCRT). No runtime, no installer, no
  `PATH` setup.
- **Three auto-selected hash kernels** — Intel SHA extensions (SHA-NI) on
  modern CPUs, an 8-lane AVX2 kernel on Haswell/Zen-class CPUs, and a portable
  scalar fallback. One binary runs everywhere; the fastest available kernel is
  picked at startup via CPUID.
- **Midstate caching** — the first 64 bytes of the header are compressed once
  per job; each nonce then costs only two SHA-256 compressions.
- **Exact 256-bit target math** — `difficulty → target` uses integer division,
  matching `floor(0xFFFF × 2²⁰⁸ / difficulty)` bit for bit.
- **Multithreaded** with `std::thread`; every thread owns a disjoint slice of the
  nonce space. Defaults to the number of logical CPUs.
- **Defensive share validation** — every candidate produced by the SIMD kernel
  is re-hashed by the scalar kernel before it is sent to the pool.
- **Complete Stratum v1 session handling**: `mining.subscribe`,
  `mining.authorize`, `mining.notify`, `mining.set_difficulty`,
  `mining.set_extranonce`, `mining.suggest_difficulty`, `client.get_version`,
  `client.reconnect`, `client.show_message`, idle timeout, reconnect with
  exponential backoff.
- **Self-contained tooling**: `--self-test` (known-answer vectors, target math,
  a short live mine), `--benchmark` (hashrate without a pool), plus a fake-pool
  end-to-end test that rebuilds every submitted header with independent code.

## Requirements

**To run**

| Item | Notes |
| --- | --- |
| Windows 10/11, 64-bit | Tested on Windows 11 23H2 |
| Internet access | TCP to the pool; plain `stratum+tcp://` only |
| Pool account | Solo pools use your BTC address as the username |
| CPU | x86-64. SHA-NI is used when present, then AVX2, then the scalar kernel |

**To build**

| Item | Notes |
| --- | --- |
| MinGW-w64 `g++` | Tested with WinLibs g++ 16.1.0 (UCRT). No CMake, no Visual Studio, no Python |
| `-lws2_32` | Ships with MinGW-w64 |

## Quick start

Grab the prebuilt Windows binary (`btcminer-<version>-windows-x64.exe`) from the
[latest release](https://github.com/Linh2244/btcminer/releases/latest), or build
it yourself (see below). The commands use the source-checkout path
`.\dist\btcminer.exe`; a downloaded release is a single file, so run it from
wherever you saved it. Then:

```powershell
# 1) verify the hashing core, target math and a short mining run (offline)
.\dist\btcminer.exe --self-test

# 2) measure hashrate for 15 seconds (no pool needed)
.\dist\btcminer.exe --benchmark 15

# 3) mine for real against a solo pool
.\dist\btcminer.exe -o stratum+tcp://solo.ckpool.org:3333 `
                    -u <YOUR_BTC_ADDRESS>.worker1 -p x -t 8
```

A healthy session looks like this:

```
11:05:38  INFO    btcminer 1.3.0 | pool stratum+tcp://solo.ckpool.org:3333 | worker 1A1z....cpptest | 8 thread(s) | kernel sha-ni
11:05:43  INFO    authorized | extranonce1=bcaf946e | extranonce2_size=8
11:05:44  INFO    pool difficulty set to 10000
11:05:58  INFO    16.93 MH/s | accepted 0 | rejected 0 | best share - | difficulty 10000 | job 6ae40f5a0000d42d
```

`config.json` is picked up automatically from the **current working directory**
(not from the folder containing the `.exe`). Command-line flags always override
the file.

## Build from source

```powershell
# build dist\btcminer.exe (static) and run --self-test automatically
powershell -ExecutionPolicy Bypass -File .\build.ps1

# optional: also build the developer tools (build\bench.exe, build\check.exe)
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Tools

# start from a clean tree
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Clean
```

`build.ps1` compiles every translation unit (`sha256_avx2.cpp` gets `-mavx2`,
`sha256_shani.cpp` gets `-msha -mssse3 -msse4.1`), links with
`-static -static-libgcc -static-libstdc++ -lws2_32`, then runs the binary's
self-test and fails the build if it does not pass.

Equivalent manual build:

```powershell
New-Item -ItemType Directory -Force build | Out-Null

g++ -O3 -std=c++17 -Wall -Wextra -c cpp/sha256.cpp      -o build/sha256.o
g++ -O3 -std=c++17 -Wall -Wextra -mavx2 -c cpp/sha256_avx2.cpp -o build/sha256_avx2.o
g++ -O3 -std=c++17 -Wall -Wextra -msha -mssse3 -msse4.1 `
    -c cpp/sha256_shani.cpp -o build/sha256_shani.o
foreach ($s in "util","json","job","stratum","worker","miner","main") {
    g++ -O3 -std=c++17 -Wall -Wextra -c "cpp/$s.cpp" -o "build/$s.o"
}

g++ -O3 -std=c++17 -static -static-libgcc -static-libstdc++ `
    build/util.o build/json.o build/job.o build/stratum.o build/worker.o `
    build/miner.o build/main.o build/sha256.o build/sha256_avx2.o `
    build/sha256_shani.o -o dist/btcminer.exe -lws2_32
```

The build is warning-clean with `-Wall -Wextra`.

## Usage

### Configuration file

Copy the template and edit it:

```powershell
Copy-Item config.example.json config.json
```

| Key | Meaning | Default |
| --- | --- | --- |
| `url` | Pool URL (`stratum+tcp://host:port`) | — |
| `user` | Worker name, usually `<BTC address>.<worker>` | — |
| `password` | Worker password (pools usually ignore it) | `"x"` |
| `processes` | Number of mining threads (name kept for compatibility) | logical CPUs |
| `stats_interval` | Seconds between hashrate reports | `30` |
| `idle_timeout` | Reconnect if the pool is silent this long | `300` |
| `log_level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `duration` | Stop after N seconds (handy for testing) | unlimited |
| `suggest_difficulty` | Ask the pool for this share difficulty | not sent |
| `seed` | RNG seed (reproducible nonce start) | random |

### Command-line reference

```
usage: btcminer [-h] [-o URL] [-u USER] [-p PASSWORD] [-t THREADS]
                [-c CONFIG] [--duration DURATION]
                [--stats-interval STATS_INTERVAL]
                [--idle-timeout IDLE_TIMEOUT]
                [--suggest-difficulty SUGGEST_DIFFICULTY]
                [--user-agent USER_AGENT] [--seed SEED]
                [--benchmark [SECONDS]] [--self-test]
                [--log-level {DEBUG,INFO,WARNING,ERROR}] [--version]
```

| Option | Description |
| --- | --- |
| `-o, --url URL` | Pool URL: `stratum+tcp://host:port`, `stratum://`, `tcp://`, or `host:port` |
| `-u, --user USER` | Worker name / BTC address |
| `-p, --password PASS` | Worker password |
| `-t, --processes N` | Number of mining threads (default: logical CPUs) |
| `-c, --config FILE` | JSON config file (default: `./config.json` if present) |
| `--duration N` | Stop after N seconds |
| `--stats-interval N` | Seconds between hashrate reports |
| `--idle-timeout N` | Reconnect when the pool is silent for N seconds |
| `--suggest-difficulty N` | Send `mining.suggest_difficulty` after subscribe |
| `--user-agent STRING` | Version string sent to the pool |
| `--seed N` | RNG seed (reproducible nonce start) |
| `--benchmark [N]` | Hash locally for N seconds (default: 30) |
| `--self-test` | Verify hashing, target math and a live mine, then exit |
| `--log-level LEVEL` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `--version` | Print version and exit |
| `-h, --help` | Print help |

Exit codes: `0` success, `1` runtime failure (e.g. self-test failed), `2` usage
or configuration error.

### Examples

```powershell
# solo mining on ckpool (username = your BTC address)
.\dist\btcminer.exe -o stratum+tcp://solo.ckpool.org:3333 `
                    -u bc1....worker1 -p x -t 8

# run for 60 s with per-10 s stats and debug logging
.\dist\btcminer.exe -o pool.example.com:3333 -u user.worker --duration 60 `
                    --stats-interval 10 --log-level DEBUG

# background run, everything (stdout + stderr) to a log file
.\dist\btcminer.exe -o stratum+tcp://solo.ckpool.org:3333 `
                    -u bc1....cpu1 -t 8 *> miner.log
```

## Performance

Test machine: Intel **i5-8365U** (4 cores / 8 threads, **no SHA-NI**, AVX2 +
BMI2), Windows 11, power-limited to ~15 W. Absolute numbers vary with the power
budget and cooling; the scaling is what matters.

| Threads | This miner (AVX2) | Python reference (`legacy/`) | Speed-up |
| --- | --- | --- | --- |
| 1 | 5.9 MH/s | 0.36 MH/s | ~16× |
| 2 | 9.2 MH/s | 0.60 MH/s | ~15× |
| 4 | 13.6 MH/s | 0.81 MH/s | ~17× |
| 8 | 17.7 MH/s (bursts to ~24) | 1.02 MH/s | ~17× |

- A single AVX2 thread reaches ~8 MH/s when the CPU is allowed to boost
  (`build\bench.exe`).
- AVX2 and SMT both help; the default thread count is the logical CPU count.
- The kernel is memory-light and scales close to linearly until the power limit
  is hit.

**SHA-NI.** On CPUs with Intel SHA extensions (Goldmont, Ice Lake and newer;
AMD Zen and newer) the SHA-NI kernel is selected automatically. It runs one
nonce at a time but completes each compression with `SHA256RNDS2` and
`SHA256MSG1`/`SHA256MSG2` instead of the 8-wide AVX2 round loop. This test
machine has no SHA-NI, so no MH/s figure is claimed here; the kernel's output
and the full mining path are verified against the scalar kernel under Intel SDE
(`sde -tgl -- .\build\bench.exe`).

## Testing

```powershell
# 1) known-answer vectors, target math and a short live mine
.\dist\btcminer.exe --self-test

# 2) kernel vectors + per-kernel hashrate (needs .\build.ps1 -Tools)
.\build\bench.exe 8          # argument = millions of nonces

# 3) end-to-end: a fake pool rebuilds every submitted header independently
python tests\fake_pool_check.py

# 4) Python reference test-suite (in legacy/)
cd legacy; python -m unittest discover -v; cd ..
```

What each test covers:

| Test | What it proves |
| --- | --- |
| `--self-test` | Block 125552 hashes to the expected digest (scalar, AVX2 and SHA-NI), difficulty 1/2/0.5 targets are exact, and the worker pool finds and re-verifies real shares |
| `bench.exe` | Every available kernel agrees with the scalar kernel on 4096 random nonces; prints single-thread MH/s per kernel |
| `fake_pool_check.py` | The miner's submitted `(job, extranonce2, ntime, nonce)` really hashes below the pool target, using `hashlib`/`struct` instead of the miner's own code |
| `legacy/tests` | The Python reference implementation still behaves as documented |

`fake_pool_check.py` exits with `RESULT: PASS` and prints a summary such as
`valid shares: 3134 invalid: 0`. A single invalid share fails the test.

## How it works

```
     pool                                    btcminer
       │  mining.subscribe(user_agent)          │
       │◀───────────────────────────────────────│
       │───────────────────────────────────────▶│  [subscriptions, extranonce1, en2_size]
       │  mining.authorize(user, pass)           │
       │───────────────────────────────────────▶│  true
       │  mining.set_difficulty(diff)            │
       │───────────────────────────────────────▶│
       │  mining.notify(job_id, prevhash, coinb1, coinb2,
       │                merkle_branches, version, nbits, ntime, clean)
       │───────────────────────────────────────▶│
       │                                         │  build 76-byte header prefix,
       │                                         │  compress first 64 bytes → midstate
       │                                         │  scan nonces on N threads
       │  mining.submit(user, job_id, en2, ntime, nonce)
       │◀───────────────────────────────────────│
       │───────────────────────────────────────▶│  true / "above target" / "stale"
```

**Header layout (80 bytes).** `version` (LE u32), `prevhash` (32 B), `merkle
root` (32 B), `ntime` (LE u32), `nbits` (LE u32), `nonce` (LE u32).

**Coinbase and merkle root.**

```
coinbase    = coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2
merkle_root = SHA256d(coinbase)
for branch in merkle_branches:
    merkle_root = SHA256d(merkle_root ‖ branch)
```

**Share check.** Hash the header twice with SHA-256, reverse the 32-byte result
(display order) and compare it, as a big-endian integer, against the target.

**Byte-order rules that Stratum gets wrong everywhere.** These were verified
against live `ckpool` jobs and the parent block hash on-chain:

| Field | Handling |
| --- | --- |
| `prevhash` | Reverse the bytes inside each 4-byte word |
| `version`, `nbits`, `ntime` | Parse as hex integers, then store little-endian |
| `coinb1`, `coinb2`, merkle branches | Use the raw decoded bytes |
| `nonce` on submit | `"%08x"` of the 32-bit counter |
| `nonce` inside the header | Little-endian bytes of the counter — so the SHA-256 **block word is the byte-swap of the counter** |
| Comparing hashes | Reverse the 32-byte digest, then compare with the target |

> The last nonce rule is the subtle one: a miner that hashes the counter directly
> will find shares locally and have every one rejected with `above target`. That
> exact bug existed during development and is now covered by
> `tests/fake_pool_check.py`.

**Target math.** `target = floor(0xFFFF × 2²⁰⁸ / difficulty)`, computed with a
53-bit mantissa split and `unsigned __int128` limb division, so no bits are lost
to floating point.

## Repository layout

```
cpp/                    C++17 sources (no third-party code)
  sha256.{h,cpp}        SHA-256, midstate, nonce scan, kernel dispatch
  sha256_avx2.cpp       8-lane AVX2 kernel (compiled with -mavx2)
  sha256_shani.cpp      SHA-NI kernel (compiled with -msha -mssse3 -msse4.1)
  job.{h,cpp}           mining.notify parsing, coinbase/merkle/header assembly
  stratum.{h,cpp}       newline-delimited JSON-RPC over TCP (Winsock2)
  worker.{h,cpp}        thread pool, nonce ranges, share re-verification
  miner.{h,cpp}         session lifecycle, pool messages, submit, statistics
  util.{h,cpp}          hex, 256-bit target math, formatting, logging
  json.{h,cpp}          minimal JSON parser/serializer
  main.cpp              CLI, config file, --self-test, --benchmark
  tools/bench.cpp       kernel vectors + speed benchmark
  tools/check.cpp       dumps target/header for diffing against legacy/
dist/btcminer.exe       prebuilt static executable
tests/fake_pool_check.py  end-to-end validator (fake Stratum pool)
legacy/                 original Python implementation + its tests (reference)
build.ps1               build script (compile, static link, self-test)
config.example.json     configuration template
README.vi.md            Vietnamese version of this document
```

**Threading model.** The main thread owns the socket and the job state. Worker
threads share an immutable `Work` object (midstate + target + submission
metadata) and scan contiguous chunks of 8192 nonces between job checks, so a new
block is picked up within about a millisecond. Each share carries a
`shared_ptr<const Work>`, which guarantees the submitted `job_id`/`extranonce2`
match the midstate that produced it even if a new job arrived meanwhile.

**Kernel dispatch.** CPUID is checked once at startup: SHA-NI if
`CPUID.7.0:EBX.SHA` is set (and SSSE3/SSE4.1 are present), otherwise AVX2, otherwise
the scalar kernel. `--self-test` cross-checks every available kernel against the
scalar one before the miner touches a pool.

**Resilience.** Sessions are re-established with exponential backoff from 2 s to
60 s (reset after a session lasting longer than 120 s). The Stratum client keeps
a backlog so notifications pipelined into the same TCP segment as a response are
handled in arrival order. An idle timeout (default 300 s) forces a reconnect if
the pool goes silent.

## Current feature status

- **TLS support.** `stratum+ssl://` / `stratum+tls://` URLs are accepted and
  validated with Windows SChannel; `--tls-insecure` disables verification for
  trusted test environments.
- **BIP310 version rolling.** When the pool negotiates `version-rolling`, the
  miner sends the configured mask and includes the rolled version in
  `mining.submit` while a mask is active.
- **CPU only.** No GPU/ASIC support; not competitive with dedicated hardware.
- **Single-buffer SHA-NI.** The SHA-NI path interleaves rounds within one nonce
  but does not run several nonces in parallel, so there is still headroom on
  wide cores.
- **Windows only.** The transport layer is Winsock2; the hashing core is
  portable but there is no Linux/macOS build script yet.
- **Solo mining is unrealistic** at this hashrate — expect months of runtime
  without a single accepted share at pool difficulty 10,000.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `pool refused the worker credentials` | Wrong username format; many pools require a valid BTC address |
| `job arrived before the first mining.set_difficulty` | Informational: difficulty 1 is assumed until the pool sends one |
| `no data from pool for 300 s` | Connection stalled or blocked; lower `--idle-timeout` |
| `share rejected: ... stale` | The block changed while the share was in flight — normal |
| `share rejected: low difficulty` | Pool changed difficulty mid-job; the next job uses the new target |
| Every share rejected with `above target` | Byte-order bug (nonce/prevhash/merkle); run `python tests\fake_pool_check.py` |
| No shares at all | Pool difficulty is far above the local hashrate; confirm with `--self-test` |
| `kernel scalar` instead of `sha-ni`/`avx2` in the log | CPU (or VM) lacks SHA-NI/AVX2; still correct, but slower |
| `g++ not found on PATH` | Install MinGW-w64 (WinLibs) and reopen the terminal |
| `build.ps1 cannot be loaded ... running scripts is disabled` | `powershell -ExecutionPolicy Bypass -File .\build.ps1` |
| Antivirus flags the executable | Common false positive for mining binaries; build it yourself or add an exclusion |

## Security

- The miner only sends the user agent, worker name, extranonce2, `ntime` and
  nonce. **Never enter a private key or seed phrase into a miner.**
- The pool password is normally `x` and is not a wallet password.
- Audit the source before running any miner you did not build yourself. This
  repository is small on purpose: ~3,500 lines of C++ with no dependencies.

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Build with `.\build.ps1 -Tools`; the build must stay warning-clean under
   `-Wall -Wextra`.
2. `.\dist\btcminer.exe --self-test` must pass.
3. `python tests\fake_pool_check.py` must print `RESULT: PASS`.
4. Keep the dependency set at zero (C++17 standard library + Winsock2) and match
   the existing style: 4-space indent, `snake_case` functions, `PascalCase`
   types, comments that explain *why*.

Useful contribution ideas: a SHA-NI kernel, BIP310 version rolling, a Linux
build (`kqueue`/`poll` transport), and a CMake option for non-Windows hosts.

## License

Released under the [MIT License](LICENSE).

```
Copyright (c) 2026 btcminer contributors
```

In short: you may use, copy, modify, merge, publish, distribute, sublicense and
sell copies of this software, provided the copyright notice and permission
notice are kept. The software is provided **as is**, without warranty of any
kind.

You are responsible for your electricity costs, your hardware, your
employer's/ISP's rules, and local law when running this software.

## Acknowledgements

- The [Stratum mining protocol](https://en.bitcoin.it/wiki/Stratum_mining_protocol)
  reference on the Bitcoin Wiki.
- [ckpool](https://bitbucket.org/ckolivas/ckpool) (stratum server) and
  [cpuminer-opt](https://github.com/JayDDee/cpuminer-opt) — reference behaviour
  for share validation, byte order and header assembly.
- Block 125552 — the canonical SHA-256d test vector.
- The Python reference implementation in `legacy/`, which the C++ port is
  validated against.
