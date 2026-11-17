// SHA-256d core for Bitcoin header hashing.
//
// The 80-byte header is hashed in two SHA-256 passes.  The first 64 bytes of
// the header never change while a job is mined, so their compression result
// ("midstate") is computed once per job.  Each nonce then only needs:
//
//   1. one compression of block 2 (last 4 bytes of the merkle root, ntime,
//      nbits, nonce + padding), and
//   2. one compression of the 32-byte result (second SHA-256 pass).
//
// Two kernels are provided:
//   * a portable scalar one (always available), and
//   * an AVX2 one hashing 8 nonces in parallel (used when the CPU supports it).
#pragma once

#include <cstddef>
#include <cstdint>

namespace sha256 {

extern const uint32_t K[64];

struct Midstate {
    uint32_t s[8];  // state after the first 64-byte header block
    uint32_t w[3];  // block-2 words 0..2 (header bytes 64..75);
                    // word 3 is the nonce and is supplied per hash
};

// SHA-256 compression function.
void compress(uint32_t state[8], const uint32_t block[16]);

// Splits an 80-byte block header into the reusable midstate.
void build_midstate(Midstate& m, const uint8_t header[80]);

// Hashes a single nonce.  `raw` receives the 32-byte digest in wire order
// (i.e. the reverse of the hex string displayed by explorers/pools).
void hash_nonce(const Midstate& m, uint32_t nonce, uint8_t raw[32]);

// Convenience helper: hashes a complete 80-byte header (nonce taken from the
// last 4 bytes).  `raw` is in wire order.
void hash_header(const uint8_t header[80], uint8_t raw[32]);

// Generic SHA-256 / double SHA-256 of an arbitrary buffer (used for the
// coinbase and merkle branches).  `raw` is in wire order.
void digest(const uint8_t* data, size_t size, uint8_t raw[32]);
void digest2(const uint8_t* data, size_t size, uint8_t raw[32]);

// AVX2 capability of the running CPU (checked once).
bool has_avx2();

// Human readable name of the kernel that scan() uses.
const char* kernel_name();

// Scans `count` consecutive nonces starting at `start` (wrapping is the
// caller's job).  Every nonce whose big-endian digest is <= target_be is
// appended to `nonces`/`digests` (at most `max_out`).  Returns how many were
// found.  `digests` may be null.
int scan(const Midstate& m, uint32_t start, uint32_t count,
         const uint8_t target_be[32], uint32_t* nonces,
         uint8_t (*digests)[32], int max_out);

// Scalar-only variants, used by tests and by the self-test.
void hash_nonce_scalar(const Midstate& m, uint32_t nonce, uint8_t raw[32]);
int scan_scalar(const Midstate& m, uint32_t start, uint32_t count,
                const uint8_t target_be[32], uint32_t* nonces,
                uint8_t (*digests)[32], int max_out);

// 8-lane AVX2 kernel (defined in sha256_avx2.cpp).  Returns false when the
// CPU cannot run it.
bool avx2_available();
int scan_avx2(const Midstate& m, uint32_t start, uint32_t count,
              const uint8_t target_be[32], uint32_t* nonces,
              uint8_t (*digests)[32], int max_out);

// Internal: hashes 8 consecutive nonces with the AVX2 kernel.  `digests`
// receives 8 big-endian 32-byte digests.
bool hash8_avx2(const Midstate& m, uint32_t start, uint8_t digests[8][32]);

}  // namespace sha256
