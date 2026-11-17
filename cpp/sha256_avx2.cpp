// AVX2 SHA-256d kernel: hashes 8 consecutive nonces in parallel.
//
// This translation unit is compiled with -mavx2 and is only called after a
// runtime CPUID check (see sha256::has_avx2()).
#include <immintrin.h>

#include <cstring>

#include "sha256.h"

namespace sha256 {
namespace {

inline __m256i ror32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_srli_epi32(x, n),
                           _mm256_slli_epi32(x, 32 - n));
}

#define XOR3(a, b, c) \
    _mm256_xor_si256(_mm256_xor_si256((a), (b)), (c))
#define ADD4(a, b, c, d) \
    _mm256_add_epi32(_mm256_add_epi32((a), (b)), _mm256_add_epi32((c), (d)))

// One SHA-256 compression for 8 independent messages.
inline void compress8(__m256i h[8], const __m256i in[16]) {
    __m256i w[64];
    for (int i = 0; i < 16; ++i) w[i] = in[i];
    for (int i = 16; i < 64; ++i) {
        __m256i s0 = XOR3(ror32(w[i - 15], 7), ror32(w[i - 15], 18),
                          _mm256_srli_epi32(w[i - 15], 3));
        __m256i s1 = XOR3(ror32(w[i - 2], 17), ror32(w[i - 2], 19),
                          _mm256_srli_epi32(w[i - 2], 10));
        w[i] = ADD4(w[i - 16], s0, w[i - 7], s1);
    }

    __m256i a = h[0], b = h[1], c = h[2], d = h[3];
    __m256i e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; ++i) {
        __m256i S1 = XOR3(ror32(e, 6), ror32(e, 11), ror32(e, 25));
        __m256i ch = _mm256_xor_si256(_mm256_and_si256(e, f),
                                      _mm256_andnot_si256(e, g));
        __m256i t1 = ADD4(hh, S1, ch, w[i]);
        t1 = _mm256_add_epi32(t1, _mm256_set1_epi32(int(K[i])));
        __m256i S0 = XOR3(ror32(a, 2), ror32(a, 13), ror32(a, 22));
        __m256i maj = XOR3(_mm256_and_si256(a, b), _mm256_and_si256(a, c),
                           _mm256_and_si256(b, c));
        __m256i t2 = _mm256_add_epi32(S0, maj);

        hh = g;
        g = f;
        f = e;
        e = _mm256_add_epi32(d, t1);
        d = c;
        c = b;
        b = a;
        a = _mm256_add_epi32(t1, t2);
    }

    h[0] = _mm256_add_epi32(h[0], a);
    h[1] = _mm256_add_epi32(h[1], b);
    h[2] = _mm256_add_epi32(h[2], c);
    h[3] = _mm256_add_epi32(h[3], d);
    h[4] = _mm256_add_epi32(h[4], e);
    h[5] = _mm256_add_epi32(h[5], f);
    h[6] = _mm256_add_epi32(h[6], g);
    h[7] = _mm256_add_epi32(h[7], hh);
}

const uint32_t IV_SCALAR[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline __m256i set1(uint32_t v) { return _mm256_set1_epi32(int(v)); }

inline int bswap32(uint32_t v) { return int(__builtin_bswap32(v)); }

}  // namespace

bool hash8_avx2(const Midstate& m, uint32_t start, uint8_t digests[8][32]) {
    __m256i h[8];
    for (int i = 0; i < 8; ++i) h[i] = set1(m.s[i]);

    // Block 2: 3 fixed words, the per-lane nonce, padding and bit length.
    __m256i block[16];
    block[0] = set1(m.w[0]);
    block[1] = set1(m.w[1]);
    block[2] = set1(m.w[2]);
    block[3] = _mm256_setr_epi32(
        bswap32(start + 0), bswap32(start + 1), bswap32(start + 2),
        bswap32(start + 3), bswap32(start + 4), bswap32(start + 5),
        bswap32(start + 6), bswap32(start + 7));
    block[4] = set1(0x80000000u);
    for (int i = 5; i < 15; ++i) block[i] = _mm256_setzero_si256();
    block[15] = set1(640);

    compress8(h, block);

    // Second SHA-256 pass: digest already contains the block words.
    __m256i block2[16];
    for (int i = 0; i < 8; ++i) block2[i] = h[i];
    block2[8] = set1(0x80000000u);
    for (int i = 9; i < 15; ++i) block2[i] = _mm256_setzero_si256();
    block2[15] = set1(256);

    __m256i h2[8];
    for (int i = 0; i < 8; ++i) h2[i] = set1(IV_SCALAR[i]);
    compress8(h2, block2);

    alignas(32) uint32_t words[8][8];
    for (int k = 0; k < 8; ++k) {
        _mm256_store_si256(reinterpret_cast<__m256i*>(words[k]), h2[k]);
    }
    // Displayed (big-endian) digest = reverse of the 32 output bytes, i.e.
    // the state words h7..h0 written little-endian.
    for (int lane = 0; lane < 8; ++lane) {
        for (int k = 0; k < 8; ++k) {
            uint32_t v = words[7 - k][lane];
            digests[lane][4 * k + 0] = uint8_t(v);
            digests[lane][4 * k + 1] = uint8_t(v >> 8);
            digests[lane][4 * k + 2] = uint8_t(v >> 16);
            digests[lane][4 * k + 3] = uint8_t(v >> 24);
        }
    }
    return true;
}

int scan_avx2(const Midstate& m, uint32_t start, uint32_t count,
              const uint8_t target_be[32], uint32_t* nonces,
              uint8_t (*digests)[32], int max_out) {
    int found = 0;
    alignas(32) uint8_t out[8][32];
    uint32_t done = 0;
    while (done + 8 <= count) {
        hash8_avx2(m, start + done, out);
        for (int lane = 0; lane < 8; ++lane) {
            if (std::memcmp(out[lane], target_be, 32) <= 0) {
                if (nonces) nonces[found] = start + done + uint32_t(lane);
                if (digests) std::memcpy(digests[found], out[lane], 32);
                if (++found >= max_out) return found;
            }
        }
        done += 8;
    }
    // Tail (count is normally a multiple of 8; be safe anyway).
    if (done < count) {
        found += scan_scalar(m, start + done, count - done, target_be,
                             nonces ? nonces + found : nullptr,
                             digests ? digests + found : nullptr,
                             max_out - found);
    }
    return found;
}

}  // namespace sha256
