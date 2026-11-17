// SHA-NI (Intel SHA extensions) kernel: one nonce at a time.
//
// This translation unit is compiled with -msha -mssse3 -msse4.1 and is only
// called after has_sha_ni() reported support.
//
// The round layout and the SHA256MSG1/SHA256MSG2 message schedule follow the
// public-domain reference "sha256-x86.c" by Jeffrey Walton (itself based on
// Intel and miTLS code), rewritten here as a compile-time-unrolled loop.
#include <immintrin.h>

#include <cstring>

#include "sha256.h"

namespace sha256 {
namespace {

constexpr uint32_t IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}

inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

// One group of four rounds.  G is the 4-round group index (0..15); making it a
// template parameter keeps the message-schedule registers in XMM registers
// instead of spilling them to the stack.
template <int G>
__attribute__((always_inline)) inline void round_group(__m128i& s0,
                                                       __m128i& s1,
                                                       __m128i (&r)[4]) {
    constexpr int cur = G & 3;
    constexpr int prev = (G + 3) & 3;
    constexpr int next = (G + 1) & 3;

    // WK = W[4G..4G+3] + K[4G..4G+3]; SHA256RNDS2 consumes two of them at a
    // time, so the second half is shuffled into the low dwords afterwards.
    __m128i wk = _mm_add_epi32(
        r[cur],
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(K + 4 * G)));
    s1 = _mm_sha256rnds2_epu32(s1, s0, wk);
    wk = _mm_shuffle_epi32(wk, 0x0E);
    s0 = _mm_sha256rnds2_epu32(s0, s1, wk);

    // Finalise the schedule word group 4 rounds ahead (W[4G+16..4G+19]).
    if constexpr (G >= 3 && G <= 14) {
        r[next] = _mm_add_epi32(r[next], _mm_alignr_epi8(r[cur], r[prev], 4));
        r[next] = _mm_sha256msg2_epu32(r[next], r[cur]);
    }
    // Prepare the partial schedule 16 rounds ahead (sigma0 of W[4G+1..4G+4]).
    if constexpr (G >= 1 && G <= 12) {
        r[prev] = _mm_sha256msg1_epu32(r[prev], r[cur]);
    }

    if constexpr (G < 15) {
        round_group<G + 1>(s0, s1, r);
    }
}

// Compresses one 64-byte block into `state` (words are big-endian message
// words, as in the regular SHA-256 compression function).
__attribute__((always_inline)) inline void compress_block(uint32_t state[8],
                                                          const uint8_t block[64]) {
    __m128i lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state));
    __m128i hi = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 4));

    // Repack the state as SHA-NI expects it: STATE0 = A,B,E,F and
    // STATE1 = C,D,G,H (from the high dword down).
    const __m128i swapped = _mm_shuffle_epi32(lo, 0xB1); /* CDAB */
    hi = _mm_shuffle_epi32(hi, 0x1B);                    /* HGFE */
    __m128i s0 = _mm_alignr_epi8(swapped, hi, 8);        /* ABEF */
    __m128i s1 = _mm_blend_epi16(hi, swapped, 0xF0);     /* CDGH */

    const __m128i abef_save = s0;
    const __m128i cdgh_save = s1;

    const __m128i mask =
        _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    __m128i r[4];
    r[0] = _mm_shuffle_epi8(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 0)), mask);
    r[1] = _mm_shuffle_epi8(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 16)), mask);
    r[2] = _mm_shuffle_epi8(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 32)), mask);
    r[3] = _mm_shuffle_epi8(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 48)), mask);

    round_group<0>(s0, s1, r);

    s0 = _mm_add_epi32(s0, abef_save);
    s1 = _mm_add_epi32(s1, cdgh_save);

    const __m128i fb = _mm_shuffle_epi32(s0, 0x1B); /* FEBA */
    s1 = _mm_shuffle_epi32(s1, 0xB1);               /* DCHG */
    s0 = _mm_blend_epi16(fb, s1, 0xF0);             /* DCBA */
    s1 = _mm_alignr_epi8(s1, fb, 8);                /* HGFE */

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state), s0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 4), s1);
}

// Double SHA-256 of the header with `nonce`, producing the digest in display
// (big-endian) order, which is what pools compare against the target.
inline void hash_display(const Midstate& m, uint32_t nonce, uint8_t out[32]) {
    // First pass, block 2: 3 fixed words, the little-endian nonce, padding
    // and the 640-bit length.
    alignas(16) uint8_t block[64];
    store_be32(block + 0, m.w[0]);
    store_be32(block + 4, m.w[1]);
    store_be32(block + 8, m.w[2]);
    block[12] = uint8_t(nonce);
    block[13] = uint8_t(nonce >> 8);
    block[14] = uint8_t(nonce >> 16);
    block[15] = uint8_t(nonce >> 24);
    block[16] = 0x80;
    std::memset(block + 17, 0, 47);
    block[62] = 0x02;
    block[63] = 0x80;

    uint32_t st[8];
    std::memcpy(st, m.s, sizeof(st));
    compress_block(st, block);

    // Second pass: the 32-byte digest plus padding form a single block.
    alignas(16) uint8_t second[64];
    for (int i = 0; i < 8; ++i) store_be32(second + 4 * i, st[i]);
    second[32] = 0x80;
    std::memset(second + 33, 0, 31);
    second[62] = 0x01;  // 256 bits, big-endian
    second[63] = 0x00;

    uint32_t st2[8];
    std::memcpy(st2, IV, sizeof(st2));
    compress_block(st2, second);

    // Display order is the reverse of the wire order: h7 down to h0, each
    // word stored little-endian (equivalent to reversing the 32 raw bytes).
    for (int k = 0; k < 8; ++k) store_le32(out + 4 * k, st2[7 - k]);
}

}  // namespace

bool sha_ni_available() { return has_sha_ni(); }

void hash_nonce_sha_ni(const Midstate& m, uint32_t nonce, uint8_t raw[32]) {
    uint8_t display[32];
    hash_display(m, nonce, display);
    for (int i = 0; i < 32; ++i) raw[i] = display[31 - i];
}

int scan_sha_ni(const Midstate& m, uint32_t start, uint32_t count,
                const uint8_t target_be[32], uint32_t* nonces,
                uint8_t (*digests)[32], int max_out) {
    int found = 0;
    alignas(16) uint8_t digest[32];
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t nonce = start + i;
        hash_display(m, nonce, digest);
        if (std::memcmp(digest, target_be, 32) <= 0) {
            if (nonces) nonces[found] = nonce;
            if (digests) std::memcpy(digests[found], digest, 32);
            if (++found >= max_out) break;
        }
    }
    return found;
}

}  // namespace sha256
