#include "sha256.h"

#include <cstring>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace sha256 {

const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

namespace {

constexpr uint32_t IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t load_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint32_t bswap32(uint32_t v) {
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}

inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}

// Second SHA-256 pass: the first pass' 32-byte digest (already the block
// words) plus padding.
inline void finish_second(uint32_t s[8], const uint8_t raw[32],
                          uint32_t nonce_unused = 0) {
    (void)nonce_unused;
    uint32_t block[16];
    for (int i = 0; i < 8; ++i) block[i] = load_be32(raw + 4 * i);
    block[8] = 0x80000000u;
    for (int i = 9; i < 15; ++i) block[i] = 0;
    block[15] = 256;
    uint32_t st[8];
    std::memcpy(st, IV, sizeof(st));
    compress(st, block);
    std::memcpy(s, st, sizeof(st));
}

inline void write_raw(const uint32_t st[8], uint8_t raw[32]) {
    for (int i = 0; i < 8; ++i) store_be32(raw + 4 * i, st[i]);
}

}  // namespace

void compress(uint32_t s[8], const uint32_t w[16]) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) W[i] = w[i];
    for (int i = 16; i < 64; ++i) {
        uint32_t x = W[i - 15];
        uint32_t y = W[i - 2];
        uint32_t s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        uint32_t s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
    uint32_t e = s[4], f = s[5], g = s[6], h = s[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

void build_midstate(Midstate& m, const uint8_t header[80]) {
    uint32_t block[16];
    for (int i = 0; i < 16; ++i) block[i] = load_be32(header + 4 * i);
    std::memcpy(m.s, IV, sizeof(m.s));
    compress(m.s, block);
    // Block 2 words: header bytes 64..75 are constant for the job, bytes
    // 76..79 hold the nonce and are supplied per hash.
    m.w[0] = load_be32(header + 64);
    m.w[1] = load_be32(header + 68);
    m.w[2] = load_be32(header + 72);
}

void hash_nonce_scalar(const Midstate& m, uint32_t nonce, uint8_t raw[32]) {
    uint32_t st[8];
    std::memcpy(st, m.s, sizeof(st));

    uint32_t block[16];
    block[0] = m.w[0];
    block[1] = m.w[1];
    block[2] = m.w[2];
    // The nonce argument is the value pools expect in mining.submit (and the
    // one printed in logs).  In the header it is stored little-endian, so the
    // SHA-256 block word is its byte-swapped form.
    block[3] = bswap32(nonce);
    block[4] = 0x80000000u;
    for (int i = 5; i < 15; ++i) block[i] = 0;
    block[15] = 640;  // 80 bytes * 8 bits

    compress(st, block);
    write_raw(st, raw);

    uint32_t out[8];
    finish_second(out, raw);
    write_raw(out, raw);
}

void hash_nonce(const Midstate& m, uint32_t nonce, uint8_t raw[32]) {
    hash_nonce_scalar(m, nonce, raw);
}

void hash_header(const uint8_t header[80], uint8_t raw[32]) {
    Midstate m;
    build_midstate(m, header);
    // Header bytes 76..79 store the nonce little-endian; recover the counter
    // value that mining.submit expects.
    uint32_t nonce = bswap32(load_be32(header + 76));
    hash_nonce(m, nonce, raw);
}

void digest(const uint8_t* data, size_t size, uint8_t raw[32]) {
    uint32_t st[8];
    std::memcpy(st, IV, sizeof(st));

    size_t offset = 0;
    while (size - offset >= 64) {
        uint32_t block[16];
        for (int i = 0; i < 16; ++i) block[i] = load_be32(data + offset + 4 * i);
        compress(st, block);
        offset += 64;
    }

    uint8_t tail[128];
    std::memset(tail, 0, sizeof(tail));
    size_t rest = size - offset;
    if (rest) std::memcpy(tail, data + offset, rest);
    tail[rest] = 0x80;

    size_t total = (rest < 56) ? 64 : 128;
    uint64_t bits = uint64_t(size) * 8;
    for (int i = 0; i < 8; ++i) {
        tail[total - 1 - i] = uint8_t(bits >> (8 * i));
    }
    for (size_t block_start = 0; block_start < total; block_start += 64) {
        uint32_t block[16];
        for (int i = 0; i < 16; ++i) {
            block[i] = load_be32(tail + block_start + 4 * i);
        }
        compress(st, block);
    }
    write_raw(st, raw);
}

void digest2(const uint8_t* data, size_t size, uint8_t raw[32]) {
    uint8_t first[32];
    digest(data, size, first);
    digest(first, 32, raw);
}

// ---------------------------------------------------------------------------
// capability detection
// ---------------------------------------------------------------------------
namespace {

bool detect_avx2() {
#if defined(_MSC_VER)
    int regs[4];
    __cpuid(regs, 0);
    if (regs[0] < 7) return false;
    __cpuidex(regs, 1, 0);
    if (!(regs[2] & (1 << 27))) return false;  // OSXSAVE
    if (!(regs[2] & (1 << 28))) return false;  // AVX
    __cpuidex(regs, 7, 0);
    return (regs[1] & (1 << 5)) != 0;          // AVX2
#else
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid_max(0, nullptr)) return false;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
    if (!(ecx & (1u << 27)) || !(ecx & (1u << 28))) return false;
    if (__get_cpuid_max(0, nullptr) < 7) return false;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1u << 5)) != 0;
#endif
}

const bool kHasAvx2 = detect_avx2();

bool detect_sha_ni() {
#if defined(_MSC_VER)
    int regs[4];
    __cpuid(regs, 1);
    if (!(regs[2] & (1 << 9))) return false;   // SSSE3
    if (!(regs[2] & (1 << 19))) return false;  // SSE4.1
    __cpuid(regs, 0);
    if (regs[0] < 7) return false;
    __cpuidex(regs, 7, 0);
    return (regs[1] & (1 << 29)) != 0;         // SHA
#else
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
    if (!(ecx & (1u << 9)) || !(ecx & (1u << 19))) return false;
    if (__get_cpuid_max(0, nullptr) < 7) return false;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1u << 29)) != 0;
#endif
}

const bool kHasShaNi = detect_sha_ni();

}  // namespace

bool has_avx2() { return kHasAvx2; }

bool avx2_available() { return kHasAvx2; }

bool has_sha_ni() { return kHasShaNi; }

const char* kernel_name() {
    if (kHasShaNi) return "sha-ni";
    return kHasAvx2 ? "avx2 (8 lanes)" : "scalar";
}

int scan(const Midstate& m, uint32_t start, uint32_t count,
         const uint8_t target_be[32], uint32_t* nonces,
         uint8_t (*digests)[32], int max_out) {
    if (kHasShaNi) {
        return scan_sha_ni(m, start, count, target_be, nonces, digests, max_out);
    }
    if (kHasAvx2) {
        return scan_avx2(m, start, count, target_be, nonces, digests, max_out);
    }
    return scan_scalar(m, start, count, target_be, nonces, digests, max_out);
}

int scan_scalar(const Midstate& m, uint32_t start, uint32_t count,
                const uint8_t target_be[32], uint32_t* nonces,
                uint8_t (*digests)[32], int max_out) {
    int found = 0;
    uint8_t raw[32];
    uint8_t be[32];
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t nonce = start + i;
        hash_nonce_scalar(m, nonce, raw);
        for (int j = 0; j < 32; ++j) be[j] = raw[31 - j];
        if (std::memcmp(be, target_be, 32) <= 0) {
            if (nonces) nonces[found] = nonce;
            if (digests) std::memcpy(digests[found], be, 32);
            if (++found >= max_out) break;
        }
    }
    return found;
}

}  // namespace sha256
