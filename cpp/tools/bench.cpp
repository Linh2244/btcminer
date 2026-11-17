// Standalone kernel test/benchmark (not part of the miner executable).
//
//   bench.exe [Mnonces]
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../sha256.h"

namespace {

const char* HEADER_HEX =
    "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
    "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
    "c7f5d74df2b9441a42a14695";
const char* EXPECTED =
    "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d";

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool from_hex(const char* s, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = uint8_t(hi << 4 | lo);
    }
    return true;
}

void to_hex(const uint8_t* p, size_t n, char* out) {
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = 0;
}

void show_digest(const uint8_t raw[32], char* out) {
    uint8_t be[32];
    for (int i = 0; i < 32; ++i) be[i] = raw[31 - i];
    to_hex(be, 32, out);
}

uint32_t header_nonce(const uint8_t header[80]) {
    // The header stores the nonce little-endian; the counter that
    // mining.submit expects is its byte-swapped value.
    return uint32_t(header[76]) | (uint32_t(header[77]) << 8) |
           (uint32_t(header[78]) << 16) | (uint32_t(header[79]) << 24);
}

double measure(sha256::Midstate& mid, uint64_t total, bool shani) {
    uint8_t target[32];
    std::memset(target, 0, sizeof(target));  // impossible: never matches

    uint64_t done = 0;
    uint32_t n = 0;
    auto t0 = std::chrono::steady_clock::now();
    while (done < total) {
        uint32_t cnt = uint32_t(std::min<uint64_t>(65536, total - done));
        if (shani) {
            sha256::scan_sha_ni(mid, n, cnt, target, nullptr, nullptr, 0);
        } else {
            sha256::scan_avx2(mid, n, cnt, target, nullptr, nullptr, 0);
        }
        n += cnt;
        done += cnt;
    }
    auto t1 = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t1 - t0).count();
    std::printf("  %s speed          : %.2f MH/s (%.0f ms for %llu hashes)\n",
                shani ? "sha-ni" : "avx2", done / secs / 1e6, secs * 1000,
                (unsigned long long)done);
    return done / secs / 1e6;
}

}  // namespace

int main(int argc, char** argv) {
    double mnonces = argc > 1 ? std::atof(argv[1]) : 8.0;

    uint8_t header[80];
    if (!from_hex(HEADER_HEX, header, 80)) {
        std::printf("bad header hex\n");
        return 2;
    }

    sha256::Midstate mid;
    sha256::build_midstate(mid, header);

    char hex[65];
    uint8_t raw[32];
    sha256::hash_header(header, raw);
    show_digest(raw, hex);
    bool scalar_ok = std::strcmp(hex, EXPECTED) == 0;
    std::printf("scalar block 125552 : %s %s\n", hex,
                scalar_ok ? "OK" : "FAIL");

    uint64_t total = uint64_t(mnonces * 1000000.0);
    bool ok = scalar_ok;
    const uint32_t nonce = header_nonce(header);

    if (sha256::has_avx2()) {
        uint8_t avx[8][32];
        sha256::hash8_avx2(mid, nonce & ~7u, avx);
        to_hex(avx[nonce & 7], 32, hex);
        bool avx_ok = std::strcmp(hex, EXPECTED) == 0;
        std::printf("avx2   block 125552 : %s %s\n", hex,
                    avx_ok ? "OK" : "FAIL");
        ok = ok && avx_ok;

        // Cross-check against the scalar kernel on pseudo-random nonces.
        int mismatches = 0;
        uint32_t seed = 0x12345678u;
        uint8_t be[32];
        for (int i = 0; i < 4096; i += 8) {
            seed = seed * 1103515245u + 12345u;
            uint32_t base = seed;
            sha256::hash8_avx2(mid, base, avx);
            for (int lane = 0; lane < 8; ++lane) {
                uint8_t sraw[32];
                sha256::hash_nonce_scalar(mid, base + lane, sraw);
                for (int j = 0; j < 32; ++j) be[j] = sraw[31 - j];
                if (std::memcmp(be, avx[lane], 32) != 0) ++mismatches;
            }
        }
        std::printf("avx2 vs scalar      : %d mismatch(es) / 4096\n", mismatches);
        ok = ok && mismatches == 0;
        measure(mid, total, false);
    } else {
        std::printf("avx2                : not available on this CPU\n");
    }

    if (sha256::has_sha_ni()) {
        uint8_t sraw[32];
        sha256::hash_nonce_sha_ni(mid, nonce, sraw);
        show_digest(sraw, hex);
        bool ni_ok = std::strcmp(hex, EXPECTED) == 0;
        std::printf("sha-ni block 125552 : %s %s\n", hex,
                    ni_ok ? "OK" : "FAIL");
        ok = ok && ni_ok;

        int mismatches = 0;
        uint32_t seed = 0x9e3779b9u;
        for (int i = 0; i < 4096; ++i) {
            seed = seed * 1103515245u + 12345u;
            uint8_t s1[32], s2[32];
            sha256::hash_nonce_scalar(mid, seed, s1);
            sha256::hash_nonce_sha_ni(mid, seed, s2);
            if (std::memcmp(s1, s2, 32) != 0) ++mismatches;
        }
        std::printf("sha-ni vs scalar    : %d mismatch(es) / 4096\n", mismatches);
        ok = ok && mismatches == 0;
        measure(mid, total, true);
    } else {
        std::printf("sha-ni              : not available on this CPU\n");
    }

    std::printf("kernel selected     : %s\n", sha256::kernel_name());
    std::printf("%s\n", ok ? "KERNEL OK" : "KERNEL FAILED");
    return ok ? 0 : 1;
}
