// Debug tool: prints target math and a header built from a real ckpool job so
// the output can be diffed against the Python implementation.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../job.h"
#include "../json.h"
#include "../sha256.h"
#include "../util.h"

namespace {

// mining.notify captured from solo.ckpool.org (block height 976725).
const char* kParams = R"JSON([
    "6ae40f5a0000d3a1",
    "a461c910f70acbd25a6d639f971fcc7682486e5400004d9a0000000000000000",
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff360355e50e0004d5c2fb6a032c2e590c",
    "0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe031dea4112000000001976a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888acd1625f000000000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24aa21a9ed67d7289be2e77bf3b6ca77f25f935192ce1b5c38eaacd309adbcc8b457c52e4454e50e00",
    [
        "27c65dfc7456846c34a94841441975c5920c51690efedeab9f4e90c2aec77def",
        "142c6597b19d5a91e31d656e7b55e1ab45fe6d21b56366eac76f2b5a4d2f1ed7",
        "efe428e3daad508f5dfcb271a67dc5f2b07c031a63c9f008b8ceda722950923c",
        "0fed01d3cec710d96ffda5f4296904ec71f52e13324ebf165fef83396c4602c8",
        "c942275e942d05577c938de14387b03d9d84cb30353ae71b4d410232449180c3",
        "191c8085cd5128b1f4f9a5c7675d7c9111afe28290478d4de5203ed4b304061c"
    ],
    "20000000",
    "17021673",
    "6afbc2d5",
    true
])JSON";

}  // namespace

int main() {
    for (double difficulty : {1.0, 1e-5, 10000.0, 0.5}) {
        uint8_t target[32];
        util::difficulty_to_target(difficulty, target);
        std::printf("target %g = %s\n", difficulty,
                    util::hex_encode(target, 32).c_str());
    }

    std::string error;
    Json params = Json::parse(kParams, &error);
    if (!error.empty()) {
        std::printf("json error: %s\n", error.c_str());
        return 1;
    }

    std::vector<uint8_t> extranonce1;
    util::hex_decode("bd4c926e", extranonce1, 4, nullptr);
    Job job;
    if (!parse_notify(params, extranonce1, 8, job, error)) {
        std::printf("notify error: %s\n", error.c_str());
        return 1;
    }
    std::printf("prevhash = %s\n", util::hex_encode(job.prevhash).c_str());

    std::vector<uint8_t> extranonce2;
    util::hex_decode("0011223344556677", extranonce2, 8, nullptr);
    uint8_t header[76];
    build_header_prefix(job, extranonce2, header);
    std::printf("header   = %s\n", util::hex_encode(header, 76).c_str());

    uint8_t full[80];
    std::memcpy(full, header, 76);
    uint8_t nonce[4] = {0x78, 0x56, 0x34, 0x12};  // little endian 0x12345678
    std::memcpy(full + 76, nonce, 4);
    uint8_t raw[32];
    uint8_t display[32];
    sha256::hash_header(full, raw);
    for (int i = 0; i < 32; ++i) display[i] = raw[31 - i];
    std::printf("hash1234 = %s\n", util::hex_encode(display, 32).c_str());
    return 0;
}
