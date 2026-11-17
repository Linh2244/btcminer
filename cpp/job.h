// Stratum job parsing and block header assembly.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "json.h"
#include "sha256.h"

struct Job {
    std::string id;
    std::vector<uint8_t> prevhash;  // 32 bytes, already word-swapped
    std::vector<uint8_t> coinb1;
    std::vector<uint8_t> coinb2;
    std::vector<std::array<uint8_t, 32>> branches;
    uint32_t version = 0;
    uint32_t nbits = 0;
    uint32_t ntime = 0;
    std::string ntime_hex;
    bool clean = true;
    std::vector<uint8_t> extranonce1;
    size_t extranonce2_size = 0;
};

// Decodes the parameter list of a mining.notify notification.
bool parse_notify(const Json& params, const std::vector<uint8_t>& extranonce1,
                  size_t extranonce2_size, Job& job, std::string& error);

// 76-byte header prefix (the nonce lives in the last 4 bytes).
void build_header_prefix(const Job& job, const std::vector<uint8_t>& extranonce2,
                         uint8_t header[76]);

// Splits a job+extranonce2 into the reusable mining midstate.
void make_midstate(const Job& job, const std::vector<uint8_t>& extranonce2,
                   sha256::Midstate& mid);

// Writes a version into the first four bytes of an 80-byte header.
void set_header_version(uint8_t header[80], uint32_t version);

// Spreads the low bits of `value` over the set bits of `mask` (BIP310
// version rolling).  Bits of `value` above the mask population are dropped.
uint32_t deposit_bits(uint32_t value, uint32_t mask);

// Reverses the bytes inside every 4-byte word (stratum prevhash encoding).
std::vector<uint8_t> word_swap(const std::vector<uint8_t>& data);
