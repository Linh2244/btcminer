#include "job.h"

#include <cstdio>
#include <cstring>

#include "util.h"

namespace {

bool parse_hex_field(const Json& value, const char* name, size_t expected_size,
                     std::vector<uint8_t>& out, std::string& error) {
    if (!value.is_string()) {
        error = std::string(name) + " must be a hex string";
        return false;
    }
    std::string detail;
    if (!util::hex_decode(value.as_string(), out, expected_size, &detail)) {
        error = std::string(name) + ": " + detail;
        return false;
    }
    return true;
}

bool parse_int_field(const Json& value, const char* name, uint32_t& out,
                     std::string& error) {
    if (value.is_number()) {
        long long v = value.as_int(-1);
        if (v < 0 || v > 0xffffffffLL) {
            error = std::string(name) + " is out of range";
            return false;
        }
        out = uint32_t(v);
        return true;
    }
    if (!value.is_string() || value.as_string().empty()) {
        error = std::string(name) + " must be a hex integer";
        return false;
    }
    unsigned long long parsed = 0;
    const std::string& text = value.as_string();
    for (char c : text) {
        int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else {
            error = std::string(name) + " is not valid hex";
            return false;
        }
        parsed = parsed * 16 + unsigned(digit);
        if (parsed > 0xffffffffULL) {
            error = std::string(name) + " does not fit in 32 bits";
            return false;
        }
    }
    out = uint32_t(parsed);
    return true;
}

inline void put_le32(uint8_t* out, uint32_t value) {
    out[0] = uint8_t(value);
    out[1] = uint8_t(value >> 8);
    out[2] = uint8_t(value >> 16);
    out[3] = uint8_t(value >> 24);
}

}  // namespace

std::vector<uint8_t> word_swap(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); i += 4) {
        out[i + 0] = data[i + 3];
        out[i + 1] = data[i + 2];
        out[i + 2] = data[i + 1];
        out[i + 3] = data[i + 0];
    }
    return out;
}

bool parse_notify(const Json& params, const std::vector<uint8_t>& extranonce1,
                  size_t extranonce2_size, Job& job, std::string& error) {
    if (!params.is_array() || params.size() < 8) {
        error = "mining.notify needs at least 8 parameters";
        return false;
    }
    if (!params[0].is_string()) {
        error = "job id must be a string";
        return false;
    }
    if (extranonce2_size > 32) {
        error = "unsupported extranonce2 size";
        return false;
    }

    Job parsed;
    parsed.id = params[0].as_string();

    std::vector<uint8_t> prevhash;
    if (!parse_hex_field(params[1], "prevhash", 32, prevhash, error)) return false;
    parsed.prevhash = word_swap(prevhash);

    if (!parse_hex_field(params[2], "coinb1", std::string::npos, parsed.coinb1, error)) {
        return false;
    }
    if (!parse_hex_field(params[3], "coinb2", std::string::npos, parsed.coinb2, error)) {
        return false;
    }

    const Json& branches = params[4];
    if (!branches.is_null() && !branches.is_array()) {
        error = "merkle branches must be a list";
        return false;
    }
    if (branches.is_array()) {
        for (size_t i = 0; i < branches.size(); ++i) {
            std::vector<uint8_t> branch;
            if (!parse_hex_field(branches[i], "merkle branch", 32, branch, error)) {
                return false;
            }
            std::array<uint8_t, 32> fixed;
            std::memcpy(fixed.data(), branch.data(), 32);
            parsed.branches.push_back(fixed);
        }
    }

    if (!parse_int_field(params[5], "version", parsed.version, error)) return false;
    if (!parse_int_field(params[6], "nbits", parsed.nbits, error)) return false;
    if (!parse_int_field(params[7], "ntime", parsed.ntime, error)) return false;
    if (params.size() > 8) parsed.clean = params[8].as_bool(true);
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%08x", (unsigned)parsed.ntime);
    parsed.ntime_hex = buf;

    parsed.extranonce1 = extranonce1;
    parsed.extranonce2_size = extranonce2_size;
    job = std::move(parsed);
    return true;
}

namespace {

std::vector<uint8_t> build_coinbase(const Job& job,
                                    const std::vector<uint8_t>& extranonce2) {
    std::vector<uint8_t> coinbase;
    coinbase.reserve(job.coinb1.size() + job.extranonce1.size() +
                     extranonce2.size() + job.coinb2.size());
    coinbase.insert(coinbase.end(), job.coinb1.begin(), job.coinb1.end());
    coinbase.insert(coinbase.end(), job.extranonce1.begin(), job.extranonce1.end());
    coinbase.insert(coinbase.end(), extranonce2.begin(), extranonce2.end());
    coinbase.insert(coinbase.end(), job.coinb2.begin(), job.coinb2.end());
    return coinbase;
}

std::array<uint8_t, 32> merkle_root(const Job& job,
                                    const std::vector<uint8_t>& extranonce2) {
    std::vector<uint8_t> coinbase = build_coinbase(job, extranonce2);
    std::array<uint8_t, 32> root;
    sha256::digest2(coinbase.data(), coinbase.size(), root.data());

    std::vector<uint8_t> buffer(64);
    for (const auto& branch : job.branches) {
        std::memcpy(buffer.data(), root.data(), 32);
        std::memcpy(buffer.data() + 32, branch.data(), 32);
        sha256::digest2(buffer.data(), 64, root.data());
    }
    return root;
}

}  // namespace

void build_header_prefix(const Job& job, const std::vector<uint8_t>& extranonce2,
                         uint8_t header[76]) {
    put_le32(header + 0, job.version);
    std::memcpy(header + 4, job.prevhash.data(), 32);
    std::array<uint8_t, 32> root = merkle_root(job, extranonce2);
    std::memcpy(header + 36, root.data(), 32);
    put_le32(header + 68, job.ntime);
    put_le32(header + 72, job.nbits);
}

void make_midstate(const Job& job, const std::vector<uint8_t>& extranonce2,
                   sha256::Midstate& mid) {
    uint8_t header[76];
    build_header_prefix(job, extranonce2, header);
    uint8_t full[80];
    std::memcpy(full, header, 76);
    std::memset(full + 76, 0, 4);
    sha256::build_midstate(mid, full);
}

void set_header_version(uint8_t header[80], uint32_t version) {
    put_le32(header, version);
}

uint32_t deposit_bits(uint32_t value, uint32_t mask) {
    uint32_t result = 0;
    uint32_t source = 1;
    for (int bit = 0; bit < 32; ++bit) {
        if (!(mask & (1u << bit))) continue;
        if (value & source) result |= 1u << bit;
        source <<= 1;
    }
    return result;
}
