#include "util.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <random>

namespace util {
namespace {

constexpr long double DIFF1 = 65535.0L;  // times 2^208

inline int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// UCRT prints exponents with three digits ("1.40e-005"); the rest of the
// project (and Python) uses two.  Normalise for nicer logs.
std::string normalise_exponent(std::string text) {
    size_t e = text.find('e');
    if (e == std::string::npos) return text;
    size_t digits = e + 1;
    if (digits < text.size() && (text[digits] == '+' || text[digits] == '-')) ++digits;
    while (digits + 2 < text.size() && text[digits] == '0') text.erase(digits, 1);
    return text;
}

Logger g_log(Level::Info);

}  // namespace

std::string hex_encode(const uint8_t* data, size_t size) {
    static const char* digits = "0123456789abcdef";
    std::string out(size * 2, '\0');
    for (size_t i = 0; i < size; ++i) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0x0f];
    }
    return out;
}

std::string hex_encode(const std::vector<uint8_t>& data) {
    return hex_encode(data.data(), data.size());
}

bool hex_decode(const std::string& text, std::vector<uint8_t>& out,
                size_t expected_size, std::string* error) {
    if (text.size() % 2 != 0) {
        if (error) *error = "odd number of hex digits";
        return false;
    }
    std::vector<uint8_t> bytes(text.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        int hi = nibble(text[2 * i]);
        int lo = nibble(text[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            if (error) *error = "invalid hex digit";
            return false;
        }
        bytes[i] = uint8_t(hi << 4 | lo);
    }
    if (expected_size != std::string::npos && bytes.size() != expected_size) {
        if (error) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), "expected %zu bytes, got %zu",
                          expected_size, bytes.size());
            *error = buf;
        }
        return false;
    }
    out.swap(bytes);
    return true;
}

// target = floor(65535 * 2^208 / difficulty), clamped to [1, 2^256-1].
//
// The division is done with exact integers: the double is split into a 53-bit
// mantissa and a power of two, so the target matches what a pool (which uses
// exact rationals) expects.
void difficulty_to_target(double difficulty, uint8_t target_be[32]) {
    std::memset(target_be, 0, 32);
    if (!(difficulty > 0.0)) {  // also rejects NaN
        target_be[31] = 1;
        return;
    }

    int exponent = 0;
    double fraction = std::frexp(difficulty, &exponent);  // d = fraction * 2^exponent
    uint64_t mantissa = uint64_t(std::ldexp(fraction, 53));  // 53-bit integer
    if (mantissa == 0) {
        target_be[31] = 1;
        return;
    }
    int shift = 208 - (exponent - 53);  // numerator = 65535 << shift

    if (shift < 0) {  // difficulty is huge: target is below 1
        target_be[31] = 1;
        return;
    }
    if (shift > 304) {  // numerator would exceed 320 bits: target overflows
        std::memset(target_be, 0xff, 32);
        return;
    }

    // numerator = 65535 << shift, little-endian 64-bit limbs.
    uint64_t limbs[5] = {0, 0, 0, 0, 0};
    int word = shift / 64;
    int bit = shift % 64;
    unsigned __int128 value = (unsigned __int128)65535 << bit;
    limbs[word] = uint64_t(value);
    if (word + 1 < 5) limbs[word + 1] = uint64_t(value >> 64);

    uint64_t remainder = 0;
    for (int i = 4; i >= 0; --i) {
        unsigned __int128 current =
            ((unsigned __int128)remainder << 64) | limbs[i];
        limbs[i] = uint64_t(current / mantissa);
        remainder = uint64_t(current % mantissa);
    }

    if (limbs[4] != 0) {  // result does not fit in 256 bits
        std::memset(target_be, 0xff, 32);
        return;
    }
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = limbs[3 - limb];
        for (int b = 0; b < 8; ++b) {
            target_be[limb * 8 + b] = uint8_t(v >> (56 - 8 * b));
        }
    }
    bool zero = true;
    for (int i = 0; i < 32; ++i) {
        if (target_be[i]) { zero = false; break; }
    }
    if (zero) target_be[31] = 1;
}

long double be_to_long_double(const uint8_t value[32]) {
    long double v = 0.0L;
    for (int i = 0; i < 32; ++i) v = v * 256.0L + (long double)value[i];
    return v;
}

double target_to_difficulty(const uint8_t target_be[32]) {
    long double value = be_to_long_double(target_be);
    if (value <= 0.0L) return std::numeric_limits<double>::infinity();
    long double difficulty = (DIFF1 * std::ldexp(1.0L, 208)) / value;
    return (double)difficulty;
}

std::string format_hashrate(double hashes_per_second) {
    static const struct { const char* name; double scale; } units[] = {
        {"EH/s", 1e18}, {"PH/s", 1e15}, {"TH/s", 1e12},
        {"GH/s", 1e9}, {"MH/s", 1e6}, {"kH/s", 1e3},
    };
    char buf[64];
    for (const auto& unit : units) {
        if (hashes_per_second >= unit.scale) {
            std::snprintf(buf, sizeof(buf), "%.2f %s",
                          hashes_per_second / unit.scale, unit.name);
            return buf;
        }
    }
    std::snprintf(buf, sizeof(buf), "%.1f H/s", hashes_per_second);
    return buf;
}

std::string format_difficulty(double difficulty) {
    char buf[64];
    if (std::isinf(difficulty)) return "inf";
    if (difficulty >= 1e6 || difficulty < 1e-3) {
        std::snprintf(buf, sizeof(buf), "%.2e", difficulty);
        return normalise_exponent(buf);
    }
    std::snprintf(buf, sizeof(buf), "%.4f", difficulty);
    std::string text(buf);
    while (!text.empty() && text.back() == '0') text.pop_back();
    if (!text.empty() && text.back() == '.') text.pop_back();
    return text.empty() ? "0" : text;
}

std::string format_nonce(uint32_t nonce) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%08x", (unsigned)nonce);
    return buf;
}

Level Logger::parse_level(const std::string& text, bool* ok) {
    std::string upper;
    for (char c : text) upper.push_back(char(std::toupper((unsigned char)c)));
    if (upper == "DEBUG") { if (ok) *ok = true; return Level::Debug; }
    if (upper == "INFO") { if (ok) *ok = true; return Level::Info; }
    if (upper == "WARNING" || upper == "WARN") {
        if (ok) *ok = true;
        return Level::Warn;
    }
    if (upper == "ERROR") { if (ok) *ok = true; return Level::Error; }
    if (ok) *ok = false;
    return Level::Info;
}

void Logger::log(Level level, const char* fmt, va_list args) {
    if (level < level_) return;
    char message[2048];
    std::vsnprintf(message, sizeof(message), fmt, args);

    std::time_t now = std::time(nullptr);
    std::tm local;
#ifdef _WIN32
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    char stamp[16];
    std::snprintf(stamp, sizeof(stamp), "%02d:%02d:%02d", local.tm_hour,
                  local.tm_min, local.tm_sec);
    const char* names[] = {"DEBUG  ", "INFO   ", "WARNING", "ERROR  "};

    std::lock_guard<std::mutex> lock(mutex_);
    std::fprintf(stderr, "%s  %s %s\n", stamp, names[int(level)], message);
    std::fflush(stderr);
}

void Logger::debug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log(Level::Debug, fmt, args);
    va_end(args);
}

void Logger::info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log(Level::Info, fmt, args);
    va_end(args);
}

void Logger::warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log(Level::Warn, fmt, args);
    va_end(args);
}

void Logger::error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log(Level::Error, fmt, args);
    va_end(args);
}

void Logger::raw(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::fprintf(stderr, "%s\n", line.c_str());
    std::fflush(stderr);
}

Logger& log() { return g_log; }

double now_seconds() {
    using clock = std::chrono::steady_clock;
    static const clock::time_point start = clock::now();
    return std::chrono::duration<double>(clock::now() - start).count();
}

std::string random_hex(size_t bytes) {
    return hex_encode(random_bytes(bytes));
}

std::vector<uint8_t> random_bytes(size_t bytes) {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::vector<uint8_t> data(bytes);
    for (size_t i = 0; i < bytes; ++i) data[i] = uint8_t(rng());
    return data;
}

}  // namespace util
