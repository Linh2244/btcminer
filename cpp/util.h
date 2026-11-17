// Small helpers: hex, target math, formatting, logging.
#pragma once

#include <cstdarg>
#include <cstdint>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace util {

// --- hex ---------------------------------------------------------------
std::string hex_encode(const uint8_t* data, size_t size);
std::string hex_encode(const std::vector<uint8_t>& data);
bool hex_decode(const std::string& text, std::vector<uint8_t>& out,
                size_t expected_size, std::string* error);

// --- target math -------------------------------------------------------
//: Difficulty-1 target shared by every Bitcoin pool: 0xFFFF * 2^208.
void difficulty_to_target(double difficulty, uint8_t target_be[32]);
double target_to_difficulty(const uint8_t target_be[32]);
//: Value of a big-endian 256-bit integer as a floating point number.
long double be_to_long_double(const uint8_t value[32]);

// --- formatting --------------------------------------------------------
std::string format_hashrate(double hashes_per_second);
std::string format_difficulty(double difficulty);
std::string format_nonce(uint32_t nonce);

// --- logging -----------------------------------------------------------
enum class Level { Debug = 0, Info = 1, Warn = 2, Error = 3 };

class Logger {
public:
    explicit Logger(Level level = Level::Info) : level_(level) {}
    void set_level(Level level) { level_ = level; }
    Level level() const { return level_; }
    static Level parse_level(const std::string& text, bool* ok = nullptr);

    void debug(const char* fmt, ...);
    void info(const char* fmt, ...);
    void warn(const char* fmt, ...);
    void error(const char* fmt, ...);
    void raw(const std::string& line);

private:
    void log(Level level, const char* fmt, va_list args);
    Level level_;
    std::mutex mutex_;
};

Logger& log();

// --- misc --------------------------------------------------------------
double now_seconds();  // monotonic clock
std::string random_hex(size_t bytes);
std::vector<uint8_t> random_bytes(size_t bytes);

}  // namespace util
