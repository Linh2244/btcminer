#include "cpu.h"

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace cpu {
namespace {

thread_local HANDLE g_sleep_timer = nullptr;
thread_local bool g_sleep_timer_failed = false;

HANDLE sleep_timer() {
    if (!g_sleep_timer && !g_sleep_timer_failed) {
        g_sleep_timer = CreateWaitableTimerExW(
            nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
            TIMER_ALL_ACCESS);
        if (!g_sleep_timer) {
            g_sleep_timer_failed = true;
            g_sleep_timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
        }
    }
    return g_sleep_timer;
}

std::string trim(const std::string& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && std::isspace((unsigned char)text[begin])) ++begin;
    while (end > begin && std::isspace((unsigned char)text[end - 1])) --end;
    return text.substr(begin, end - begin);
}

std::string lower(const std::string& text) {
    std::string out = text;
    for (char& c : out) c = char(std::tolower((unsigned char)c));
    return out;
}

std::string last_error_text() {
    DWORD code = GetLastError();
    char* text = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, (LPSTR)&text, 0, nullptr);
    std::string message = text ? text : "unknown error";
    if (text) LocalFree(text);
    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r' ||
            message.back() == '.')) {
        message.pop_back();
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), " (error %lu)", (unsigned long)code);
    return message + buf;
}

bool parse_decimal(const std::string& text, unsigned& value) {
    if (text.empty()) return false;
    for (char c : text) {
        if (!std::isdigit((unsigned char)c)) return false;
    }
    errno = 0;
    char* stop = nullptr;
    unsigned long parsed = std::strtoul(text.c_str(), &stop, 10);
    if (errno != 0 || !stop || *stop != '\0' || parsed > 63) return false;
    value = unsigned(parsed);
    return true;
}

}  // namespace

bool parse_affinity(const std::string& text, uint64_t& mask,
                    std::string& error) {
    mask = 0;
    std::string body = trim(text);
    if (body.empty()) {
        error = "affinity is empty";
        return false;
    }

    bool hex = body.size() > 2 && body[0] == '0' &&
               (body[1] == 'x' || body[1] == 'X');
    bool has_hex_digit = false;
    for (char c : body) {
        if (std::isxdigit((unsigned char)c) &&
            !std::isdigit((unsigned char)c)) {
            has_hex_digit = true;
        }
    }
    if (hex || has_hex_digit) {
        errno = 0;
        char* stop = nullptr;
        unsigned long long value = std::strtoull(body.c_str(), &stop, 16);
        if (errno != 0 || !stop || *stop != '\0' || value == 0) {
            error = "invalid affinity mask '" + text + "'";
            return false;
        }
        mask = uint64_t(value);
        return true;
    }

    size_t start = 0;
    while (start <= body.size()) {
        size_t comma = body.find(',', start);
        std::string token = body.substr(
            start, comma == std::string::npos ? std::string::npos : comma - start);
        token = trim(token);
        size_t dash = token.find('-');
        unsigned first = 0;
        unsigned last = 0;
        if (dash == std::string::npos) {
            if (!parse_decimal(token, first)) {
                error = "invalid CPU list entry '" + token + "'";
                return false;
            }
            last = first;
        } else {
            if (!parse_decimal(trim(token.substr(0, dash)), first) ||
                !parse_decimal(trim(token.substr(dash + 1)), last) || first > last) {
                error = "invalid CPU range '" + token + "'";
                return false;
            }
        }
        for (unsigned cpu = first; cpu <= last; ++cpu) mask |= 1ull << cpu;
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    if (mask == 0) {
        error = "affinity selects no CPU";
        return false;
    }
    return true;
}

int count_cpus(uint64_t mask) {
    int count = 0;
    while (mask) {
        mask &= mask - 1;
        ++count;
    }
    return count;
}

int cpu_for_worker(uint64_t mask, int index, int count) {
    if (!mask || count <= 0) return -1;
    int wanted = index % count;
    for (int cpu = 0; cpu < 64; ++cpu) {
        if (!(mask & (1ull << cpu))) continue;
        if (wanted == 0) return cpu;
        --wanted;
    }
    return -1;
}

bool valid_priority(const std::string& name) {
    const std::string value = lower(name);
    return value == "idle" || value == "below" || value == "normal" ||
           value == "above" || value == "high" || value == "realtime";
}

bool apply_process_priority(const std::string& name, std::string& error) {
    DWORD cls = NORMAL_PRIORITY_CLASS;
    const std::string value = lower(name);
    if (value == "idle") cls = IDLE_PRIORITY_CLASS;
    else if (value == "below") cls = BELOW_NORMAL_PRIORITY_CLASS;
    else if (value == "normal") cls = NORMAL_PRIORITY_CLASS;
    else if (value == "above") cls = ABOVE_NORMAL_PRIORITY_CLASS;
    else if (value == "high") cls = HIGH_PRIORITY_CLASS;
    else if (value == "realtime") cls = REALTIME_PRIORITY_CLASS;
    else {
        error = "unknown priority '" + name + "'";
        return false;
    }
    if (!SetPriorityClass(GetCurrentProcess(), cls)) {
        error = "cannot set process priority: " + last_error_text();
        return false;
    }
    return true;
}

int thread_priority_value(const std::string& name) {
    const std::string value = lower(name);
    if (value == "idle") return THREAD_PRIORITY_IDLE;
    if (value == "below") return THREAD_PRIORITY_BELOW_NORMAL;
    if (value == "above") return THREAD_PRIORITY_ABOVE_NORMAL;
    if (value == "high") return THREAD_PRIORITY_HIGHEST;
    if (value == "realtime") return THREAD_PRIORITY_TIME_CRITICAL;
    return THREAD_PRIORITY_NORMAL;
}

bool apply_current_thread(uint64_t mask, int index, int count,
                          const std::string& priority, std::string& error) {
    if (mask) {
        uint64_t target = mask;
        int available = count_cpus(mask);
        if (available > 0 && count <= available) {
            int cpu = cpu_for_worker(mask, index, count);
            if (cpu >= 0) target = 1ull << cpu;
        }
        if (!SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)target)) {
            error = "cannot set thread affinity: " + last_error_text();
            return false;
        }
    }
    if (!SetThreadPriority(GetCurrentThread(), thread_priority_value(priority))) {
        error = "cannot set thread priority: " + last_error_text();
        return false;
    }
    return true;
}

void sleep_milliseconds(double ms) {
    if (!(ms > 0.0)) return;
    HANDLE timer = sleep_timer();
    if (timer) {
        LARGE_INTEGER due;
        due.QuadPart = -static_cast<LONGLONG>(ms * 10000.0);
        if (due.QuadPart > -1) due.QuadPart = -1;
        if (SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE)) {
            WaitForSingleObject(timer, INFINITE);
            return;
        }
    }
    DWORD millis = DWORD(ms + 0.5);
    if (millis == 0) millis = 1;
    Sleep(millis);
}

}  // namespace cpu
