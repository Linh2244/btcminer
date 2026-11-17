// CPU controls: affinity masks, priority classes and per-thread pinning.
//
// Everything here is Windows specific and intentionally kept out of the
// headers that the portable hashing code includes.
#pragma once

#include <cstdint>
#include <string>

namespace cpu {

// Parses "0-3,6" / "0,2,4" (decimal lists) or a hexadecimal mask such as
// "0xF".  Returns false with a message on malformed input or an empty mask.
bool parse_affinity(const std::string& text, uint64_t& mask, std::string& error);

// Number of set bits in the mask.
int count_cpus(uint64_t mask);

// Logical CPU assigned to worker `index`, or -1 when the mask is empty.
int cpu_for_worker(uint64_t mask, int index, int count);

// Priority names: idle, below, normal, above, high, realtime.
bool valid_priority(const std::string& name);
bool apply_process_priority(const std::string& name, std::string& error);
int thread_priority_value(const std::string& name);

// Pins and prioritises the calling thread.  `mask` may be zero (no pinning).
// Returns false and fills `error` when the thread cannot be configured.
bool apply_current_thread(uint64_t mask, int index, int count,
                          const std::string& priority, std::string& error);

// Sleeps for `ms` milliseconds using a high-resolution waitable timer, which
// keeps the CPU limit accurate despite the default 15.6 ms sleep granularity.
void sleep_milliseconds(double ms);

}  // namespace cpu
