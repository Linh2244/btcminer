// Worker threads: each scans a disjoint part of the 32-bit nonce space.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "job.h"
#include "sha256.h"

struct Work {
    uint32_t generation = 0;
    sha256::Midstate mid{};
    uint8_t target[32] = {0};  // big-endian (display order)
    std::string job_id;
    std::string ntime_hex;
    std::string extranonce2_hex;
    double difficulty = 0.0;
};

struct Share {
    uint32_t nonce = 0;
    std::shared_ptr<const Work> work;
    int thread = 0;
};

class WorkerPool {
public:
    WorkerPool(int threads, uint64_t seed, uint64_t affinity_mask = 0,
               int cpu_limit = 100, std::string priority = "normal");
    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;

    void start();
    void stop();
    void publish(std::shared_ptr<const Work> work);
    void clear();
    std::vector<Share> drain_shares();
    uint64_t hashes() const { return hashes_.load(std::memory_order_relaxed); }
    int threads() const { return count_; }

private:
    void loop(int index);

    int count_;
    uint64_t seed_;
    uint64_t affinity_mask_ = 0;
    int cpu_limit_ = 100;
    std::string priority_ = "normal";
    std::vector<std::thread> threads_;
    std::atomic<bool> stop_{false};
    std::atomic<uint32_t> generation_{0};
    std::atomic<uint64_t> hashes_{0};
    std::mutex work_mutex_;
    std::shared_ptr<const Work> work_;
    std::mutex share_mutex_;
    std::vector<Share> shares_;
};
