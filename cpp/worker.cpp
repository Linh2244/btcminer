#include "worker.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>

#include "util.h"

namespace {

//: Nonces hashed between two checks for a newer job (~1 ms per thread).
constexpr uint32_t kChunk = 8192;
//: Enough room for every share a chunk can produce at the lowest difficulty.
constexpr int kMaxSharesPerChunk = 8;

}  // namespace

WorkerPool::WorkerPool(int threads, uint64_t seed)
    : count_(std::max(1, threads)), seed_(seed) {
    shares_.reserve(16);
}

WorkerPool::~WorkerPool() { stop(); }

void WorkerPool::start() {
    if (!threads_.empty()) return;
    stop_.store(false);
    threads_.reserve(size_t(count_));
    for (int i = 0; i < count_; ++i) {
        threads_.emplace_back([this, i] { loop(i); });
    }
    util::log().debug("%d worker thread(s) started, kernel: %s", count_,
                      sha256::kernel_name());
}

void WorkerPool::stop() {
    if (threads_.empty()) return;
    stop_.store(true, std::memory_order_release);
    for (auto& thread : threads_) {
        if (thread.joinable()) thread.join();
    }
    threads_.clear();
}

void WorkerPool::publish(std::shared_ptr<const Work> work) {
    {
        std::lock_guard<std::mutex> lock(work_mutex_);
        work_ = std::move(work);
    }
    generation_.fetch_add(1, std::memory_order_release);
}

void WorkerPool::clear() {
    {
        std::lock_guard<std::mutex> lock(work_mutex_);
        work_.reset();
    }
    generation_.fetch_add(1, std::memory_order_release);
}

std::vector<Share> WorkerPool::drain_shares() {
    std::vector<Share> out;
    {
        std::lock_guard<std::mutex> lock(share_mutex_);
        out.swap(shares_);
    }
    return out;
}

void WorkerPool::loop(int index) {
    std::mt19937_64 rng(seed_ + uint64_t(index) * 0x9e3779b97f4a7c15ull);

    const uint64_t span = 0x100000000ull / uint64_t(count_);
    const uint64_t lo = span * uint64_t(index);
    const uint64_t hi = (index == count_ - 1) ? 0x100000000ull
                                             : span * uint64_t(index + 1);
    uint64_t position = lo + (span ? rng() % span : 0);

    std::shared_ptr<const Work> work;
    uint32_t seen_generation = 0;

    while (!stop_.load(std::memory_order_acquire)) {
        if (!work ||
            seen_generation != generation_.load(std::memory_order_acquire)) {
            {
                std::lock_guard<std::mutex> lock(work_mutex_);
                work = work_;
            }
            seen_generation = generation_.load(std::memory_order_acquire);
            if (!work) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
        }

        uint64_t remaining = hi - position;
        if (remaining < 8) {
            position = lo;
            continue;
        }
        uint32_t count = uint32_t(std::min<uint64_t>(kChunk, remaining & ~7ull));

        uint32_t nonces[kMaxSharesPerChunk];
        uint8_t digests[kMaxSharesPerChunk][32];
        int found = sha256::scan(work->mid, uint32_t(position), count,
                                 work->target, nonces, digests,
                                 kMaxSharesPerChunk);

        hashes_.fetch_add(count, std::memory_order_relaxed);
        position += count;
        if (position >= hi) position = lo;

        for (int i = 0; i < found; ++i) {
            // Double check with the portable kernel: a bug in the SIMD kernel
            // must never produce a bogus share.
            uint8_t raw[32];
            uint8_t be[32];
            sha256::hash_nonce_scalar(work->mid, nonces[i], raw);
            for (int j = 0; j < 32; ++j) be[j] = raw[31 - j];
            if (std::memcmp(be, work->target, 32) > 0) continue;

            Share share;
            share.nonce = nonces[i];
            share.work = work;
            share.thread = index;
            std::lock_guard<std::mutex> lock(share_mutex_);
            shares_.push_back(std::move(share));
        }
    }
}
