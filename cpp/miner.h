// Stratum session handling + mining orchestration.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "job.h"
#include "stratum.h"
#include "worker.h"

struct PoolCredentials {
    std::string url;
    std::string user;
    std::string password = "x";
};

struct MinerConfig {
    //: Pools tried in order; the first one is the primary.
    std::vector<PoolCredentials> pools;
    std::string user_agent;
    int threads = 4;
    double stats_interval = 30.0;
    double idle_timeout = 300.0;
    bool has_duration = false;
    double duration = 0.0;
    bool has_suggest = false;
    double suggest_difficulty = 0.0;
    bool has_seed = false;
    uint64_t seed = 0;

    // BIP310 version rolling.
    bool version_rolling = true;
    uint32_t version_mask = 0x1fffe000u;

    // TLS certificate validation (disable only for testing).
    bool tls_verify = true;

    // Local status API.
    bool api_enabled = true;
    std::string api_bind = "127.0.0.1";
    uint16_t api_port = 4068;

    // CPU controls.
    uint64_t affinity_mask = 0;  // 0 = every CPU
    std::string priority = "normal";
    int cpu_limit = 100;
};

class Miner {
public:
    explicit Miner(MinerConfig config);
    ~Miner();

    void run();
    void benchmark(double seconds);
    void request_stop() { stop_.store(true, std::memory_order_relaxed); }

    uint64_t hashes() const { return pool_.hashes(); }
    uint64_t accepted() const { return accepted_; }
    uint64_t rejected() const { return rejected_; }
    double best_difficulty() const { return best_difficulty_; }

private:
    void session(const PoolCredentials& pool);
    void close_session();
    const PoolCredentials& current_pool() const {
        return config_.pools[pool_index_];
    }
    void handle_message(const Json& message);
    void on_notify(const Json& params);
    void on_set_difficulty(const Json& params);
    void on_set_extranonce(const Json& params);
    void apply_subscription(const Json& result);
    void negotiate_version_rolling();
    void on_set_version_mask(const Json& params);
    void set_difficulty(double difficulty);
    void publish_work();
    void on_share(const Share& share);
    void on_submit_response(long long id, const Json& message);
    void stats_tick();
    void print_summary();
    bool time_exceeded() const;
    void sleep_interruptible(double seconds);

    MinerConfig config_;
    WorkerPool pool_;

    std::unique_ptr<StratumClient> client_;
    size_t pool_index_ = 0;
    size_t pool_switches_ = 0;
    bool have_job_ = false;
    Job job_;
    Json raw_notify_;

    std::vector<uint8_t> extranonce1_;
    size_t extranonce2_size_ = 4;
    std::vector<uint8_t> extranonce2_;

    // BIP310 version rolling for the current session (0 = off).
    uint32_t version_mask_ = 0;

    bool have_difficulty_ = false;
    double difficulty_ = 0.0;
    uint8_t target_[32] = {0};
    uint32_t generation_ = 0;
    std::string work_key_;
    bool warned_default_difficulty_ = false;

    struct PendingShare {
        double difficulty = 0.0;
        std::string job_id;
    };
    std::map<long long, PendingShare> pending_;

    std::deque<std::pair<double, uint64_t>> samples_;
    double last_rx_ = 0.0;
    double last_stats_ = 0.0;
    double started_at_ = 0.0;

    uint64_t shares_found_ = 0;
    uint64_t accepted_ = 0;
    uint64_t rejected_ = 0;
    uint64_t stale_ = 0;
    double best_difficulty_ = 0.0;

    std::atomic<bool> stop_{false};
};
