// Local status HTTP endpoint for miner health and progress reporting.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

struct StatusSnapshot {
    std::string version;
    double uptime = 0.0;
    std::string pool_url;
    std::string pool_user;
    size_t pool_index = 0;
    size_t pool_count = 0;
    std::string kernel;
    int threads = 0;
    double hashrate = 0.0;
    uint64_t hashes = 0;
    uint64_t shares_found = 0;
    uint64_t accepted = 0;
    uint64_t rejected = 0;
    uint64_t stale = 0;
    double best_share = 0.0;
    double pool_difficulty = 0.0;
    std::string job_id;
    uint32_t version_mask = 0;
    size_t switch_count = 0;
};

class StatusServer {
public:
    using SnapshotFn = std::function<StatusSnapshot()>;

    StatusServer(std::string bind_host, uint16_t port, SnapshotFn snapshot);
    ~StatusServer();

    StatusServer(const StatusServer&) = delete;
    StatusServer& operator=(const StatusServer&) = delete;

    void start();
    void stop();

private:
    void listen_loop();
    void handle_client(uintptr_t socket);
    std::string render_status_json() const;
    std::string render_healthz() const;

    std::string bind_host_;
    uint16_t port_ = 4068;
    SnapshotFn snapshot_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    uintptr_t listener_ = ~uintptr_t{0};
};
