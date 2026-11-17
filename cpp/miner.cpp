#include "miner.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <thread>

#include "util.h"

namespace {

//: Difficulty assumed if a pool sends a job before mining.set_difficulty.
constexpr double kDefaultDifficulty = 1.0;
constexpr const char* kVersion = "1.3.0";

std::string lower_ascii(std::string text) {
    for (char& c : text) c = char(std::tolower((unsigned char)c));
    return text;
}

std::string json_error_text(const Json& error) {
    if (error.is_string()) return error.as_string();
    if (error.is_array() && error.size() > 1 && error[1].is_string()) {
        return error[1].as_string();
    }
    return error.dump();
}

// Parses an 8-digit hexadecimal version mask (BIP310).
bool parse_version_mask(const Json& value, uint32_t& mask) {
    std::string text;
    if (value.is_string()) {
        text = value.as_string();
    } else if (value.is_number()) {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "%08x",
                      (unsigned)uint32_t(value.as_int(0)));
        text = buffer;
    } else {
        return false;
    }
    if (text.empty() || text.size() > 8) return false;
    uint32_t parsed = 0;
    for (char c : text) {
        int digit = -1;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        if (digit < 0) return false;
        parsed = (parsed << 4) | uint32_t(digit);
    }
    mask = parsed;
    return true;
}

}  // namespace

Miner::Miner(MinerConfig config)
    : config_(std::move(config)),
      pool_(config_.threads,
            config_.has_seed ? config_.seed : std::random_device{}(),
            config_.affinity_mask, config_.cpu_limit, config_.priority) {
    if (config_.user_agent.empty()) {
        config_.user_agent = std::string("btcminer-cpp/") + kVersion;
    }
    if (config_.threads < 1) config_.threads = 1;
    raw_notify_ = Json::make_array();
}

Miner::~Miner() {
    if (status_server_) status_server_->stop();
    pool_.stop();
}

void Miner::run() {
    started_at_ = util::now_seconds();
    refresh_status_snapshot();
    if (config_.pools.empty()) throw StratumError("no pool configured");
    util::log().info(
        "btcminer %s | %zu pool(s) | worker %s | %d thread(s) | kernel %s",
        kVersion, config_.pools.size(), config_.pools.front().user.c_str(),
        config_.threads, sha256::kernel_name());
    pool_.start();
    if (config_.api_enabled) {
        try {
            status_server_ = std::make_unique<StatusServer>(
                config_.api_bind, config_.api_port,
                [this]() { return status_snapshot(); });
            status_server_->start();
        } catch (const std::exception& error) {
            util::log().warn("status API is disabled on %s:%u: %s",
                             config_.api_bind.c_str(), unsigned(config_.api_port),
                             error.what());
            status_server_.reset();
        }
    }
    double backoff = 2.0;
    int failures_on_pool = 0;
    try {
        while (!stop_.load() && !time_exceeded()) {
            const PoolCredentials& pool = current_pool();
            double session_started = util::now_seconds();
            try {
                session(pool);
            } catch (const std::exception& error) {
                util::log().warn("%s", error.what());
            }
            close_session();
            if (stop_.load() || time_exceeded()) break;

            double lived = util::now_seconds() - session_started;
            if (lived > 120.0) {
                backoff = 2.0;
                failures_on_pool = 0;
                if (pool_index_ != 0) {
                    util::log().info("session was stable, returning to the primary pool");
                    pool_index_ = 0;
                }
            } else if (++failures_on_pool >= 2 && config_.pools.size() > 1) {
                failures_on_pool = 0;
                pool_index_ = (pool_index_ + 1) % config_.pools.size();
                ++pool_switches_;
                util::log().warn("switching to pool %zu/%zu: %s", pool_index_ + 1,
                                 config_.pools.size(),
                                 current_pool().url.c_str());
            }
            util::log().info("reconnecting in %.0f s", backoff);
            sleep_interruptible(backoff);
            backoff = std::min(backoff * 2.0, 60.0);
        }
    } catch (...) {
        pool_.stop();
        throw;
    }
    pool_.stop();
    print_summary();
}

void Miner::benchmark(double seconds) {
    util::log().info(
        "benchmark mode: hashing locally for %.0f s with %d thread(s), kernel %s",
        seconds, config_.threads, sha256::kernel_name());
    pool_.start();

    auto work = std::make_shared<Work>();
    work->generation = 1;
    uint8_t random_prefix[76];
    std::vector<uint8_t> noise = util::random_bytes(76);
    std::memcpy(random_prefix, noise.data(), 76);
    uint8_t full[80];
    std::memcpy(full, random_prefix, 76);
    std::memset(full + 76, 0, 4);
    sha256::build_midstate(work->mid, full);
    // Impossible target: no share is ever found.
    std::memset(work->target, 0, 32);
    work->job_id = "benchmark";
    work->ntime_hex = "00000000";
    pool_.publish(work);

    double start = util::now_seconds();
    double warm_at = -1.0;
    uint64_t warm_hashes = 0;
    double last_report = start;

    while (!stop_.load()) {
        double now = util::now_seconds();
        if (now - start >= seconds) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        now = util::now_seconds();
        if (warm_at < 0.0 && now - start >= std::min(1.5, seconds / 2.0)) {
            warm_at = now;
            warm_hashes = pool_.hashes();
        }
        if (warm_at >= 0.0 && now - last_report >= 5.0) {
            last_report = now;
            double rate = double(pool_.hashes() - warm_hashes) /
                          std::max(now - warm_at, 1e-9);
            util::log().info("benchmark: %s", util::format_hashrate(rate).c_str());
        }
    }

    double end = util::now_seconds();
    pool_.stop();
    double base = warm_at >= 0.0 ? warm_at : start;
    uint64_t base_hashes = warm_at >= 0.0 ? warm_hashes : 0;
    uint64_t total = pool_.hashes();
    double elapsed = std::max(end - base, 1e-9);
    util::log().info(
        "benchmark result: %s average over %.1f s (%llu hashes, %d thread(s))",
        util::format_hashrate(double(total - base_hashes) / elapsed).c_str(),
        elapsed, (unsigned long long)total, config_.threads);
}

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------
void Miner::session(const PoolCredentials& pool) {
    PoolUrl url;
    std::string error;
    if (!parse_url(pool.url, url, error)) {
        throw StratumError("invalid pool URL: " + error);
    }

    util::log().info("connecting to %s:%u (%s) | pool %zu/%zu", url.host.c_str(),
                     unsigned(url.port), url.scheme.c_str(), pool_index_ + 1,
                     config_.pools.size());
    if (url.tls && !config_.tls_verify) {
        util::log().warn("TLS certificate validation is disabled for this pool");
    }
    client_ = std::make_unique<StratumClient>(url.host, url.port, url.tls,
                                              config_.tls_verify);
    client_->connect();

    Json subscribe_params = Json::make_array();
    subscribe_params.push(Json::make_string(config_.user_agent));
    Json result = client_->request("mining.subscribe", subscribe_params, 30.0);
    apply_subscription(result);
    negotiate_version_rolling();

    if (config_.has_suggest && config_.suggest_difficulty > 0.0) {
        Json suggest = Json::make_array();
        suggest.push(Json::make_number(config_.suggest_difficulty));
        try {
            client_->request("mining.suggest_difficulty", suggest, 5.0);
        } catch (const StratumError& exc) {
            util::log().debug("pool ignored suggest_difficulty: %s", exc.what());
        }
    }

    Json auth_params = Json::make_array();
    auth_params.push(Json::make_string(pool.user));
    auth_params.push(Json::make_string(pool.password));
    Json authorized = client_->request("mining.authorize", auth_params, 30.0);
    if (!authorized.is_bool() || !authorized.as_bool()) {
        throw StratumError("pool refused the worker credentials (" + pool.user +
                           ")");
    }

    util::log().info("authorized | extranonce1=%s | extranonce2_size=%d",
                     extranonce1_.empty() ? "-"
                                         : util::hex_encode(extranonce1_).c_str(),
                     int(extranonce2_size_));

    // Fire and forget: most pools never answer this one.
    try {
        Json empty = Json::make_array();
        client_->send_request("mining.extranonce.subscribe", empty);
    } catch (const std::exception& exc) {
        util::log().debug("could not enable extranonce subscription: %s",
                          exc.what());
    }

    double now = util::now_seconds();
    last_rx_ = now;
    last_stats_ = now;
    samples_.clear();
    samples_.emplace_back(now, pool_.hashes());

    while (!stop_.load() && !time_exceeded()) {
        std::vector<Json> messages = client_->poll(0.5);
        std::vector<Json> backlog = client_->take_backlog();
        if (!messages.empty() || !backlog.empty()) {
            last_rx_ = util::now_seconds();
        }
        // Older backlog messages first: they arrived before this read.
        for (const Json& message : backlog) handle_message(message);
        for (const Json& message : messages) handle_message(message);

        for (const Share& share : pool_.drain_shares()) on_share(share);
        stats_tick();

        if (util::now_seconds() - last_rx_ > config_.idle_timeout) {
            throw StratumDisconnected("no data from pool for " +
                                      std::to_string(int(config_.idle_timeout)) +
                                      " s");
        }
    }
}

void Miner::close_session() {
    pool_.clear();
    if (client_) {
        client_->close();
        client_.reset();
    }
    if (!pending_.empty()) {
        util::log().warn("%zu submitted share(s) still unconfirmed",
                         pending_.size());
        pending_.clear();
    }
}

void Miner::apply_subscription(const Json& result) {
    if (!result.is_array() || result.size() < 3) {
        throw StratumError("unexpected mining.subscribe result: " + result.dump());
    }
    const Json& extranonce1 = result[1];
    if (!extranonce1.is_string()) {
        throw StratumError("pool did not provide an extranonce1");
    }
    std::vector<uint8_t> decoded;
    std::string detail;
    if (!util::hex_decode(extranonce1.as_string(), decoded, std::string::npos,
                          &detail)) {
        throw StratumError("invalid extranonce1: " + detail);
    }
    extranonce1_ = std::move(decoded);

    const Json& size = result[2];
    long long value = size.is_number() ? size.as_int(-1) : -1;
    if (value < 0 || value > 32) {
        throw StratumError("invalid extranonce2 size: " + size.dump());
    }
    extranonce2_size_ = size_t(value);
    util::log().debug("subscriptions: %s", result[0].dump().c_str());
    work_key_.clear();
}

void Miner::negotiate_version_rolling() {
    version_mask_ = 0;
    if (!config_.version_rolling || config_.version_mask == 0) {
        util::log().debug("version rolling disabled by configuration");
        return;
    }

    Json extensions = Json::make_array();
    extensions.push(Json::make_string("version-rolling"));
    Json parameters = Json::make_object();
    char requested[16];
    std::snprintf(requested, sizeof(requested), "%08x",
                  (unsigned)config_.version_mask);
    parameters.set("version-rolling.mask", Json::make_string(requested));
    parameters.set("version-rolling.min-bit-count", Json::make_int(2));
    Json request = Json::make_array();
    request.push(std::move(extensions));
    request.push(std::move(parameters));

    Json result;
    try {
        result = client_->request("mining.configure", request, 10.0);
    } catch (const std::exception& error) {
        util::log().info("pool did not accept mining.configure: %s",
                         error.what());
        return;
    }

    const Json* supported =
        result.is_object() ? result.find("version-rolling") : nullptr;
    if (!supported || !supported->is_bool() || !supported->as_bool()) {
        util::log().info("pool does not support version rolling");
        return;
    }

    uint32_t mask = config_.version_mask;
    const Json* mask_value =
        result.is_object() ? result.find("version-rolling.mask") : nullptr;
    if (mask_value && !parse_version_mask(*mask_value, mask)) {
        util::log().warn("pool returned a malformed version mask, using %08x",
                         (unsigned)config_.version_mask);
        mask = config_.version_mask;
    }
    if (mask == 0) {
        util::log().info("pool negotiated an empty version mask, rolling off");
        return;
    }
    version_mask_ = mask;
    util::log().info("version rolling enabled | mask %08x", (unsigned)mask);
}

void Miner::on_set_version_mask(const Json& params) {
    if (params.size() < 1) {
        util::log().warn("empty mining.set_version_mask");
        return;
    }
    uint32_t mask = 0;
    if (!parse_version_mask(params[0], mask)) {
        util::log().warn("ignoring malformed mining.set_version_mask: %s",
                         params.dump().c_str());
        return;
    }
    if (mask == version_mask_) {
        util::log().debug("pool repeated the version mask %08x", (unsigned)mask);
        return;
    }
    version_mask_ = mask;
    if (mask) {
        util::log().info("pool updated the version rolling mask to %08x",
                         (unsigned)mask);
    } else {
        util::log().info("pool disabled version rolling for this session");
    }
    if (have_job_) publish_work();
}

// ---------------------------------------------------------------------------
// pool messages
// ---------------------------------------------------------------------------
void Miner::handle_message(const Json& message) {
    if (!message.is_object()) return;

    const Json* method = message.find("method");
    if (method && method->is_string() && !method->as_string().empty()) {
        const std::string& name = method->as_string();
        Json empty_params = Json::make_array();
        const Json* params_ptr = message.find("params");
        const Json& params =
            (params_ptr && params_ptr->is_array()) ? *params_ptr : empty_params;

        if (name == "mining.notify") {
            on_notify(params);
        } else if (name == "mining.set_difficulty") {
            on_set_difficulty(params);
        } else if (name == "mining.set_extranonce") {
            on_set_extranonce(params);
        } else if (name == "mining.set_version_mask") {
            on_set_version_mask(params);
        } else if (name == "client.get_version") {
            const Json* id = message.find("id");
            if (id && client_) {
                client_->respond(*id, Json::make_string(config_.user_agent));
            }
        } else if (name == "client.show_message") {
            util::log().info("pool message: %s",
                             params.size() ? params[0].as_string().c_str() : "");
        } else if (name == "client.reconnect") {
            throw StratumDisconnected("pool requested a reconnect");
        } else if (name == "mining.ping" || name == "mining.set_goal") {
            util::log().debug("ignoring %s: %s", name.c_str(),
                              params.dump().c_str());
        } else {
            util::log().debug("unhandled pool method %s: %s", name.c_str(),
                              params.dump().c_str());
        }
        return;
    }

    const Json* id = message.find("id");
    if (id && id->is_number()) {
        auto it = pending_.find(id->as_int());
        if (it != pending_.end()) {
            pending_.erase(it);
            on_submit_response(id->as_int(), message);
            return;
        }
    }

    const Json* error = message.find("error");
    if (error && !error->is_null()) {
        util::log().warn("pool error: %s", error->dump().c_str());
    }
}

void Miner::on_notify(const Json& params) {
    if (!have_difficulty_) {
        if (!warned_default_difficulty_) {
            util::log().info(
                "job arrived before the first mining.set_difficulty, "
                "using difficulty %g until the pool sends one",
                kDefaultDifficulty);
            warned_default_difficulty_ = true;
        }
        set_difficulty(kDefaultDifficulty);
    }

    Job parsed;
    std::string error;
    if (!parse_notify(params, extranonce1_, extranonce2_size_, parsed, error)) {
        util::log().error("bad mining.notify: %s", error.c_str());
        return;
    }

    raw_notify_ = params;
    job_ = std::move(parsed);
    have_job_ = true;
    extranonce2_ = util::random_bytes(extranonce2_size_);
    if (job_.clean) {
        util::log().debug("clean job %s", job_.id.c_str());
    }
    publish_work();
}

void Miner::on_set_difficulty(const Json& params) {
    if (params.size() < 1) {
        util::log().warn("empty mining.set_difficulty");
        return;
    }
    const Json& value = params[0];
    double difficulty = value.is_number() ? value.as_double()
                                          : std::strtod(value.as_string().c_str(),
                                                        nullptr);
    if (!(difficulty > 0.0)) {
        util::log().warn("bad mining.set_difficulty: %s", params.dump().c_str());
        return;
    }

    uint8_t previous[32];
    std::memcpy(previous, target_, 32);
    bool was_set = have_difficulty_;
    set_difficulty(difficulty);
    if (was_set && std::memcmp(previous, target_, 32) == 0) {
        util::log().debug("pool repeated difficulty %s, nothing to do",
                          util::format_difficulty(difficulty).c_str());
        return;
    }
    util::log().info("pool difficulty set to %s",
                     util::format_difficulty(difficulty).c_str());
    if (have_job_) publish_work();
}

void Miner::on_set_extranonce(const Json& params) {
    if (params.size() < 2) {
        util::log().warn("bad mining.set_extranonce: %s", params.dump().c_str());
        return;
    }
    std::vector<uint8_t> decoded;
    std::string detail;
    if (!util::hex_decode(params[0].is_string() ? params[0].as_string() : "",
                          decoded, std::string::npos, &detail)) {
        util::log().warn("bad mining.set_extranonce: %s", detail.c_str());
        return;
    }
    long long size = params[1].is_number() ? params[1].as_int(-1) : -1;
    if (size < 0 || size > 32) {
        util::log().warn("bad mining.set_extranonce: invalid size");
        return;
    }
    extranonce1_ = std::move(decoded);
    extranonce2_size_ = size_t(size);

    util::log().info("extranonce changed | extranonce1=%s | extranonce2_size=%d",
                     extranonce1_.empty() ? "-"
                                         : util::hex_encode(extranonce1_).c_str(),
                     int(extranonce2_size_));
    work_key_.clear();
    if (!raw_notify_.is_null()) on_notify(raw_notify_);
}

void Miner::set_difficulty(double difficulty) {
    difficulty_ = difficulty;
    have_difficulty_ = true;
    util::difficulty_to_target(difficulty, target_);
}

// ---------------------------------------------------------------------------
// shares
// ---------------------------------------------------------------------------
void Miner::publish_work() {
    if (!have_job_ || !have_difficulty_) return;

    auto work = std::make_shared<Work>();
    uint8_t header76[76];
    uint8_t full[80];
    try {
        build_header_prefix(job_, extranonce2_, header76);
        std::memcpy(full, header76, 76);
        std::memset(full + 76, 0, 4);
        sha256::build_midstate(work->mid, full);
    } catch (const std::exception& error) {
        util::log().error("cannot build block header: %s", error.what());
        return;
    }
    util::log().debug("header %s", util::hex_encode(header76, 76).c_str());
    work->generation = ++generation_;
    std::memcpy(work->header, full, 80);
    work->version = job_.version;
    work->version_mask = version_mask_;
    std::memcpy(work->target, target_, 32);
    work->job_id = job_.id;
    work->ntime_hex = job_.ntime_hex;
    work->extranonce2_hex = util::hex_encode(extranonce2_);
    work->difficulty = difficulty_;

    char mask_text[16];
    std::snprintf(mask_text, sizeof(mask_text), "%08x",
                  (unsigned)work->version_mask);
    std::string key = job_.id + "|" + work->extranonce2_hex + "|" +
                      util::hex_encode(target_, 32) + "|" + job_.ntime_hex +
                      "|" + mask_text;
    if (key == work_key_) return;
    work_key_ = key;

    pool_.publish(work);
    util::log().debug("job %s published | difficulty %s | extranonce2 %s",
                      job_.id.c_str(),
                      util::format_difficulty(difficulty_).c_str(),
                      work->extranonce2_hex.empty()
                          ? "-"
                          : work->extranonce2_hex.c_str());
}

void Miner::on_share(const Share& share) {
    uint8_t raw[32];
    uint8_t be[32];
    sha256::hash_nonce_scalar(share.mid, share.nonce, raw);
    for (int i = 0; i < 32; ++i) be[i] = raw[31 - i];
    double share_difficulty = util::target_to_difficulty(be);

    ++shares_found_;
    best_difficulty_ = std::max(best_difficulty_, share_difficulty);
    if (share.work->version_mask) {
        util::log().info(
            "share found | worker %d | job %s | nonce %s | version %08x | "
            "difficulty %s",
            share.thread, share.work->job_id.c_str(),
            util::format_nonce(share.nonce).c_str(), (unsigned)share.version,
            util::format_difficulty(share_difficulty).c_str());
    } else {
        util::log().info(
            "share found | worker %d | job %s | nonce %s | difficulty %s",
            share.thread, share.work->job_id.c_str(),
            util::format_nonce(share.nonce).c_str(),
            util::format_difficulty(share_difficulty).c_str());
    }

    if (!client_) {
        util::log().warn("no active pool connection, share dropped");
        return;
    }

    Json params = Json::make_array();
    params.push(Json::make_string(current_pool().user));
    params.push(Json::make_string(share.work->job_id));
    params.push(Json::make_string(share.work->extranonce2_hex));
    params.push(Json::make_string(share.work->ntime_hex));
    params.push(Json::make_string(util::format_nonce(share.nonce)));
    // BIP310: the sixth parameter is only valid while a mask is negotiated.
    if (share.work->version_mask) {
        char version_hex[16];
        std::snprintf(version_hex, sizeof(version_hex), "%08x",
                      (unsigned)share.version);
        params.push(Json::make_string(version_hex));
    }

    int id = client_->send_request("mining.submit", params);
    pending_[id] = PendingShare{share_difficulty, share.work->job_id};
}

void Miner::on_submit_response(long long id, const Json& message) {
    (void)id;
    const Json* result = message.find("result");
    if (result && result->is_bool() && result->as_bool()) {
        ++accepted_;
        util::log().info("share accepted | accepted %llu / rejected %llu",
                         (unsigned long long)accepted_,
                         (unsigned long long)rejected_);
        return;
    }
    ++rejected_;
    std::string text = "no reason given";
    const Json* error = message.find("error");
    if (error && !error->is_null()) text = json_error_text(*error);
    std::string lowered = lower_ascii(text);
    if (lowered.find("stale") != std::string::npos ||
        lowered.find("job not found") != std::string::npos) {
        ++stale_;
    }
    util::log().warn("share rejected: %s", text.c_str());
}

// ---------------------------------------------------------------------------
// status snapshot
// ---------------------------------------------------------------------------
StatusSnapshot Miner::status_snapshot() const {
    std::lock_guard<std::mutex> lock(status_mutex_);
    return status_snapshot_;
}

void Miner::refresh_status_snapshot() {
    StatusSnapshot snapshot;
    snapshot.version = std::string("btcminer ") + kVersion;
    snapshot.uptime = std::max(0.0, util::now_seconds() - started_at_);
    if (!config_.pools.empty()) {
        snapshot.pool_url = current_pool().url;
        snapshot.pool_user = current_pool().user;
        snapshot.pool_index = pool_index_ + 1;
        snapshot.pool_count = config_.pools.size();
    }
    snapshot.kernel = sha256::kernel_name();
    snapshot.threads = config_.threads;
    snapshot.hashes = pool_.hashes();
    snapshot.shares_found = shares_found_;
    snapshot.accepted = accepted_;
    snapshot.rejected = rejected_;
    snapshot.stale = stale_;
    snapshot.best_share = best_difficulty_;
    snapshot.pool_difficulty = have_difficulty_ ? difficulty_ : 0.0;
    snapshot.job_id = have_job_ ? job_.id : "";
    snapshot.version_mask = version_mask_;
    snapshot.switch_count = pool_switches_;

    if (samples_.size() >= 2) {
        double now = util::now_seconds();
        double t0 = samples_.front().first;
        uint64_t h0 = samples_.front().second;
        snapshot.hashrate = double(snapshot.hashes - h0) /
                           std::max(now - t0, 1e-9);
    }

    std::lock_guard<std::mutex> lock(status_mutex_);
    status_snapshot_ = snapshot;
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------
void Miner::stats_tick() {
    double now = util::now_seconds();
    double interval = std::max(5.0, config_.stats_interval);
    if (now - last_stats_ < interval) return;
    last_stats_ = now;

    uint64_t total = pool_.hashes();
    samples_.emplace_back(now, total);
    while (samples_.size() > 2 && now - samples_.front().first > interval * 3.0) {
        samples_.pop_front();
    }
    double t0 = samples_.front().first;
    uint64_t h0 = samples_.front().second;
    double rate = double(total - h0) / std::max(now - t0, 1e-9);

    util::log().info(
        "%s | accepted %llu | rejected %llu | best share %s | difficulty %s | job %s",
        util::format_hashrate(rate).c_str(),
        (unsigned long long)accepted_, (unsigned long long)rejected_,
        best_difficulty_ > 0.0
            ? util::format_difficulty(best_difficulty_).c_str()
            : "-",
        have_difficulty_ ? util::format_difficulty(difficulty_).c_str() : "-",
        have_job_ ? job_.id.substr(0, 16).c_str() : "-");
    refresh_status_snapshot();
}

void Miner::print_summary() {
    double elapsed = std::max(util::now_seconds() - started_at_, 1e-9);
    uint64_t total = pool_.hashes();
    util::log().info(
        "stopped | %s average | %llu hashes | %llu share(s) found | %llu accepted | "
        "%llu rejected | best share %s",
        util::format_hashrate(double(total) / elapsed).c_str(),
        (unsigned long long)total, (unsigned long long)shares_found_,
        (unsigned long long)accepted_, (unsigned long long)rejected_,
        best_difficulty_ > 0.0
            ? util::format_difficulty(best_difficulty_).c_str()
            : "-");
}

bool Miner::time_exceeded() const {
    if (!config_.has_duration) return false;
    return util::now_seconds() - started_at_ >= config_.duration;
}

void Miner::sleep_interruptible(double seconds) {
    double deadline = util::now_seconds() + seconds;
    while (!stop_.load() && util::now_seconds() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

