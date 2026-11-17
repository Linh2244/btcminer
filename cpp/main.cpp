// Command line entry point: argument parsing, config file and self-test.
#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "cpu.h"
#include "job.h"
#include "json.h"
#include "miner.h"
#include "sha256.h"
#include "util.h"
#include "worker.h"

namespace {

constexpr const char* kVersion = "1.3.0";
constexpr const char* kDefaultConfigFile = "config.json";

//: Block 125552 - the classic SHA-256d reference vector.
constexpr const char* kReferenceHeaderHex =
    "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
    "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
    "c7f5d74df2b9441a42a14695";
constexpr const char* kReferenceHash =
    "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d";

struct Options {
    bool help = false;
    bool version = false;
    bool self_test = false;
    bool have_benchmark = false;
    double benchmark = 30.0;

    std::string url;
    std::string user;
    std::string password;
    std::string config_file;
    std::string user_agent;
    std::string log_level;

    std::string api_bind;
    bool no_api = false;
    std::string affinity;
    std::string priority;
    bool have_cpu_limit = false;
    int cpu_limit = 100;
    bool tls_insecure = false;
    bool no_version_rolling = false;

    bool have_processes = false;
    int processes = 0;
    bool have_duration = false;
    double duration = 0.0;
    bool have_stats = false;
    double stats_interval = 0.0;
    bool have_idle = false;
    double idle_timeout = 0.0;
    bool have_suggest = false;
    double suggest_difficulty = 0.0;
    bool have_seed = false;
    uint64_t seed = 0;
};

int physical_cores() {
    DWORD length = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length);
    if (length == 0) return 0;
    std::vector<char> buffer(length);
    if (!GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                buffer.data()),
            &length)) {
        return 0;
    }
    int cores = 0;
    size_t offset = 0;
    while (offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) <= length) {
        auto* info =
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                buffer.data() + offset);
        if (info->Relationship == RelationProcessorCore) ++cores;
        if (info->Size == 0) break;
        offset += info->Size;
    }
    return cores;
}

int default_threads() {
    // SMT still helps the SIMD kernels (measured ~40% more hashrate on a
    // 4c/8t laptop), so default to the logical processor count.
    unsigned logical = std::thread::hardware_concurrency();
    if (logical > 0) return int(logical);
    int cores = physical_cores();
    return cores > 0 ? cores : 1;
}

bool parse_double(const std::string& text, double& out) {
    char* stop = nullptr;
    double value = std::strtod(text.c_str(), &stop);
    if (!stop || *stop != '\0' || stop == text.c_str()) return false;
    out = value;
    return true;
}

bool parse_u64(const std::string& text, uint64_t& out) {
    char* stop = nullptr;
    unsigned long long value = std::strtoull(text.c_str(), &stop, 10);
    if (!stop || *stop != '\0' || stop == text.c_str()) return false;
    out = value;
    return true;
}

void print_help() {
    std::printf(
        "usage: btcminer [-h] [-o URL] [-u USER] [-p PASSWORD] [-t THREADS]\n"
        "                [-c CONFIG] [--duration DURATION]\n"
        "                [--stats-interval STATS_INTERVAL]\n"
        "                [--idle-timeout IDLE_TIMEOUT]\n"
        "                [--suggest-difficulty SUGGEST_DIFFICULTY]\n"
        "                [--user-agent USER_AGENT] [--seed SEED]\n"
        "                [--api-bind HOST:PORT] [--no-api]\n"
        "                [--affinity LIST] [--priority LEVEL] [--cpu-limit N]\n"
        "                [--tls-insecure] [--no-version-rolling]\n"
        "                [--benchmark [SECONDS]] [--self-test]\n"
        "                [--log-level {DEBUG,INFO,WARNING,ERROR}] [--version]\n"
        "\n"
        "CPU SHA-256d Bitcoin miner speaking Stratum v1.\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  -o, --url URL         pool URL, e.g. stratum+tcp://host:3333\n"
        "  -u, --user USER       worker name, usually <btc-address>[.<worker>]\n"
        "  -p, --password PASS   worker password (pools usually ignore it)\n"
        "  -t, --processes N     number of mining threads (default: logical CPUs)\n"
        "  -c, --config FILE     JSON config file (default: ./config.json)\n"
        "  --duration N          stop after N seconds (useful for testing)\n"
        "  --stats-interval N    seconds between hashrate reports\n"
        "  --idle-timeout N      reconnect when the pool is silent for N seconds\n"
        "  --suggest-difficulty N  ask the pool for this share difficulty\n"
        "  --user-agent STRING   version string sent to the pool\n"
        "  --seed N              RNG seed (reproducible nonce start)\n"
        "  --api-bind HOST:PORT  status API address (default 127.0.0.1:4068)\n"
        "  --no-api              disable the local status API\n"
        "  --affinity LIST       CPUs for workers, e.g. 0-3,6 or 0xF\n"
        "  --priority LEVEL      idle, below, normal, above, high or realtime\n"
        "  --cpu-limit N         approximate CPU usage limit, 1-100 percent\n"
        "  --tls-insecure        skip TLS certificate checks (testing only)\n"
        "  --no-version-rolling  do not negotiate BIP310 version rolling\n"
        "  --benchmark [N]       hash locally for N seconds (default 30)\n"
        "  --self-test           verify hashing, target math and a real mining run\n"
        "  --log-level LEVEL     DEBUG, INFO, WARNING or ERROR\n"
        "  --version             show program version and exit\n");
}

bool parse_args(int argc, char** argv, Options& options, std::string& error) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        std::string value;
        bool inline_value = false;
        size_t equals = arg.find('=');
        if (arg.rfind("--", 0) == 0 && equals != std::string::npos) {
            value = arg.substr(equals + 1);
            arg = arg.substr(0, equals);
            inline_value = true;
        }

        auto take_value = [&](std::string& target) -> bool {
            if (inline_value) {
                target = value;
                return true;
            }
            if (i + 1 >= argc) {
                error = "missing value for " + arg;
                return false;
            }
            target = argv[++i];
            return true;
        };

        if (arg == "-h" || arg == "--help") {
            options.help = true;
        } else if (arg == "--version") {
            options.version = true;
        } else if (arg == "--self-test") {
            options.self_test = true;
        } else if (arg == "-o" || arg == "--url") {
            if (!take_value(options.url)) return false;
        } else if (arg == "-u" || arg == "--user") {
            if (!take_value(options.user)) return false;
        } else if (arg == "-p" || arg == "--password") {
            if (!take_value(options.password)) return false;
        } else if (arg == "-c" || arg == "--config") {
            if (!take_value(options.config_file)) return false;
        } else if (arg == "--user-agent") {
            if (!take_value(options.user_agent)) return false;
        } else if (arg == "--log-level") {
            if (!take_value(options.log_level)) return false;
        } else if (arg == "--api-bind") {
            if (!take_value(options.api_bind)) return false;
        } else if (arg == "--no-api") {
            options.no_api = true;
        } else if (arg == "--affinity") {
            if (!take_value(options.affinity)) return false;
        } else if (arg == "--priority") {
            if (!take_value(options.priority)) return false;
        } else if (arg == "--cpu-limit") {
            std::string text;
            if (!take_value(text)) return false;
            long long value = std::strtoll(text.c_str(), nullptr, 10);
            if (value < 1 || value > 100) {
                error = "invalid CPU limit (1-100): " + text;
                return false;
            }
            options.have_cpu_limit = true;
            options.cpu_limit = int(value);
        } else if (arg == "--tls-insecure") {
            options.tls_insecure = true;
        } else if (arg == "--no-version-rolling") {
            options.no_version_rolling = true;
        } else if (arg == "-t" || arg == "--processes") {
            std::string text;
            if (!take_value(text)) return false;
            long long value = std::strtoll(text.c_str(), nullptr, 10);
            if (value < 1 || value > 1024) {
                error = "invalid number of processes: " + text;
                return false;
            }
            options.have_processes = true;
            options.processes = int(value);
        } else if (arg == "--duration") {
            std::string text;
            if (!take_value(text)) return false;
            if (!parse_double(text, options.duration)) {
                error = "invalid duration: " + text;
                return false;
            }
            options.have_duration = true;
        } else if (arg == "--stats-interval") {
            std::string text;
            if (!take_value(text)) return false;
            if (!parse_double(text, options.stats_interval)) {
                error = "invalid stats interval: " + text;
                return false;
            }
            options.have_stats = true;
        } else if (arg == "--idle-timeout") {
            std::string text;
            if (!take_value(text)) return false;
            if (!parse_double(text, options.idle_timeout)) {
                error = "invalid idle timeout: " + text;
                return false;
            }
            options.have_idle = true;
        } else if (arg == "--suggest-difficulty") {
            std::string text;
            if (!take_value(text)) return false;
            if (!parse_double(text, options.suggest_difficulty)) {
                error = "invalid suggested difficulty: " + text;
                return false;
            }
            options.have_suggest = true;
        } else if (arg == "--seed") {
            std::string text;
            if (!take_value(text)) return false;
            if (!parse_u64(text, options.seed)) {
                error = "invalid seed: " + text;
                return false;
            }
            options.have_seed = true;
        } else if (arg == "--benchmark") {
            options.have_benchmark = true;
            options.benchmark = 30.0;
            if (inline_value) {
                if (!parse_double(value, options.benchmark)) {
                    error = "invalid benchmark duration: " + value;
                    return false;
                }
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                double parsed = 0.0;
                if (parse_double(argv[i + 1], parsed)) {
                    options.benchmark = parsed;
                    ++i;
                }
            }
            if (options.benchmark <= 0.0) {
                error = "benchmark duration must be positive";
                return false;
            }
        } else {
            error = "unrecognized argument: " + arg;
            return false;
        }
    }
    return true;
}

bool read_file(const std::string& path, std::string& text) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    text.assign(std::istreambuf_iterator<char>(stream),
                std::istreambuf_iterator<char>());
    return true;
}

struct Settings {
    std::vector<PoolCredentials> pools;
    std::string url;
    std::string user;
    std::string password = "x";
    std::string user_agent = std::string("btcminer-cpp/") + kVersion;
    std::string log_level = "INFO";
    int threads = 0;
    double stats_interval = 30.0;
    double idle_timeout = 300.0;
    bool has_duration = false;
    double duration = 0.0;
    bool has_suggest = false;
    double suggest_difficulty = 0.0;
    bool has_seed = false;
    uint64_t seed = 0;

    bool version_rolling = true;
    bool tls_verify = true;
    bool api_enabled = true;
    std::string api_bind = "127.0.0.1";
    int api_port = 4068;
    std::string affinity;
    uint64_t affinity_mask = 0;
    std::string priority = "normal";
    int cpu_limit = 100;
};

// Splits "host:port" (bracketed IPv6 allowed) into its parts.
bool split_host_port(const std::string& text, std::string& host, int& port,
                     std::string& error) {
    std::string body = text;
    size_t colon = body.rfind(':');
    if (colon == std::string::npos) {
        error = "expected HOST:PORT";
        return false;
    }
    host = body.substr(0, colon);
    std::string port_text = body.substr(colon + 1);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    if (host.empty()) host = "127.0.0.1";
    char* stop = nullptr;
    long value = std::strtol(port_text.c_str(), &stop, 10);
    if (!stop || *stop != '\0' || value < 1 || value > 65535) {
        error = "invalid port '" + port_text + "'";
        return false;
    }
    port = int(value);
    return true;
}

bool apply_json_config(const Json& config, Settings& settings,
                       std::string& error) {
    if (!config.is_object()) {
        error = "configuration must be a JSON object";
        return false;
    }
    auto string_field = [&](const char* key, std::string& target) {
        const Json* value = config.find(key);
        if (value && value->is_string()) target = value->as_string();
    };
    auto number_field = [&](const char* key, double& target) -> bool {
        const Json* value = config.find(key);
        if (!value || value->is_null()) return true;
        if (value->is_number()) {
            target = value->as_double();
            return true;
        }
        if (value->is_string()) {
            double parsed = 0.0;
            if (parse_double(value->as_string(), parsed)) {
                target = parsed;
                return true;
            }
        }
        error = std::string("config field '") + key + "' must be a number";
        return false;
    };

    auto bool_field = [&](const char* key, bool& target) -> bool {
        const Json* value = config.find(key);
        if (!value || value->is_null()) return true;
        if (!value->is_bool()) {
            error = std::string("config field '") + key + "' must be true or false";
            return false;
        }
        target = value->as_bool();
        return true;
    };

    string_field("url", settings.url);
    string_field("user", settings.user);
    string_field("password", settings.password);
    string_field("user_agent", settings.user_agent);
    string_field("log_level", settings.log_level);
    if (!bool_field("version_rolling", settings.version_rolling)) return false;
    if (!bool_field("tls_verify", settings.tls_verify)) return false;

    const Json* pool_list = config.find("pools");
    if (pool_list && !pool_list->is_null()) {
        if (!pool_list->is_array()) {
            error = "config field 'pools' must be a list";
            return false;
        }
        for (size_t i = 0; i < pool_list->size(); ++i) {
            const Json& entry = (*pool_list)[i];
            if (!entry.is_object()) {
                error = "each pool must be a JSON object";
                return false;
            }
            const Json* pool_url = entry.find("url");
            if (!pool_url || !pool_url->is_string() ||
                pool_url->as_string().empty()) {
                error = "pool url must be a non-empty string";
                return false;
            }
            PoolCredentials pool;
            pool.url = pool_url->as_string();
            const Json* pool_user = entry.find("user");
            if (pool_user && pool_user->is_string()) {
                pool.user = pool_user->as_string();
            }
            const Json* pool_password = entry.find("password");
            if (pool_password && pool_password->is_string()) {
                pool.password = pool_password->as_string();
            }
            settings.pools.push_back(std::move(pool));
        }
    }

    const Json* api = config.find("api");
    if (api && !api->is_null()) {
        if (!api->is_object()) {
            error = "config field 'api' must be an object";
            return false;
        }
        const Json* enabled = api->find("enabled");
        if (enabled && enabled->is_bool()) settings.api_enabled = enabled->as_bool();
        const Json* bind = api->find("bind");
        if (bind && bind->is_string()) settings.api_bind = bind->as_string();
        const Json* port = api->find("port");
        if (port && port->is_number()) settings.api_port = int(port->as_int(4068));
    }

    const Json* cpu_config = config.find("cpu");
    if (cpu_config && !cpu_config->is_null()) {
        if (!cpu_config->is_object()) {
            error = "config field 'cpu' must be an object";
            return false;
        }
        const Json* affinity = cpu_config->find("affinity");
        if (affinity && affinity->is_string()) {
            settings.affinity = affinity->as_string();
        } else if (affinity && affinity->is_number()) {
            char buffer[32];
            std::snprintf(buffer, sizeof(buffer), "0x%llx",
                          (unsigned long long)affinity->as_int(0));
            settings.affinity = buffer;
        } else if (affinity && !affinity->is_null()) {
            error = "config field 'cpu.affinity' must be a string or a mask";
            return false;
        }
        const Json* priority = cpu_config->find("priority");
        if (priority && priority->is_string()) {
            settings.priority = priority->as_string();
        }
        const Json* limit = cpu_config->find("limit");
        if (limit && limit->is_number()) settings.cpu_limit = int(limit->as_int(100));
    }

    double processes = 0.0;
    if (!number_field("processes", processes)) return false;
    if (processes >= 1.0) settings.threads = int(processes);
    if (!number_field("stats_interval", settings.stats_interval)) return false;
    if (!number_field("idle_timeout", settings.idle_timeout)) return false;
    if (config.find("duration")) {
        if (!number_field("duration", settings.duration)) return false;
        settings.has_duration = settings.duration > 0.0;
    }
    if (config.find("suggest_difficulty")) {
        if (!number_field("suggest_difficulty", settings.suggest_difficulty)) {
            return false;
        }
        settings.has_suggest = settings.suggest_difficulty > 0.0;
    }
    if (config.find("seed")) {
        const Json* value = config.find("seed");
        if (value->is_number()) {
            settings.seed = uint64_t(value->as_int(0));
            settings.has_seed = true;
        }
    }
    return true;
}

bool build_settings(const Options& options, Settings& settings,
                    std::string& error) {
    std::string path = options.config_file;
    if (path.empty()) {
        std::string probe;
        if (read_file(kDefaultConfigFile, probe)) path = kDefaultConfigFile;
    }
    if (!path.empty()) {
        std::string text;
        if (!read_file(path, text)) {
            error = "cannot read " + path;
            return false;
        }
        std::string parse_error;
        Json config = Json::parse(text, &parse_error);
        if (!parse_error.empty()) {
            error = "cannot parse " + path + ": " + parse_error;
            return false;
        }
        if (!apply_json_config(config, settings, error)) return false;
        util::log().debug("configuration loaded from %s", path.c_str());
    }

    if (!options.url.empty()) settings.url = options.url;
    if (!options.user.empty()) settings.user = options.user;
    if (!options.password.empty()) settings.password = options.password;
    if (!options.user_agent.empty()) settings.user_agent = options.user_agent;
    if (!options.log_level.empty()) settings.log_level = options.log_level;
    if (options.have_processes) settings.threads = options.processes;
    if (options.have_stats) settings.stats_interval = options.stats_interval;
    if (options.have_idle) settings.idle_timeout = options.idle_timeout;
    if (options.have_duration) {
        settings.has_duration = true;
        settings.duration = options.duration;
    }
    if (options.have_suggest) {
        settings.has_suggest = true;
        settings.suggest_difficulty = options.suggest_difficulty;
    }
    if (options.have_seed) {
        settings.has_seed = true;
        settings.seed = options.seed;
    }
    if (!options.api_bind.empty()) {
        std::string bind_error;
        if (!split_host_port(options.api_bind, settings.api_bind,
                             settings.api_port, bind_error)) {
            error = "invalid --api-bind: " + bind_error;
            return false;
        }
    }
    if (options.no_api) settings.api_enabled = false;
    if (!options.affinity.empty()) settings.affinity = options.affinity;
    if (!options.priority.empty()) settings.priority = options.priority;
    if (options.have_cpu_limit) settings.cpu_limit = options.cpu_limit;
    if (options.tls_insecure) settings.tls_verify = false;
    if (options.no_version_rolling) settings.version_rolling = false;

    if (!settings.affinity.empty()) {
        std::string affinity_error;
        if (!cpu::parse_affinity(settings.affinity, settings.affinity_mask,
                                 affinity_error)) {
            error = "invalid affinity: " + affinity_error;
            return false;
        }
    }
    if (!cpu::valid_priority(settings.priority)) {
        error = "invalid priority '" + settings.priority +
                "' (use idle, below, normal, above, high or realtime)";
        return false;
    }
    if (settings.cpu_limit < 1 || settings.cpu_limit > 100) {
        error = "CPU limit must be between 1 and 100 percent";
        return false;
    }
    if (settings.api_port < 1 || settings.api_port > 65535) {
        error = "invalid status API port";
        return false;
    }

    // Build the pool list: `pools` wins, otherwise the top-level URL is the
    // primary pool.  CLI overrides patch the primary entry, and the shared
    // user/password fill pools that omit them.
    if (!settings.pools.empty()) {
        if (!settings.url.empty()) settings.pools[0].url = settings.url;
        if (!settings.user.empty()) settings.pools[0].user = settings.user;
        if (!settings.password.empty()) {
            settings.pools[0].password = settings.password;
        }
        for (PoolCredentials& pool : settings.pools) {
            if (pool.user.empty()) pool.user = settings.user;
            if (pool.password.empty()) pool.password = settings.password;
        }
    } else if (!settings.url.empty()) {
        PoolCredentials pool;
        pool.url = settings.url;
        pool.user = settings.user;
        pool.password = settings.password;
        settings.pools.push_back(std::move(pool));
    }

    if (settings.threads < 1) {
        if (settings.affinity_mask) {
            settings.threads = std::max(1, cpu::count_cpus(settings.affinity_mask));
        } else {
            settings.threads = default_threads();
        }
    }
    return true;
}

int run_self_test(const MinerConfig& config) {
    int failures = 0;
    util::Logger& log = util::log();

    log.info("self-test 1/4: SHA-256d reference vector (block 125552)");
    uint8_t header[80];
    std::vector<uint8_t> decoded;
    if (!util::hex_decode(kReferenceHeaderHex, decoded, 80, nullptr)) {
        log.error("  FAIL bad reference header");
        return 1;
    }
    std::memcpy(header, decoded.data(), 80);
    uint8_t raw[32];
    uint8_t display[32];
    sha256::hash_header(header, raw);
    for (int i = 0; i < 32; ++i) display[i] = raw[31 - i];
    std::string hex = util::hex_encode(display, 32);
    if (hex == kReferenceHash) {
        log.info("  OK   header hashes to %s", hex.c_str());
    } else {
        log.error("  FAIL expected %s, got %s", kReferenceHash, hex.c_str());
        ++failures;
    }

    if (sha256::has_avx2()) {
        sha256::Midstate mid;
        sha256::build_midstate(mid, header);
        uint32_t seed = 0x12345678u;
        int mismatches = 0;
        for (int i = 0; i < 2048; i += 8) {
            seed = seed * 1103515245u + 12345u;
            uint8_t digests[8][32];
            sha256::hash8_avx2(mid, seed, digests);
            for (int lane = 0; lane < 8; ++lane) {
                uint8_t scalar_raw[32];
                uint8_t scalar_be[32];
                sha256::hash_nonce_scalar(mid, seed + uint32_t(lane), scalar_raw);
                for (int j = 0; j < 32; ++j) scalar_be[j] = scalar_raw[31 - j];
                if (std::memcmp(scalar_be, digests[lane], 32) != 0) ++mismatches;
            }
        }
        if (mismatches) {
            log.error("  FAIL AVX2 kernel differs from scalar in %d cases",
                      mismatches);
            ++failures;
        } else {
            log.info("  OK   AVX2 kernel matches scalar (2048 nonces)");
        }
    } else {
        log.info("  --   AVX2 not available, using the scalar kernel");
    }

    if (sha256::has_sha_ni()) {
        sha256::Midstate mid;
        sha256::build_midstate(mid, header);
        const uint32_t nonce = uint32_t(header[76]) |
                               (uint32_t(header[77]) << 8) |
                               (uint32_t(header[78]) << 16) |
                               (uint32_t(header[79]) << 24);
        uint8_t ni_raw[32];
        uint8_t ni_display[32];
        sha256::hash_nonce_sha_ni(mid, nonce, ni_raw);
        for (int i = 0; i < 32; ++i) ni_display[i] = ni_raw[31 - i];
        hex = util::hex_encode(ni_display, 32);
        if (hex == kReferenceHash) {
            log.info("  OK   SHA-NI hashes block 125552 to %s", hex.c_str());
        } else {
            log.error("  FAIL SHA-NI expected %s, got %s", kReferenceHash,
                      hex.c_str());
            ++failures;
        }

        int mismatches = 0;
        uint32_t seed = 0x9e3779b9u;
        for (int i = 0; i < 2048; ++i) {
            seed = seed * 1103515245u + 12345u;
            uint8_t scalar_raw[32];
            uint8_t ni_raw2[32];
            sha256::hash_nonce_scalar(mid, seed, scalar_raw);
            sha256::hash_nonce_sha_ni(mid, seed, ni_raw2);
            if (std::memcmp(scalar_raw, ni_raw2, 32) != 0) ++mismatches;
        }
        if (mismatches) {
            log.error("  FAIL SHA-NI kernel differs from scalar in %d cases",
                      mismatches);
            ++failures;
        } else {
            log.info("  OK   SHA-NI kernel matches scalar (2048 nonces)");
        }
    } else {
        log.info("  --   SHA-NI not available on this CPU");
    }

    log.info("self-test 2/4: difficulty <-> target conversion");
    uint8_t target[32];
    util::difficulty_to_target(1.0, target);
    uint8_t expected[32] = {0};
    expected[4] = 0xff;
    expected[5] = 0xff;
    if (std::memcmp(target, expected, 32) != 0) {
        log.error("  FAIL difficulty 1 target is %s",
                  util::hex_encode(target, 32).c_str());
        ++failures;
    }

    util::difficulty_to_target(2.0, target);
    std::memset(expected, 0, 32);
    expected[4] = 0x7f;
    expected[5] = 0xff;
    expected[6] = 0x80;
    if (std::memcmp(target, expected, 32) != 0) {
        log.error("  FAIL difficulty 2 target is %s",
                  util::hex_encode(target, 32).c_str());
        ++failures;
    }

    util::difficulty_to_target(0.5, target);
    std::memset(expected, 0, 32);
    expected[3] = 0x01;
    expected[4] = 0xff;
    expected[5] = 0xfe;
    if (std::memcmp(target, expected, 32) != 0) {
        log.error("  FAIL difficulty 0.5 target is %s",
                  util::hex_encode(target, 32).c_str());
        ++failures;
    }

    double roundtrip = util::target_to_difficulty(target);
    if (!(roundtrip > 0.4999 && roundtrip < 0.5001)) {
        log.error("  FAIL target_to_difficulty round trip: %f", roundtrip);
        ++failures;
    }
    if (!failures) {
        util::difficulty_to_target(1.0, target);
        log.info("  OK   diff 1 target = %s",
                 util::hex_encode(target, 32).c_str());
    }

    log.info("self-test 3/4: BIP310 version rolling");

    struct DepositCase {
        uint32_t value;
        uint32_t mask;
        uint32_t expected;
    };
    const DepositCase deposit_cases[] = {
        {0, 0x1fffe000u, 0x00000000u},
        {1, 0x1fffe000u, 0x00002000u},
        {0xffffu, 0x1fffe000u, 0x1fffe000u},
        {0x8000u, 0x1fffe000u, 0x10000000u},
        {3, 0x00000003u, 0x00000003u},
        {3, 0x0000000au, 0x0000000au},
        {0xffffffffu, 0x0000000fu, 0x0000000fu},
    };
    bool deposit_ok = true;
    for (const DepositCase& item : deposit_cases) {
        uint32_t got = deposit_bits(item.value, item.mask);
        if (got != item.expected) {
            log.error("  FAIL deposit_bits(%08x, %08x) = %08x, expected %08x",
                      (unsigned)item.value, (unsigned)item.mask,
                      (unsigned)got, (unsigned)item.expected);
            deposit_ok = false;
        }
    }

    // A midstate rebuilt for a rolled version must hash exactly like a full
    // 80-byte header carrying that version.
    const uint32_t test_mask = 0x1fffe000u;
    const uint32_t base_version = 0x20000000u;
    const uint32_t nonce = 0x12345678u;
    uint8_t rolled_header[80];
    std::vector<uint8_t> roll_noise = util::random_bytes(80);
    std::memcpy(rolled_header, roll_noise.data(), 80);
    std::memset(rolled_header + 76, 0, 4);
    uint32_t rolled_version =
        (base_version & ~test_mask) | deposit_bits(31337, test_mask);
    set_header_version(rolled_header, rolled_version);

    sha256::Midstate rolled_mid;
    sha256::build_midstate(rolled_mid, rolled_header);
    uint8_t via_mid[32];
    sha256::hash_nonce(rolled_mid, nonce, via_mid);

    uint8_t full_header[80];
    std::memcpy(full_header, rolled_header, 80);
    full_header[76] = uint8_t(nonce);
    full_header[77] = uint8_t(nonce >> 8);
    full_header[78] = uint8_t(nonce >> 16);
    full_header[79] = uint8_t(nonce >> 24);
    uint8_t via_header[32];
    sha256::hash_header(full_header, via_header);
    bool midstate_ok = std::memcmp(via_mid, via_header, 32) == 0;

    if (deposit_ok && midstate_ok) {
        log.info("  OK   deposit_bits vectors and rolled midstate (%08x)",
                 (unsigned)rolled_version);
    } else {
        if (!midstate_ok) {
            log.error("  FAIL rolled midstate does not match the full header");
        }
        ++failures;
    }

    log.info("self-test 4/4: mining an easy share (%d thread(s), difficulty 1e-05)",
             config.threads);
    sha256::Midstate mid;
    uint8_t full[80];
    std::vector<uint8_t> noise = util::random_bytes(80);
    std::memcpy(full, noise.data(), 80);
    sha256::build_midstate(mid, full);

    std::shared_ptr<Work> work = std::make_shared<Work>();
    work->generation = 1;
    work->mid = mid;
    util::difficulty_to_target(1e-5, work->target);
    work->job_id = "self-test";

    WorkerPool pool(std::max(1, config.threads), 12345);
    std::vector<Share> shares;
    double started = util::now_seconds();
    pool.start();
    pool.publish(work);
    while (util::now_seconds() - started < 30.0 && shares.size() < 3) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        for (Share& share : pool.drain_shares()) shares.push_back(share);
    }
    pool.stop();

    if (shares.empty()) {
        log.error("  FAIL no share found in 30 s");
        ++failures;
    } else {
        bool valid = true;
        for (const Share& share : shares) {
            uint8_t verify_raw[32];
            uint8_t verify_be[32];
            sha256::hash_nonce_scalar(share.mid, share.nonce, verify_raw);
            for (int i = 0; i < 32; ++i) verify_be[i] = verify_raw[31 - i];
            if (std::memcmp(verify_be, work->target, 32) > 0) valid = false;
        }
        if (!valid) {
            log.error("  FAIL invalid share found by the worker kernel");
            ++failures;
        } else {
            log.info("  OK   %zu share(s) verified in %.1f s", shares.size(),
                     util::now_seconds() - started);
        }
    }

    if (failures) {
        log.error("self-test FAILED (%d problem(s))", failures);
        return 1;
    }
    log.info("self-test PASSED");
    return 0;
}

Miner* g_miner = nullptr;

void on_sigint(int) {
    if (g_miner) g_miner->request_stop();
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    std::string error;
    if (!parse_args(argc, argv, options, error)) {
        std::fprintf(stderr, "btcminer: %s\n", error.c_str());
        std::fprintf(stderr, "try 'btcminer --help'\n");
        return 2;
    }
    if (options.help) {
        print_help();
        return 0;
    }
    if (options.version) {
        std::printf("btcminer %s\n", kVersion);
        return 0;
    }

    Settings settings;
    util::Level level = util::Level::Info;
    if (!options.log_level.empty()) {
        bool ok = false;
        level = util::Logger::parse_level(options.log_level, &ok);
        if (!ok) {
            std::fprintf(stderr, "btcminer: invalid log level '%s'\n",
                         options.log_level.c_str());
            return 2;
        }
    }
    util::log().set_level(level);

    if (!build_settings(options, settings, error)) {
        std::fprintf(stderr, "btcminer: %s\n", error.c_str());
        return 2;
    }
    util::log().set_level(util::Logger::parse_level(settings.log_level));

    MinerConfig config;
    config.pools = settings.pools;
    config.user_agent = settings.user_agent;
    config.threads = settings.threads;
    config.stats_interval = settings.stats_interval;
    config.idle_timeout = settings.idle_timeout;
    config.has_duration = settings.has_duration;
    config.duration = settings.duration;
    config.has_suggest = settings.has_suggest;
    config.suggest_difficulty = settings.suggest_difficulty;
    config.has_seed = settings.has_seed;
    config.seed = settings.seed;
    config.version_rolling = settings.version_rolling;
    config.tls_verify = settings.tls_verify;
    config.api_enabled = settings.api_enabled;
    config.api_bind = settings.api_bind;
    config.api_port = uint16_t(settings.api_port);
    config.affinity_mask = settings.affinity_mask;
    config.priority = settings.priority;
    config.cpu_limit = settings.cpu_limit;

    if (options.self_test) return run_self_test(config);

    try {
        if (!options.have_benchmark) {
            if (config.pools.empty()) {
                std::fprintf(stderr,
                             "btcminer: missing pool URL: pass -o/--url or "
                             "create config.json\n");
                return 2;
            }
            for (size_t i = 0; i < config.pools.size(); ++i) {
                const PoolCredentials& pool = config.pools[i];
                if (pool.user.empty()) {
                    std::fprintf(stderr,
                                 "btcminer: pool %zu has no worker name: pass "
                                 "-u/--user\n",
                                 i + 1);
                    return 2;
                }
                PoolUrl parsed_url;
                std::string url_error;
                if (!parse_url(pool.url, parsed_url, url_error)) {
                    std::fprintf(stderr, "btcminer: pool %zu: %s\n", i + 1,
                                 url_error.c_str());
                    return 2;
                }
            }
        }

        std::string priority_error;
        if (!cpu::apply_process_priority(settings.priority, priority_error)) {
            std::fprintf(stderr, "btcminer: %s\n", priority_error.c_str());
        }

        Miner miner(config);
        if (options.have_benchmark) {
            miner.benchmark(options.benchmark);
            return 0;
        }
        g_miner = &miner;
        std::signal(SIGINT, on_sigint);
        std::signal(SIGTERM, on_sigint);
        miner.run();
        g_miner = nullptr;
    } catch (const std::exception& exc) {
        std::fprintf(stderr, "btcminer: %s\n", exc.what());
        return 1;
    }
    return 0;
}
