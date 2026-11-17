// Minimal Stratum v1 client: newline delimited JSON-RPC over TCP.
#pragma once

#include <cstdint>
#include <deque>
#include <stdexcept>
#include <string>
#include <vector>

#include "json.h"

class StratumError : public std::runtime_error {
public:
    explicit StratumError(const std::string& what) : std::runtime_error(what) {}
};

class StratumDisconnected : public StratumError {
public:
    explicit StratumDisconnected(const std::string& what)
        : StratumError(what) {}
};

struct PoolUrl {
    std::string scheme;
    std::string host;
    uint16_t port = 3333;
};

// Accepts stratum+tcp://host:port, stratum://host:port, tcp://host:port and
// plain host:port.  TLS schemes are rejected with an explicit message.
bool parse_url(const std::string& url, PoolUrl& out, std::string& error);

class StratumClient {
public:
    StratumClient(std::string host, uint16_t port);
    ~StratumClient();

    StratumClient(const StratumClient&) = delete;
    StratumClient& operator=(const StratumClient&) = delete;

    void connect(int timeout_ms = 30000);
    void close();
    bool connected() const { return socket_ != ~uintptr_t{0}; }

    // Fire and forget request; returns its id.
    int send_request(const std::string& method, const Json& params);
    // Sends a request and waits for the matching response.  Messages that
    // arrive in the meantime (including ones pipelined after the response in
    // the same TCP read) go to the backlog in arrival order.
    Json request(const std::string& method, const Json& params,
                 double timeout_seconds = 60.0);
    void respond(const Json& id, const Json& result);

    std::vector<Json> poll(double timeout_seconds);
    std::deque<Json>& backlog() { return backlog_; }
    std::vector<Json> take_backlog();

private:
    void send_raw(const Json& payload);
    std::vector<Json> read_batch(double timeout_seconds);

    std::string host_;
    uint16_t port_;
    uintptr_t socket_;
    std::string buffer_;
    std::deque<Json> backlog_;
    int next_id_ = 0;
};
