#include "stratum.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>

#ifndef _WIN32
#error "This build targets Windows (Winsock2)."
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "util.h"

namespace {

constexpr size_t kReadSize = 65536;
constexpr uintptr_t kInvalidSocket = ~uintptr_t{0};

void ensure_winsock() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw StratumError("WSAStartup failed");
        }
    });
}

std::string socket_error_text() {
    int code = WSAGetLastError();
    char* text = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, DWORD(code), 0, (LPSTR)&text, 0, nullptr);
    std::string message = text ? text : "socket error";
    if (text) LocalFree(text);
    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r' ||
            message.back() == '.')) {
        message.pop_back();
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), " (WSA %d)", code);
    return message + buf;
}

bool is_disconnect_error(int code) {
    return code == WSAECONNRESET || code == WSAECONNABORTED ||
           code == WSAENOTCONN || code == WSAESHUTDOWN;
}

}  // namespace

bool parse_url(const std::string& url, PoolUrl& out, std::string& error) {
    if (url.empty()) {
        error = "pool URL is empty";
        return false;
    }
    std::string text = url;
    if (text.find("://") == std::string::npos) text = "stratum+tcp://" + text;

    size_t scheme_end = text.find("://");
    std::string scheme = text.substr(0, scheme_end);
    for (char& c : scheme) c = char(std::tolower((unsigned char)c));

    if (scheme == "stratum+ssl" || scheme == "stratum+tls" || scheme == "ssl" ||
        scheme == "tls") {
        error = "TLS pools are not supported, use stratum+tcp";
        return false;
    }
    if (scheme != "stratum" && scheme != "stratum+tcp" && scheme != "tcp") {
        error = "unsupported URL scheme '" + scheme + "'";
        return false;
    }

    std::string rest = text.substr(scheme_end + 3);
    size_t slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    if (rest.empty()) {
        error = "pool URL has no host";
        return false;
    }

    std::string host = rest;
    std::string port_text;
    size_t colon = rest.rfind(':');
    // A colon after the last ']' (or any colon when there is no ']') separates
    // the port.
    size_t bracket = rest.rfind(']');
    if (colon != std::string::npos &&
        (bracket == std::string::npos || colon > bracket)) {
        host = rest.substr(0, colon);
        port_text = rest.substr(colon + 1);
    }
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    if (host.empty()) {
        error = "pool URL has no host";
        return false;
    }

    int port = 3333;
    if (!port_text.empty()) {
        char* stop = nullptr;
        long value = std::strtol(port_text.c_str(), &stop, 10);
        if (!stop || *stop != '\0' || value <= 0 || value > 65535) {
            error = "invalid port '" + port_text + "'";
            return false;
        }
        port = int(value);
    }
    out.scheme = scheme;
    out.host = host;
    out.port = uint16_t(port);
    return true;
}

StratumClient::StratumClient(std::string host, uint16_t port)
    : host_(std::move(host)), port_(port), socket_(kInvalidSocket) {
    ensure_winsock();
}

StratumClient::~StratumClient() { close(); }

void StratumClient::connect(int timeout_ms) {
    close();
    (void)timeout_ms;  // the OS connect timeout is used instead

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_text[16];
    std::snprintf(port_text, sizeof(port_text), "%u", unsigned(port_));

    addrinfo* results = nullptr;
    int rc = getaddrinfo(host_.c_str(), port_text, &hints, &results);
    if (rc != 0) {
        throw StratumDisconnected("cannot resolve " + host_ + ": " +
                                  gai_strerrorA(rc));
    }

    SOCKET connected = INVALID_SOCKET;
    std::string last_error = "no address";
    for (addrinfo* entry = results; entry; entry = entry->ai_next) {
        SOCKET sock = ::socket(entry->ai_family, entry->ai_socktype,
                               entry->ai_protocol);
        if (sock == INVALID_SOCKET) {
            last_error = socket_error_text();
            continue;
        }
        if (::connect(sock, entry->ai_addr, int(entry->ai_addrlen)) == 0) {
            connected = sock;
            break;
        }
        last_error = socket_error_text();
        ::closesocket(sock);
    }
    freeaddrinfo(results);

    if (connected == INVALID_SOCKET) {
        throw StratumDisconnected("cannot connect to " + host_ + ":" +
                                  std::to_string(port_) + ": " + last_error);
    }

    int one = 1;
    setsockopt(connected, IPPROTO_TCP, TCP_NODELAY, (const char*)&one,
               sizeof(one));
    setsockopt(connected, SOL_SOCKET, SO_KEEPALIVE, (const char*)&one,
               sizeof(one));

    socket_ = uintptr_t(connected);
    buffer_.clear();
    backlog_.clear();
    util::log().debug("TCP connection established to %s:%u", host_.c_str(),
                      unsigned(port_));
}

void StratumClient::close() {
    if (socket_ == kInvalidSocket) return;
    SOCKET sock = SOCKET(socket_);
    ::shutdown(sock, SD_BOTH);
    ::closesocket(sock);
    socket_ = kInvalidSocket;
    buffer_.clear();
}

void StratumClient::send_raw(const Json& payload) {
    if (socket_ == kInvalidSocket) throw StratumDisconnected("not connected");
    std::string blob = payload.dump();
    blob.push_back('\n');

    size_t sent = 0;
    while (sent < blob.size()) {
        int chunk = ::send(SOCKET(socket_), blob.data() + sent,
                           int(blob.size() - sent), 0);
        if (chunk == SOCKET_ERROR) {
            int code = WSAGetLastError();
            if (code == WSAEWOULDBLOCK) {
                fd_set write_set;
                FD_ZERO(&write_set);
                FD_SET(SOCKET(socket_), &write_set);
                timeval tv{5, 0};
                if (::select(0, nullptr, &write_set, nullptr, &tv) <= 0) {
                    throw StratumDisconnected("send timed out");
                }
                continue;
            }
            if (is_disconnect_error(code)) {
                throw StratumDisconnected("send failed: " + socket_error_text());
            }
            throw StratumDisconnected("send failed: " + socket_error_text());
        }
        sent += size_t(chunk);
    }

    std::string shown = blob;
    if (shown.size() > 500) shown = shown.substr(0, 500) + "...";
    while (!shown.empty() && (shown.back() == '\n' || shown.back() == '\r')) {
        shown.pop_back();
    }
    util::log().debug("--> %s", shown.c_str());
}

int StratumClient::send_request(const std::string& method, const Json& params) {
    int id = ++next_id_;
    Json message = Json::make_object();
    message.set("id", Json::make_int(id));
    message.set("method", Json::make_string(method));
    message.set("params", params);
    send_raw(message);
    return id;
}

void StratumClient::respond(const Json& id, const Json& result) {
    Json message = Json::make_object();
    message.set("id", id);
    message.set("result", result);
    message.set("error", Json::make_null());
    send_raw(message);
}

Json StratumClient::request(const std::string& method, const Json& params,
                            double timeout_seconds) {
    int id = send_request(method, params);
    double deadline = util::now_seconds() + timeout_seconds;

    while (true) {
        double remaining = deadline - util::now_seconds();
        if (remaining <= 0.0) {
            throw StratumError("timed out waiting for " + method + " response");
        }
        std::vector<Json> batch = read_batch(remaining);
        for (size_t i = 0; i < batch.size(); ++i) {
            const Json* message_id = batch[i].find("id");
            bool matches = message_id && message_id->is_number() &&
                           message_id->as_int(-1) == id;
            if (matches) {
                // Everything after the response arrived later; keep it.
                for (size_t j = i + 1; j < batch.size(); ++j) {
                    backlog_.push_back(std::move(batch[j]));
                }
                const Json* error = batch[i].find("error");
                if (error && !error->is_null()) {
                    throw StratumError(method + " failed: " + error->dump());
                }
                const Json* result = batch[i].find("result");
                return result ? *result : Json();
            }
            backlog_.push_back(std::move(batch[i]));
        }
    }
}

std::vector<Json> StratumClient::take_backlog() {
    std::vector<Json> messages(backlog_.begin(), backlog_.end());
    backlog_.clear();
    return messages;
}

std::vector<Json> StratumClient::read_batch(double timeout_seconds) {
    if (socket_ == kInvalidSocket) throw StratumDisconnected("not connected");

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(SOCKET(socket_), &read_set);
    timeval tv;
    double clamped = std::max(0.0, timeout_seconds);
    tv.tv_sec = long(clamped);
    tv.tv_usec = long((clamped - double(tv.tv_sec)) * 1e6);
    int ready = ::select(0, &read_set, nullptr, nullptr, &tv);
    if (ready == SOCKET_ERROR) {
        throw StratumDisconnected("select failed: " + socket_error_text());
    }
    if (ready == 0) return {};

    char chunk[kReadSize];
    int received = ::recv(SOCKET(socket_), chunk, int(sizeof(chunk)), 0);
    if (received == 0) throw StratumDisconnected("pool closed the connection");
    if (received == SOCKET_ERROR) {
        throw StratumDisconnected("receive failed: " + socket_error_text());
    }
    buffer_.append(chunk, size_t(received));

    std::vector<Json> messages;
    size_t start = 0;
    while (true) {
        size_t newline = buffer_.find('\n', start);
        if (newline == std::string::npos) break;
        std::string line = buffer_.substr(start, newline - start);
        start = newline + 1;
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }
        if (line.empty()) continue;
        std::string error;
        Json message = Json::parse(line, &error);
        if (!error.empty()) {
            util::log().warn("ignoring malformed line from pool: %.200s",
                             line.c_str());
            continue;
        }
        util::log().debug("<-- %.500s",
                          message.dump().c_str());
        messages.push_back(std::move(message));
    }
    buffer_.erase(0, start);
    return messages;
}

std::vector<Json> StratumClient::poll(double timeout_seconds) {
    return read_batch(timeout_seconds);
}
