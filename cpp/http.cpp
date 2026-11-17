#include "http.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef _WIN32
#error "This build targets Windows (Winsock2)."
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "json.h"
#include "util.h"

namespace {

constexpr uintptr_t kInvalidSocket = ~uintptr_t{0};

void ensure_winsock() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup failed");
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
    char suffix[32];
    std::snprintf(suffix, sizeof(suffix), " (WSA %d)", code);
    return message + suffix;
}

std::string http_status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 404: return "Not Found";
        default: return "Error";
    }
}

}  // namespace

StatusServer::StatusServer(std::string bind_host, uint16_t port, SnapshotFn snapshot)
    : bind_host_(std::move(bind_host)),
      port_(port),
      snapshot_(std::move(snapshot)) {
    if (bind_host_.empty()) bind_host_ = "127.0.0.1";
    ensure_winsock();
}

StatusServer::~StatusServer() { stop(); }

void StatusServer::start() {
    if (listener_ != kInvalidSocket) return;

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    char port_text[16];
    std::snprintf(port_text, sizeof(port_text), "%u", unsigned(port_));

    addrinfo* results = nullptr;
    int rc = getaddrinfo(bind_host_.c_str(), port_text, &hints, &results);
    if (rc != 0) {
        throw std::runtime_error("cannot resolve status API bind address: " +
                                 std::string(gai_strerrorA(rc)));
    }

    SOCKET listen_socket = INVALID_SOCKET;
    for (addrinfo* entry = results; entry; entry = entry->ai_next) {
        listen_socket = ::socket(entry->ai_family, entry->ai_socktype,
                                 entry->ai_protocol);
        if (listen_socket == INVALID_SOCKET) {
            continue;
        }
        int one = 1;
        setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,
                   (const char*)&one, sizeof(one));
        if (::bind(listen_socket, entry->ai_addr, int(entry->ai_addrlen)) == 0) {
            break;
        }
        ::closesocket(listen_socket);
        listen_socket = INVALID_SOCKET;
    }
    freeaddrinfo(results);

    if (listen_socket == INVALID_SOCKET) {
        throw std::runtime_error("cannot bind status API to " + bind_host_ +
                                 ":" + std::to_string(port_) + ": " +
                                 socket_error_text());
    }

    if (::listen(listen_socket, 5) == SOCKET_ERROR) {
        ::closesocket(listen_socket);
        throw std::runtime_error("cannot listen on status API: " +
                                 socket_error_text());
    }

    listener_ = uintptr_t(listen_socket);
    thread_ = std::thread(&StatusServer::listen_loop, this);
}

void StatusServer::stop() {
    stop_.store(true, std::memory_order_relaxed);
    if (listener_ != kInvalidSocket) {
        SOCKET sock = SOCKET(listener_);
        ::shutdown(sock, SD_BOTH);
        ::closesocket(sock);
        listener_ = kInvalidSocket;
    }
    if (thread_.joinable()) thread_.join();
}

void StatusServer::listen_loop() {
    while (!stop_.load(std::memory_order_relaxed)) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(SOCKET(listener_), &read_set);
        timeval tv{0, 250000};
        int ready = ::select(0, &read_set, nullptr, nullptr, &tv);
        if (ready == SOCKET_ERROR) {
            if (stop_.load(std::memory_order_relaxed)) break;
            util::log().warn("status API select failed: %s", socket_error_text().c_str());
            break;
        }
        if (ready <= 0) continue;

        sockaddr_storage addr{};
        int addr_len = sizeof(addr);
        SOCKET client = ::accept(SOCKET(listener_),
                                 reinterpret_cast<sockaddr*>(&addr), &addr_len);
        if (client == INVALID_SOCKET) {
            if (stop_.load(std::memory_order_relaxed)) break;
            continue;
        }
        handle_client(uintptr_t(client));
        ::closesocket(client);
    }
}

void StatusServer::handle_client(uintptr_t socket_value) {
    SOCKET socket = SOCKET(socket_value);
    char request[8192];
    int got = ::recv(socket, request, int(sizeof(request) - 1), 0);
    if (got <= 0) return;
    request[got] = '\0';

    std::string text(request, size_t(got));
    std::string request_line = text.substr(0, text.find('\r'));
    if (request_line.empty()) {
        request_line = text.substr(0, text.find('\n'));
    }
    std::istringstream stream(request_line);
    std::string method;
    std::string path;
    std::string version;
    stream >> method >> path >> version;
    if (method.empty() || path.empty()) return;

    std::string body;
    std::string content_type = "text/plain";
    int code = 200;
    if (method == "GET" || method == "HEAD") {
        if (path == "/healthz") {
            body = "ok";
        } else if (path == "/status" || path == "/status/") {
            content_type = "application/json";
            body = render_status_json();
        } else {
            body = "Not Found";
            code = 404;
        }
    } else {
        body = "Method Not Allowed";
        code = 405;
    }

    std::string response = "HTTP/1.1 " + std::to_string(code) + " " +
                           http_status_text(code) + "\r\n" +
                           "Content-Type: " + content_type + "\r\n" +
                           "Content-Length: " + std::to_string(body.size()) +
                           "\r\nConnection: close\r\n\r\n";
    if (method != "HEAD") {
        response += body;
    }
    ::send(socket, response.data(), int(response.size()), 0);
}

std::string StatusServer::render_status_json() const {
    StatusSnapshot snapshot = snapshot_();
    Json object = Json::make_object();
    object.set("version", Json::make_string(snapshot.version.empty()
                                                ? "btcminer-cpp"
                                                : snapshot.version));
    object.set("uptime", Json::make_number(snapshot.uptime));

    Json pool = Json::make_object();
    pool.set("url", Json::make_string(snapshot.pool_url));
    pool.set("user", Json::make_string(snapshot.pool_user));
    pool.set("index", Json::make_int(static_cast<long long>(snapshot.pool_index)));
    pool.set("count", Json::make_int(static_cast<long long>(snapshot.pool_count)));
    object.set("pool", pool);

    object.set("kernel", Json::make_string(snapshot.kernel));
    object.set("threads", Json::make_int(snapshot.threads));
    object.set("hashrate", Json::make_number(snapshot.hashrate));
    object.set("hashes", Json::make_int(static_cast<long long>(snapshot.hashes)));
    object.set("shares_found", Json::make_int(static_cast<long long>(snapshot.shares_found)));
    object.set("accepted", Json::make_int(static_cast<long long>(snapshot.accepted)));
    object.set("rejected", Json::make_int(static_cast<long long>(snapshot.rejected)));
    object.set("stale", Json::make_int(static_cast<long long>(snapshot.stale)));
    object.set("best_share", Json::make_number(snapshot.best_share));
    object.set("pool_difficulty", Json::make_number(snapshot.pool_difficulty));
    object.set("job_id", Json::make_string(snapshot.job_id));

    char mask_buffer[16];
    std::snprintf(mask_buffer, sizeof(mask_buffer), "%08x",
                  (unsigned)snapshot.version_mask);
    object.set("version_mask", Json::make_string(mask_buffer));
    object.set("switch_count", Json::make_int(static_cast<long long>(snapshot.switch_count)));
    return object.dump();
}

std::string StatusServer::render_healthz() const {
    return "ok";
}
