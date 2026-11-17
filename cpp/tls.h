// TLS client transport built on Windows SChannel.
//
// The session owns the certificate/security context for one already connected
// TCP socket.  It hides every SChannel detail from the Stratum client, which
// only sees byte-oriented send/receive calls.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace tls {

class Session {
public:
    // `socket` is a connected SOCKET (uintptr_t to keep Windows types out of
    // this header).  `host` is the connect target: it is sent as SNI and used
    // for the certificate hostname check.  When `verify` is false the chain
    // and hostname are not checked (testing only).
    Session(uintptr_t socket, std::string host, bool verify);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Runs the TLS handshake and, when verifying, the certificate checks.
    // Throws std::runtime_error with a readable message on failure.
    void handshake();

    // Encrypts and sends `size` bytes.
    void send(const char* data, size_t size);

    // Reads decrypted bytes into `data`.  Returns 0 on a clean connection
    // close.  Throws std::runtime_error on failure.
    size_t receive(char* data, size_t size);

    // True when decrypted or already received bytes are queued, in which case
    // the caller should call receive() before waiting on the socket.
    bool has_pending() const;

    const std::wstring& target() const { return target_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::wstring target_;
};

}  // namespace tls
