#include "tls.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <winsock2.h>
#include <windows.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>

#ifndef UNISP_NAME_A
#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"
#endif

namespace tls {
namespace {

std::string trim_message(std::string text) {
    while (!text.empty() &&
           (text.back() == '\n' || text.back() == '\r' || text.back() == '.' ||
            text.back() == ' ')) {
        text.pop_back();
    }
    return text;
}

std::string win32_error_text(DWORD code) {
    char* text = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, (LPSTR)&text, 0, nullptr);
    std::string message = text ? text : "unknown error";
    if (text) LocalFree(text);
    char suffix[24];
    std::snprintf(suffix, sizeof(suffix), " (0x%08lx)",
                  (unsigned long)code);
    return trim_message(std::move(message)) + suffix;
}

std::string security_error_text(SECURITY_STATUS status) {
    return win32_error_text(DWORD(status));
}

std::string socket_error_text() {
    return win32_error_text(DWORD(WSAGetLastError()));
}

void send_all(SOCKET socket, const char* data, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        int chunk = ::send(socket, data + sent,
                           int(std::min<size_t>(size - sent, 1u << 20)), 0);
        if (chunk == SOCKET_ERROR) {
            throw std::runtime_error("TLS send failed: " + socket_error_text());
        }
        sent += size_t(chunk);
    }
}

size_t read_socket(SOCKET socket, char* buffer, size_t size) {
    int got = ::recv(socket, buffer, int(size), 0);
    if (got == 0) return 0;
    if (got == SOCKET_ERROR) {
        throw std::runtime_error("TLS receive failed: " + socket_error_text());
    }
    return size_t(got);
}

std::wstring widen(const std::string& text) {
    if (text.empty()) return std::wstring();
    int length = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), int(text.size()),
                                     nullptr, 0);
    if (length <= 0) {
        return std::wstring(text.begin(), text.end());
    }
    std::wstring wide(size_t(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), int(text.size()), &wide[0],
                        length);
    return wide;
}

// Validates the chain and the hostname with the CryptoAPI SSL policy.
void verify_certificate(CtxtHandle& context, const std::wstring& target,
                        const std::string& host) {
    PCCERT_CONTEXT server_cert = nullptr;
    SECURITY_STATUS status = QueryContextAttributesW(
        &context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &server_cert);
    if (status != SEC_E_OK || !server_cert) {
        throw std::runtime_error(
            "cannot read the pool certificate: " + security_error_text(status));
    }

    CERT_CHAIN_PARA chain_para{};
    chain_para.cbSize = sizeof(chain_para);
    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(nullptr, server_cert, nullptr,
                                 server_cert->hCertStore, &chain_para, 0,
                                 nullptr, &chain)) {
        DWORD code = GetLastError();
        CertFreeCertificateContext(server_cert);
        throw std::runtime_error("cannot build the certificate chain for " +
                                 host + ": " + win32_error_text(code));
    }

    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_para{};
    ssl_para.cbSize = sizeof(ssl_para);
    ssl_para.dwAuthType = AUTHTYPE_SERVER;
    ssl_para.pwszServerName = const_cast<wchar_t*>(target.c_str());

    CERT_CHAIN_POLICY_PARA policy_para{};
    policy_para.cbSize = sizeof(policy_para);
    policy_para.pvExtraPolicyPara = &ssl_para;

    CERT_CHAIN_POLICY_STATUS policy_status{};
    policy_status.cbSize = sizeof(policy_status);

    BOOL verified = CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_SSL, chain, &policy_para, &policy_status);
    DWORD code = verified ? policy_status.dwError : GetLastError();

    CertFreeCertificateChain(chain);
    CertFreeCertificateContext(server_cert);

    if (!verified || code != 0) {
        throw std::runtime_error("TLS certificate validation failed for " +
                                 host + ": " + win32_error_text(code));
    }
}

}  // namespace

struct Session::Impl {
    SOCKET socket = INVALID_SOCKET;
    std::string host;
    bool verify = true;

    CredHandle credential{};
    CtxtHandle context{};
    bool have_credential = false;
    bool have_context = false;

    SecPkgContext_StreamSizes sizes{};
    std::string raw;    // encrypted bytes read from the socket
    std::string plain;  // decrypted bytes not yet handed to the caller
};

Session::Session(uintptr_t socket, std::string host, bool verify)
    : impl_(new Impl()), target_(widen(host)) {
    impl_->socket = SOCKET(socket);
    impl_->host = std::move(host);
    impl_->verify = verify;
}

Session::~Session() {
    if (!impl_) return;
    if (impl_->have_context) DeleteSecurityContext(&impl_->context);
    if (impl_->have_credential) FreeCredentialsHandle(&impl_->credential);
}

void Session::handshake() {
    Impl& s = *impl_;
    auto t0 = std::chrono::steady_clock::now();
    auto mark = [&](const char* what) {
        std::fprintf(stderr, "TLS %-14s %.3f s\n", what,
                     std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    };

    DWORD timeout_ms = 30000;
    setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms,
               sizeof(timeout_ms));
    setsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms,
               sizeof(timeout_ms));

    SCHANNEL_CRED credential{};
    credential.dwVersion = SCHANNEL_CRED_VERSION;
    credential.dwFlags = s.verify ? SCH_CRED_AUTO_CRED_VALIDATION
                                  : SCH_CRED_MANUAL_CRED_VALIDATION;
    credential.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;

    TimeStamp expiry{};
    SECURITY_STATUS status = AcquireCredentialsHandleA(
        nullptr, const_cast<char*>(UNISP_NAME_A), SECPKG_CRED_OUTBOUND, nullptr,
        &credential, nullptr, nullptr, &s.credential, &expiry);
    if (status != SEC_E_OK) {
        throw std::runtime_error("cannot create TLS credentials: " +
                                 security_error_text(status));
    }
    s.have_credential = true;
    mark("credentials");

    bool first = true;
    bool need_data = false;
    ULONG attributes = 0;
    char incoming[16384];
    while (true) {
        if (!first && (need_data || s.raw.empty())) {
            size_t got = read_socket(s.socket, incoming, sizeof(incoming));
            if (got == 0) {
                throw std::runtime_error(
                    "pool closed the connection during the TLS handshake");
            }
            s.raw.append(incoming, got);
            need_data = false;
        }

        SecBuffer out{};
        out.BufferType = SECBUFFER_TOKEN;
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out};

        SecBuffer in[2]{};
        DWORD in_count = 0;
        SecBufferDesc in_desc{SECBUFFER_VERSION, 0, nullptr};
        if (!first) {
            in[0].BufferType = SECBUFFER_TOKEN;
            in[0].pvBuffer = s.raw.data();
            in[0].cbBuffer = ULONG(s.raw.size());
            in[1].BufferType = SECBUFFER_EMPTY;
            in_count = 2;
            in_desc.cBuffers = 2;
            in_desc.pBuffers = in;
        }

        DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                      ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                      ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
        status = InitializeSecurityContextA(
            &s.credential, first ? nullptr : &s.context,
            first ? const_cast<char*>(impl_->host.c_str()) : nullptr, flags, 0,
            SECURITY_NATIVE_DREP, first ? nullptr : &in_desc, 0,
            first ? &s.context : nullptr, &out_desc, &attributes,
            &expiry);
        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED ||
            status == SEC_I_INCOMPLETE_CREDENTIALS) {
            s.have_context = true;
        }
        first = false;
        mark(status == SEC_E_OK ? "call ok" : "call continue");

        if (out.pvBuffer) {
            if (out.cbBuffer) {
                send_all(s.socket, (const char*)out.pvBuffer, out.cbBuffer);
            }
            FreeContextBuffer(out.pvBuffer);
        }

        // Bytes past the handshake token belong to the next record (for
        // example a NewSessionTicket).  Keep only those.
        std::string extra;
        for (DWORD i = 0; i < in_count; ++i) {
            if (in[i].BufferType == SECBUFFER_EXTRA) {
                extra.assign((const char*)in[i].pvBuffer, in[i].cbBuffer);
                break;
            }
        }

        if (status == SEC_E_OK) {
            s.raw.swap(extra);
            break;
        }
        if (status == SEC_I_CONTINUE_NEEDED) {
            s.raw.swap(extra);
            continue;
        }
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            need_data = true;
            continue;
        }
        if (status == SEC_I_INCOMPLETE_CREDENTIALS) {
            throw std::runtime_error(
                "pool requested a client certificate, which is not supported");
        }
        throw std::runtime_error("TLS handshake failed: " +
                                 security_error_text(status));
    }

    mark("handshake");
    if (s.verify) verify_certificate(s.context, target_, impl_->host);

    status = QueryContextAttributesA(&s.context, SECPKG_ATTR_STREAM_SIZES,
                                     &s.sizes);
    if (status != SEC_E_OK) {
        throw std::runtime_error("cannot read TLS stream sizes: " +
                                 security_error_text(status));
    }

    timeout_ms = 0;
    setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms,
               sizeof(timeout_ms));
    setsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms,
               sizeof(timeout_ms));
}

void Session::send(const char* data, size_t size) {
    Impl& s = *impl_;
    size_t offset = 0;
    std::vector<char> record;
    while (offset < size) {
        size_t chunk = std::min<size_t>(size - offset, s.sizes.cbMaximumMessage);
        record.resize(size_t(s.sizes.cbHeader) + chunk +
                      s.sizes.cbTrailer);
        std::memcpy(record.data() + s.sizes.cbHeader, data + offset, chunk);

        SecBuffer buffers[4]{};
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = record.data();
        buffers[0].cbBuffer = s.sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = record.data() + s.sizes.cbHeader;
        buffers[1].cbBuffer = ULONG(chunk);
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = record.data() + s.sizes.cbHeader + chunk;
        buffers[2].cbBuffer = s.sizes.cbTrailer;
        buffers[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc desc{SECBUFFER_VERSION, 4, buffers};

        SECURITY_STATUS status = EncryptMessage(&s.context, 0, &desc, 0);
        if (status != SEC_E_OK) {
            throw std::runtime_error("cannot encrypt TLS data: " +
                                     security_error_text(status));
        }
        for (int i = 0; i < 3; ++i) {
            if (buffers[i].cbBuffer) {
                send_all(s.socket, (const char*)buffers[i].pvBuffer,
                         buffers[i].cbBuffer);
            }
        }
        offset += chunk;
    }
}

size_t Session::receive(char* data, size_t size) {
    Impl& s = *impl_;

    if (!s.plain.empty()) {
        size_t take = std::min(size, s.plain.size());
        std::memcpy(data, s.plain.data(), take);
        s.plain.erase(0, take);
        return take;
    }

    char incoming[16384];
    while (true) {
        if (s.raw.empty()) {
            size_t got = read_socket(s.socket, incoming, sizeof(incoming));
            if (got == 0) return 0;
            s.raw.append(incoming, got);
            continue;
        }

        SecBuffer buffers[4]{};
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[0].pvBuffer = s.raw.data();
        buffers[0].cbBuffer = ULONG(s.raw.size());
        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc desc{SECBUFFER_VERSION, 4, buffers};

        SECURITY_STATUS status = DecryptMessage(&s.context, &desc, 0, nullptr);
        if (status == SEC_E_OK) {
            std::string extra;
            const char* plain = nullptr;
            size_t plain_size = 0;
            for (int i = 0; i < 4; ++i) {
                if (buffers[i].BufferType == SECBUFFER_DATA &&
                    buffers[i].cbBuffer) {
                    plain = (const char*)buffers[i].pvBuffer;
                    plain_size = buffers[i].cbBuffer;
                } else if (buffers[i].BufferType == SECBUFFER_EXTRA) {
                    extra.assign((const char*)buffers[i].pvBuffer,
                                 buffers[i].cbBuffer);
                }
            }
            s.raw.swap(extra);
            if (plain_size == 0) continue;
            size_t take = std::min(size, plain_size);
            std::memcpy(data, plain, take);
            if (take < plain_size) {
                s.plain.assign(plain + take, plain_size - take);
            }
            return take;
        }
        if (status == SEC_I_CONTEXT_EXPIRED) return 0;
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            size_t got = read_socket(s.socket, incoming, sizeof(incoming));
            if (got == 0) {
                throw std::runtime_error(
                    "pool closed the connection inside a TLS record");
            }
            s.raw.append(incoming, got);
            continue;
        }
        throw std::runtime_error("cannot decrypt TLS data: " +
                                 security_error_text(status));
    }
}

bool Session::has_pending() const {
    return !impl_->plain.empty() || !impl_->raw.empty();
}

}  // namespace tls
