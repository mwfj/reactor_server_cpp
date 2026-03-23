#include "ws/websocket_handshake.h"

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <algorithm>
#include <cstring>
#include <sstream>

static const char* WS_MAGIC = "258EAFA5-E914-47DA-95CA-5AB611DC65B6";

bool WebSocketHandshake::Validate(const HttpRequest& request, std::string& error_message) {
    // 1. Must be GET
    if (request.method != "GET") {
        error_message = "WebSocket upgrade requires GET method";
        return false;
    }

    // 2. Must not have a request body — RFC 6455 opening handshake is a GET.
    // A body would be consumed by the HTTP parser and lost (never becomes WS data).
    // Also reject Transfer-Encoding (e.g. chunked with empty terminator) since it
    // indicates a body-bearing request even when the decoded body is empty.
    if (request.content_length > 0 || !request.body.empty() ||
        request.HasHeader("transfer-encoding")) {
        error_message = "WebSocket upgrade must not have a request body";
        return false;
    }

    // 3. HTTP version >= 1.1
    if (request.http_major < 1 || (request.http_major == 1 && request.http_minor < 1)) {
        error_message = "WebSocket upgrade requires HTTP/1.1 or higher";
        return false;
    }

    // 4. Host header present
    if (!request.HasHeader("host")) {
        error_message = "Missing Host header";
        return false;
    }

    // 5. Upgrade header must contain the "websocket" token (case-insensitive).
    // RFC 7230 §6.7: Upgrade is a comma-separated list of protocols.
    // Valid examples: "websocket", "WebSocket", "websocket, foo"
    std::string upgrade = request.GetHeader("upgrade");
    std::transform(upgrade.begin(), upgrade.end(), upgrade.begin(), ::tolower);
    {
        bool found_websocket = false;
        std::string token;
        std::istringstream uss(upgrade);
        while (std::getline(uss, token, ',')) {
            // Trim OWS (SP and HTAB per RFC 7230 §3.2.3)
            while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.erase(token.begin());
            while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.pop_back();
            if (token == "websocket") {
                found_websocket = true;
                break;
            }
        }
        if (!found_websocket) {
            error_message = "Missing or invalid Upgrade header";
            return false;
        }
    }

    // 6. Connection header must contain "upgrade" as a token (not substring).
    // Connection can be a comma-separated list like "keep-alive, Upgrade"
    std::string connection = request.GetHeader("connection");
    std::transform(connection.begin(), connection.end(), connection.begin(), ::tolower);
    {
        bool found_upgrade = false;
        std::string token;
        std::istringstream ss(connection);
        while (std::getline(ss, token, ',')) {
            // Trim OWS (SP and HTAB per RFC 7230 §3.2.3)
            while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.erase(token.begin());
            while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.pop_back();
            if (token == "upgrade") {
                found_upgrade = true;
                break;
            }
        }
        if (!found_upgrade) {
            error_message = "Missing or invalid Connection header";
            return false;
        }
    }

    // 6. Sec-WebSocket-Key present and valid (base64-encoded 16 bytes → 24 chars with padding)
    {
        std::string key = request.GetHeader("sec-websocket-key");
        // Trim OWS (SP/HTAB) per RFC 7230 §3.2.3
        while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) key.erase(key.begin());
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
        if (key.empty()) {
            error_message = "Missing Sec-WebSocket-Key header";
            return false;
        }
        // RFC 6455 §4.2.1: key must be base64 of 16 bytes = exactly 24 characters
        // with valid base64 alphabet (A-Z, a-z, 0-9, +, /) and == padding
        if (key.size() != 24 || key[22] != '=' || key[23] != '=') {
            error_message = "Invalid Sec-WebSocket-Key: must be base64 of 16 bytes";
            return false;
        }
        // Validate first 22 characters are base64 alphabet
        for (int i = 0; i < 22; i++) {
            char c = key[i];
            bool valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') || c == '+' || c == '/';
            if (!valid) {
                error_message = "Invalid Sec-WebSocket-Key: contains non-base64 characters";
                return false;
            }
        }
    }

    // 7. Sec-WebSocket-Version is "13"
    {
        std::string version = request.GetHeader("sec-websocket-version");
        while (!version.empty() && (version.front() == ' ' || version.front() == '\t')) version.erase(version.begin());
        while (!version.empty() && (version.back() == ' ' || version.back() == '\t')) version.pop_back();
        if (version != "13") {
            error_message = "Unsupported WebSocket version (expected 13)";
            return false;
        }
    }

    return true;
}

HttpResponse WebSocketHandshake::Accept(const HttpRequest& request) {
    std::string key = request.GetHeader("sec-websocket-key");
    // Trim OWS before hashing
    while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) key.erase(key.begin());
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
    std::string accept_key = ComputeAcceptKey(key);

    HttpResponse response;
    response.Status(101, "Switching Protocols")
            .Header("Upgrade", "websocket")
            .Header("Connection", "Upgrade")
            .Header("Sec-WebSocket-Accept", accept_key);

    return response;
}

HttpResponse WebSocketHandshake::Reject(int status_code, const std::string& reason) {
    return HttpResponse().Status(status_code).Text(reason);
}

std::string WebSocketHandshake::ComputeAcceptKey(const std::string& client_key) {
    // Concatenate with magic string
    std::string input = client_key + WS_MAGIC;

    // SHA-1 hash
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);

    // Base64 encode
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, hash, SHA_DIGEST_LENGTH);
    BIO_flush(bio);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(bio);

    return result;
}
