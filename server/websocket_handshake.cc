#include "ws/websocket_handshake.h"

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <algorithm>
#include <cstring>

static const char* WS_MAGIC = "258EAFA5-E914-47DA-95CA-5AB611DC65B6";

bool WebSocketHandshake::Validate(const HttpRequest& request, std::string& error_message) {
    // 1. Must be GET
    if (request.method != "GET") {
        error_message = "WebSocket upgrade requires GET method";
        return false;
    }

    // 2. HTTP version >= 1.1
    if (request.http_major < 1 || (request.http_major == 1 && request.http_minor < 1)) {
        error_message = "WebSocket upgrade requires HTTP/1.1 or higher";
        return false;
    }

    // 3. Host header present
    if (!request.HasHeader("host")) {
        error_message = "Missing Host header";
        return false;
    }

    // 4. Upgrade header contains "websocket"
    std::string upgrade = request.GetHeader("upgrade");
    std::transform(upgrade.begin(), upgrade.end(), upgrade.begin(), ::tolower);
    if (upgrade.find("websocket") == std::string::npos) {
        error_message = "Missing or invalid Upgrade header";
        return false;
    }

    // 5. Connection header contains "Upgrade"
    std::string connection = request.GetHeader("connection");
    std::transform(connection.begin(), connection.end(), connection.begin(), ::tolower);
    if (connection.find("upgrade") == std::string::npos) {
        error_message = "Missing or invalid Connection header";
        return false;
    }

    // 6. Sec-WebSocket-Key present
    if (!request.HasHeader("sec-websocket-key")) {
        error_message = "Missing Sec-WebSocket-Key header";
        return false;
    }

    // 7. Sec-WebSocket-Version is "13"
    if (request.GetHeader("sec-websocket-version") != "13") {
        error_message = "Unsupported WebSocket version (expected 13)";
        return false;
    }

    return true;
}

HttpResponse WebSocketHandshake::Accept(const HttpRequest& request) {
    std::string accept_key = ComputeAcceptKey(request.GetHeader("sec-websocket-key"));

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
