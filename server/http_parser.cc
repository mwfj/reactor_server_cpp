#include "http/http_parser.h"
#include "llhttp/llhttp.h"

#include <algorithm>
#include <cstring>

// --- llhttp callbacks (file-scope static, not class methods) ---
// These are declared before HttpParser methods so they can be referenced in the constructor.

static int on_message_begin(llhttp_t* parser) {
    auto* self = static_cast<HttpParser*>(parser->data);
    self->request_.Reset();
    self->current_header_field_.clear();
    self->current_header_value_.clear();
    self->parsing_header_value_ = false;
    self->in_header_field_ = false;
    self->header_bytes_ = 0;
    // Reset all error state defensively (for pipelining without external Reset())
    self->has_error_ = false;
    self->error_message_.clear();
    self->error_type_ = HttpParser::ParseError::NONE;
    return 0;
}

static int on_url(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<HttpParser*>(parser->data);

    // Charge URL bytes against header size limit (prevents oversized request targets)
    if (self->max_header_size_ > 0 &&
        (self->header_bytes_ >= self->max_header_size_ ||
         length > self->max_header_size_ - self->header_bytes_)) {
        self->has_error_ = true;
        self->error_message_ = "Header size exceeds maximum";
        self->error_type_ = HttpParser::ParseError::HEADER_TOO_LARGE;
        return HPE_USER;
    }
    self->header_bytes_ += length;

    self->request_.url.append(at, length);
    return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<HttpParser*>(parser->data);

    // Enforce header size limit (guard against unsigned overflow before adding).
    // Charge +4 for delimiters (": " + "\r\n") when starting a NEW header.
    // A new header starts when we're NOT already in a header field (in_header_field_ is false).
    // llhttp may call on_header_field multiple times for the same header when fragmented
    // across TCP segments — don't charge overhead for continuations.
    size_t overhead = self->in_header_field_ ? 0 : 4;
    self->in_header_field_ = true;  // Mark that we're accumulating this header field
    size_t charge = length + overhead;
    if (self->max_header_size_ > 0 &&
        (self->header_bytes_ >= self->max_header_size_ ||
         charge > self->max_header_size_ - self->header_bytes_)) {
        self->has_error_ = true;
        self->error_message_ = "Header size exceeds maximum";
        self->error_type_ = HttpParser::ParseError::HEADER_TOO_LARGE;
        return HPE_USER;
    }
    self->header_bytes_ += charge;

    // If we were reading a value, flush the previous header.
    if (self->parsing_header_value_) {
        // If headers_complete is true, we're in the trailer section —
        // discard all trailer fields (RFC 7230 §4.1.2 forbids security-
        // critical trailers like Authorization, and merging trailers into
        // request_.headers would let them masquerade as original headers).
        if (self->request_.headers_complete) {
            self->current_header_field_.clear();
            self->current_header_value_.clear();
        } else {
            std::string key = self->current_header_field_;
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
            auto it = self->request_.headers.find(key);
            if (it != self->request_.headers.end()) {
                // Reject duplicates of non-list headers — comma-folding these
                // creates synthetic values never on the wire (RFC 7230 §3.2.2
                // only permits folding for list-valued fields).
                if (key == "host" || key == "authorization" ||
                    key == "content-type" || key == "content-length" ||
                    key == "content-range" || key == "content-disposition") {
                    self->has_error_ = true;
                    self->error_message_ = "Duplicate " + key + " header";
                    self->error_type_ = HttpParser::ParseError::PARSE_ERROR;
                    return HPE_USER;
                }
                // Cookie uses "; " separator per RFC 6265 §5.4, not ", ".
                // Proxies/clients can split cookies into multiple headers.
                if (key == "cookie") {
                    it->second += "; " + self->current_header_value_;
                } else {
                    // List-valued headers: comma-fold per RFC 7230 §3.2.2
                    it->second += ", " + self->current_header_value_;
                }
            } else {
                self->request_.headers[key] = self->current_header_value_;
            }
        }
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }

    self->current_header_field_.append(at, length);
    self->parsing_header_value_ = false;
    return 0;
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<HttpParser*>(parser->data);

    // Enforce header size limit (guard against unsigned overflow before adding)
    if (self->max_header_size_ > 0 &&
        (self->header_bytes_ >= self->max_header_size_ ||
         length > self->max_header_size_ - self->header_bytes_)) {
        self->has_error_ = true;
        self->error_message_ = "Header size exceeds maximum";
        self->error_type_ = HttpParser::ParseError::HEADER_TOO_LARGE;
        return HPE_USER;
    }
    self->header_bytes_ += length;

    self->current_header_value_.append(at, length);
    self->parsing_header_value_ = true;
    self->in_header_field_ = false;  // No longer in field — next on_header_field is a new header
    return 0;
}

static int on_headers_complete(llhttp_t* parser) {
    auto* self = static_cast<HttpParser*>(parser->data);

    // Flush last header
    if (!self->current_header_field_.empty()) {
        std::string key = self->current_header_field_;
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
        auto it = self->request_.headers.find(key);
        if (it != self->request_.headers.end()) {
            // Reject duplicates of non-list headers
            if (key == "host" || key == "authorization" ||
                key == "content-type" || key == "content-length" ||
                key == "content-range" || key == "content-disposition") {
                self->has_error_ = true;
                self->error_message_ = "Duplicate " + key + " header";
                self->error_type_ = HttpParser::ParseError::PARSE_ERROR;
                return HPE_USER;
            }
            // Cookie uses "; " separator per RFC 6265 §5.4, not ", ".
            if (key == "cookie") {
                it->second += "; " + self->current_header_value_;
            } else {
                it->second += ", " + self->current_header_value_;
            }
        } else {
            self->request_.headers[key] = self->current_header_value_;
        }
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }

    // Extract method
    self->request_.method = llhttp_method_name(static_cast<llhttp_method_t>(parser->method));

    // Extract version
    self->request_.http_major = parser->http_major;
    self->request_.http_minor = parser->http_minor;

    // Parse URL into path and query.
    // Handle absolute-form request-targets (RFC 7230 §5.3.2):
    // "GET http://example.com/foo?x=1 HTTP/1.1" → path="/foo", query="x=1"
    // "GET http://example.com?x=1 HTTP/1.1"     → path="/",    query="x=1"
    // "GET http://example.com HTTP/1.1"          → path="/"
    std::string target = self->request_.url;
    // Case-insensitive scheme check (RFC 3986 §3.1: scheme is case-insensitive)
    std::string scheme_check = target.substr(0, 8);
    std::transform(scheme_check.begin(), scheme_check.end(), scheme_check.begin(), [](unsigned char c){ return std::tolower(c); });
    if (scheme_check.compare(0, 7, "http://") == 0 ||
        scheme_check.compare(0, 8, "https://") == 0) {
        auto scheme_end = target.find("://");
        auto authority_start = scheme_end + 3;
        auto path_pos = target.find('/', authority_start);
        if (path_pos != std::string::npos) {
            target = target.substr(path_pos);
        } else {
            // No path slash — check for query directly after authority
            // (e.g., "http://example.com?x=1" → "/?x=1")
            auto query_pos = target.find('?', authority_start);
            target = (query_pos != std::string::npos)
                     ? "/" + target.substr(query_pos)
                     : "/";
        }
    }
    auto qpos = target.find('?');
    if (qpos != std::string::npos) {
        self->request_.path = target.substr(0, qpos);
        self->request_.query = target.substr(qpos + 1);
    } else {
        self->request_.path = target;
    }

    // Keep-alive
    self->request_.keep_alive = llhttp_should_keep_alive(parser);

    // Upgrade
    self->request_.upgrade = (parser->upgrade != 0);

    // Content-Length
    self->request_.content_length = parser->content_length;

    self->request_.headers_complete = true;
    // Reset parsing state so trailer fields (which reuse on_header_field/value
    // callbacks) don't incorrectly flush the cleared header fields as an empty
    // key-value pair into the headers map.
    self->parsing_header_value_ = false;
    self->in_header_field_ = false;
    return 0;
}

static int on_body(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<HttpParser*>(parser->data);

    // Enforce body size limit DURING parsing, not after.
    // Guard against unsigned underflow: check body.size() >= max first.
    if (self->max_body_size_ > 0 &&
        (self->request_.body.size() >= self->max_body_size_ ||
         length > self->max_body_size_ - self->request_.body.size())) {
        self->has_error_ = true;
        self->error_message_ = "Body size exceeds maximum";
        self->error_type_ = HttpParser::ParseError::BODY_TOO_LARGE;
        return HPE_USER;
    }

    self->request_.body.append(at, length);
    return 0;
}

static int on_message_complete(llhttp_t* parser) {
    auto* self = static_cast<HttpParser*>(parser->data);

    // Discard any remaining trailer header field — trailers are not merged
    // into request_.headers (see on_header_field's trailer guard above).
    // RFC 7230 §4.1.2 forbids security-critical fields in trailers, and
    // merging them would let them masquerade as original request headers.
    if (self->parsing_header_value_ && !self->current_header_field_.empty()) {
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }

    self->request_.complete = true;

    // Return HPE_PAUSED so llhttp_execute() stops immediately and returns
    // HPE_PAUSED. This prevents the parser from advancing into the next
    // pipelined request and calling on_message_begin (which would reset
    // request_ before the caller can process it).
    // Note: llhttp_pause() + return 0 does NOT work — the parser continues
    // processing bytes after the callback returns 0 before the pause flag
    // takes effect, corrupting pipelined request data.
    return HPE_PAUSED;
}

// --- HttpParser::Impl (pimpl) ---

struct HttpParser::Impl {
    llhttp_t parser;
    llhttp_settings_t settings;
};

HttpParser::HttpParser() : impl_(std::make_unique<Impl>()) {
    std::memset(&impl_->settings, 0, sizeof(impl_->settings));

    impl_->settings.on_message_begin    = on_message_begin;
    impl_->settings.on_url              = on_url;
    impl_->settings.on_header_field     = on_header_field;
    impl_->settings.on_header_value     = on_header_value;
    impl_->settings.on_headers_complete = on_headers_complete;
    impl_->settings.on_body             = on_body;
    impl_->settings.on_message_complete = on_message_complete;

    llhttp_init(&impl_->parser, HTTP_REQUEST, &impl_->settings);
    impl_->parser.data = this;  // Store pointer to HttpParser for callbacks
}

HttpParser::~HttpParser() = default;

size_t HttpParser::Parse(const char* data, size_t len) {
    llhttp_errno_t err = llhttp_execute(&impl_->parser, data, len);

    if (err != HPE_OK && err != HPE_PAUSED) {
        has_error_ = true;
        if (error_type_ == ParseError::NONE) {
            error_type_ = ParseError::PARSE_ERROR;
        }
        if (error_message_.empty()) {
            error_message_ = std::string(llhttp_errno_name(err)) + ": " +
                             std::string(llhttp_get_error_reason(&impl_->parser));
        }
        return 0;
    }

    // If paused (message complete), calculate bytes consumed
    if (err == HPE_PAUSED) {
        size_t consumed = llhttp_get_error_pos(&impl_->parser) - data;
        return consumed;
    }

    return len;
}

void HttpParser::Reset() {
    request_.Reset();
    has_error_ = false;
    error_message_.clear();
    error_type_ = ParseError::NONE;
    current_header_field_.clear();
    current_header_value_.clear();
    parsing_header_value_ = false;
    in_header_field_ = false;
    header_bytes_ = 0;
    llhttp_init(&impl_->parser, HTTP_REQUEST, &impl_->settings);
    impl_->parser.data = this;
}
