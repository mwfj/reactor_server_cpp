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

    // If we were reading a value, flush the previous header
    if (self->parsing_header_value_) {
        std::string key = self->current_header_field_;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        self->request_.headers[key] = self->current_header_value_;
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
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        self->request_.headers[key] = self->current_header_value_;
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }

    // Extract method
    self->request_.method = llhttp_method_name(static_cast<llhttp_method_t>(parser->method));

    // Extract version
    self->request_.http_major = parser->http_major;
    self->request_.http_minor = parser->http_minor;

    // Parse URL into path and query
    const std::string& url = self->request_.url;
    auto qpos = url.find('?');
    if (qpos != std::string::npos) {
        self->request_.path = url.substr(0, qpos);
        self->request_.query = url.substr(qpos + 1);
    } else {
        self->request_.path = url;
    }

    // Keep-alive
    self->request_.keep_alive = llhttp_should_keep_alive(parser);

    // Upgrade
    self->request_.upgrade = (parser->upgrade != 0);

    // Content-Length
    self->request_.content_length = parser->content_length;

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
    self->request_.complete = true;

    // Pause the parser so we can process this request
    // before parsing the next one (pipelining support)
    llhttp_pause(parser);
    return 0;
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
