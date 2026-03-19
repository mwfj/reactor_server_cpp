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
    return 0;
}

static int on_url(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<HttpParser*>(parser->data);
    self->request_.url.append(at, length);
    return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<HttpParser*>(parser->data);

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
    self->current_header_value_.append(at, length);
    self->parsing_header_value_ = true;
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

HttpParser::HttpParser() : impl_(new Impl) {
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

HttpParser::~HttpParser() {
    delete impl_;
}

size_t HttpParser::Parse(const char* data, size_t len) {
    llhttp_errno_t err = llhttp_execute(&impl_->parser, data, len);

    if (err != HPE_OK && err != HPE_PAUSED) {
        has_error_ = true;
        error_message_ = std::string(llhttp_errno_name(err)) + ": " +
                         std::string(llhttp_get_error_reason(&impl_->parser));
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
    current_header_field_.clear();
    current_header_value_.clear();
    parsing_header_value_ = false;
    llhttp_init(&impl_->parser, HTTP_REQUEST, &impl_->settings);
    impl_->parser.data = this;
}
