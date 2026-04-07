#include "upstream/upstream_http_codec.h"
#include "llhttp/llhttp.h"

#include <algorithm>
#include <cstring>

// --- llhttp callbacks (file-scope static, not class methods) ---
// These are declared before UpstreamHttpCodec methods so they can be
// referenced in the constructor.

static int on_message_begin(llhttp_t* parser) {
    auto* self = static_cast<UpstreamHttpCodec*>(parser->data);
    self->response_.Reset();
    self->current_header_field_.clear();
    self->current_header_value_.clear();
    self->parsing_header_value_ = false;
    self->in_header_field_ = false;
    // Reset all error state defensively (for connection reuse without external Reset())
    self->has_error_ = false;
    self->error_message_.clear();
    self->error_type_ = UpstreamHttpCodec::ParseError::NONE;
    return 0;
}

static int on_status(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<UpstreamHttpCodec*>(parser->data);
    self->response_.status_reason.append(at, length);
    return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<UpstreamHttpCodec*>(parser->data);

    // If we were reading a value, flush the previous header.
    if (self->parsing_header_value_) {
        std::string key = self->current_header_field_;
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        self->response_.headers.emplace_back(std::move(key),
                                             std::move(self->current_header_value_));
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }

    self->current_header_field_.append(at, length);
    self->parsing_header_value_ = false;
    self->in_header_field_ = true;
    return 0;
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<UpstreamHttpCodec*>(parser->data);
    self->current_header_value_.append(at, length);
    self->parsing_header_value_ = true;
    self->in_header_field_ = false;  // No longer in field — next on_header_field is a new header
    return 0;
}

static int on_headers_complete(llhttp_t* parser) {
    auto* self = static_cast<UpstreamHttpCodec*>(parser->data);

    // Flush last header
    if (!self->current_header_field_.empty()) {
        std::string key = self->current_header_field_;
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        self->response_.headers.emplace_back(std::move(key),
                                             std::move(self->current_header_value_));
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }

    // Extract status code
    self->response_.status_code = llhttp_get_status_code(parser);

    // Extract version
    self->response_.http_major = parser->http_major;
    self->response_.http_minor = parser->http_minor;

    self->response_.headers_complete = true;
    // Reset parsing state so trailer fields (which reuse on_header_field/value
    // callbacks) don't incorrectly flush the cleared header fields as an empty
    // key-value pair into the headers vector.
    self->parsing_header_value_ = false;
    self->in_header_field_ = false;
    return 0;
}

static int on_body(llhttp_t* parser, const char* at, size_t length) {
    auto* self = static_cast<UpstreamHttpCodec*>(parser->data);

    // Enforce hard cap on response body size to prevent memory exhaustion
    // from misconfigured upstreams. Guard against unsigned underflow.
    if (self->response_.body.size() >= UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE ||
        length > UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE - self->response_.body.size()) {
        self->has_error_ = true;
        self->error_message_ = "Response body exceeds maximum size (64MB)";
        self->error_type_ = UpstreamHttpCodec::ParseError::PARSE_ERROR;
        return HPE_USER;
    }

    self->response_.body.append(at, length);
    return 0;
}

static int on_message_complete(llhttp_t* parser) {
    auto* self = static_cast<UpstreamHttpCodec*>(parser->data);

    // Discard any remaining trailer header field — trailers are not merged
    // into response_.headers (see on_header_field's trailer guard above).
    if (self->parsing_header_value_ && !self->current_header_field_.empty()) {
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }

    self->response_.complete = true;

    // Return HPE_PAUSED so llhttp_execute() stops immediately and returns
    // HPE_PAUSED. This prevents the parser from advancing into the next
    // pipelined response and calling on_message_begin (which would reset
    // response_ before the caller can process it).
    return HPE_PAUSED;
}

// --- UpstreamHttpCodec::Impl (pimpl) ---

struct UpstreamHttpCodec::Impl {
    llhttp_t parser;
    llhttp_settings_t settings;
};

UpstreamHttpCodec::UpstreamHttpCodec() : impl_(std::make_unique<Impl>()) {
    std::memset(&impl_->settings, 0, sizeof(impl_->settings));

    impl_->settings.on_message_begin    = on_message_begin;
    impl_->settings.on_status           = on_status;
    impl_->settings.on_header_field     = on_header_field;
    impl_->settings.on_header_value     = on_header_value;
    impl_->settings.on_headers_complete = on_headers_complete;
    impl_->settings.on_body             = on_body;
    impl_->settings.on_message_complete = on_message_complete;

    llhttp_init(&impl_->parser, HTTP_RESPONSE, &impl_->settings);
    impl_->parser.data = this;  // Store pointer to UpstreamHttpCodec for callbacks
}

UpstreamHttpCodec::~UpstreamHttpCodec() = default;

size_t UpstreamHttpCodec::Parse(const char* data, size_t len) {
    size_t total_consumed = 0;
    while (total_consumed < len) {
        llhttp_errno_t err = llhttp_execute(&impl_->parser,
            data + total_consumed, len - total_consumed);

        if (err == HPE_PAUSED) {
            size_t consumed = llhttp_get_error_pos(&impl_->parser) - (data + total_consumed);
            total_consumed += consumed;
            int status = llhttp_get_status_code(&impl_->parser);
            if (status >= 100 && status < 200) {
                // Interim 1xx response: discard, resume, continue parsing
                // remaining bytes. The proxy does NOT forward 1xx to the
                // client — it waits for the final response.
                llhttp_resume(&impl_->parser);
                response_.Reset();
                has_error_ = false;
                current_header_field_.clear();
                current_header_value_.clear();
                parsing_header_value_ = false;
                in_header_field_ = false;
                continue;
            }
            // Final response: return total consumed
            return total_consumed;
        }

        if (err != HPE_OK) {
            has_error_ = true;
            if (error_type_ == ParseError::NONE) {
                error_type_ = ParseError::PARSE_ERROR;
                error_message_ = llhttp_get_error_reason(&impl_->parser);
            }
            return total_consumed;
        }
        // Consumed everything without pausing
        total_consumed = len;
    }
    return total_consumed;
}

void UpstreamHttpCodec::Reset() {
    response_.Reset();
    has_error_ = false;
    error_message_.clear();
    error_type_ = ParseError::NONE;
    current_header_field_.clear();
    current_header_value_.clear();
    parsing_header_value_ = false;
    in_header_field_ = false;
    llhttp_init(&impl_->parser, HTTP_RESPONSE, &impl_->settings);
    impl_->parser.data = this;
}
