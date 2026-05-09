#pragma once

#include "upstream/upstream_codec.h"
// <string>, <memory>, <cstddef> provided transitively

// Forward declaration — the codec routes per-stream parse/finish calls
// through its parent connection's nghttp2_session. Defined in
// upstream/upstream_h2_connection.h.
class UpstreamH2Connection;
class UpstreamH2Stream;

// Outbound H2 codec for a single upstream stream. Mirrors
// `UpstreamHttpCodec` (the H1 implementation) but routes byte handling
// to the multiplexed `UpstreamH2Connection` — the actual nghttp2_session
// is owned by the connection, not the per-stream codec.
class UpstreamH2Codec : public UpstreamCodec {
public:
    UpstreamH2Codec();
    ~UpstreamH2Codec() override;

    UpstreamH2Codec(const UpstreamH2Codec&) = delete;
    UpstreamH2Codec& operator=(const UpstreamH2Codec&) = delete;

    void Reset() override;
    void SetRequestMethod(const std::string& method) override;
    void SetSink(UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink) override;
    size_t Parse(const char* data, size_t len) override;
    bool Finish() override;
    void PauseParsing() override;
    void ResumeParsing() override;
    bool IsPaused() const override { return paused_; }
    bool HasError() const override { return has_error_; }
    std::string GetError() const override { return error_message_; }
    const UpstreamResponse& GetResponse() const override { return response_; }
    UpstreamResponse& GetResponse() override { return response_; }

private:
    UpstreamResponse response_;
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink_ = nullptr;
    std::string request_method_;
    bool paused_ = false;
    bool has_error_ = false;
    std::string error_message_;
};
