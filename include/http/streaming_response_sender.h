#pragma once

#include "common.h"
// <functional>, <memory>, <string>, <cstdint> provided by common.h

class Dispatcher;
class HttpResponse;

namespace HTTP_STREAMING_NAMESPACE {

    // Streaming final-response sender for async handlers.
    //
    // Contract:
    //   - `SendHeaders()` claims the final response and commits the
    //     downstream stream. After a successful call, the handler MUST
    //     finish with exactly one of `End()` or `Abort()`.
    //   - `SendData()` is always-accept: callers never hold rejected bytes.
    //     The return value reports downstream occupancy AFTER the chunk is
    //     consumed so the caller can apply backpressure upstream.
    //   - `ACCEPTED_ABOVE_HIGH_WATER` means the chunk was accepted AND the
    //     downstream buffer crossed the configured high-water mark. The caller
    //     should pause upstream reads until the drain listener fires.
    //   - `CLOSED` means the sender is no longer usable (client disconnect,
    //     terminal End/Abort already fired, or contract violation such as
    //     SendData/End before SendHeaders).
    //   - `Abort()` is idempotent. `Abort()` before `SendHeaders()` is legal
    //     and must not emit a successful final response.
    //   - Streaming senders are dispatcher-thread primitives. Off-dispatcher
    //     calls are rejected with `CLOSED` / `-1` and logged at error level.
    class StreamingResponseSender {
    public:
        enum class SendResult {
            ACCEPTED_BELOW_WATER = 0,
            ACCEPTED_ABOVE_HIGH_WATER = 1,
            CLOSED = 2,
        };

        enum class AbortReason {
            UPSTREAM_TRUNCATED,
            UPSTREAM_TIMEOUT,
            UPSTREAM_ERROR,
            CLIENT_DISCONNECT,
            TIMER_EXPIRED,
            SERVER_SHUTDOWN,
        };

        using DrainListener = std::function<void()>;

        class Impl {
        public:
            virtual ~Impl() = default;
            [[nodiscard]] virtual int SendHeaders(
                const HttpResponse& headers_only_response) = 0;
            [[nodiscard]] virtual SendResult SendData(
                const char* data, size_t len) = 0;
            [[nodiscard]] virtual SendResult End(
                const std::vector<std::pair<std::string, std::string>>& trailers) = 0;
            virtual void Abort(AbortReason reason) = 0;
            virtual void SetDrainListener(DrainListener listener) = 0;
            virtual void ConfigureWatermarks(size_t high_water_bytes) = 0;
            virtual Dispatcher* GetDispatcher() = 0;
            virtual void OnDownstreamWriteProgress(size_t /*remaining_bytes*/) {}
            virtual void OnDownstreamWriteComplete() {}
        };

        StreamingResponseSender() = default;
        explicit StreamingResponseSender(std::shared_ptr<Impl> impl)
            : impl_(std::move(impl)) {}

        [[nodiscard]] int SendHeaders(
            const HttpResponse& headers_only_response) const {
            return impl_ ? impl_->SendHeaders(headers_only_response) : -1;
        }
        [[nodiscard]] SendResult SendData(const char* data, size_t len) const {
            return impl_ ? impl_->SendData(data, len) : SendResult::CLOSED;
        }
        [[nodiscard]] SendResult End(
            const std::vector<std::pair<std::string, std::string>>& trailers = {}) const {
            return impl_ ? impl_->End(trailers) : SendResult::CLOSED;
        }
        void Abort(AbortReason reason) const {
            if (impl_) impl_->Abort(reason);
        }
        void SetDrainListener(DrainListener listener) const {
            if (impl_) impl_->SetDrainListener(std::move(listener));
        }
        void ConfigureWatermarks(size_t high_water_bytes) const {
            if (impl_) impl_->ConfigureWatermarks(high_water_bytes);
        }
        Dispatcher* GetDispatcher() const {
            return impl_ ? impl_->GetDispatcher() : nullptr;
        }
        explicit operator bool() const { return static_cast<bool>(impl_); }

    private:
        std::shared_ptr<Impl> impl_;
    };

} // namespace HTTP_STREAMING_NAMESPACE
