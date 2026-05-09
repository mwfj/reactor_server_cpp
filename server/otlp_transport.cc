#include "observability/otlp_transport.h"

#include "auth/upstream_http_client.h"

#include <algorithm>
#include <chrono>
#include <future>
#include <utility>

namespace OBSERVABILITY_NAMESPACE {

int OtlpTimeoutCeilSeconds(std::chrono::milliseconds ms) noexcept {
    // Realistic OTLP timeouts are seconds-scale; clamp the input so the
    // (count + 999) addition below cannot overflow. 24h is far beyond
    // any sensible operator setting and well below int64 millisecond
    // saturation.
    constexpr int64_t kClampMs = static_cast<int64_t>(24) * 3600 * 1000;
    int64_t v = ms.count();
    if (v <= 0) return 1;
    if (v > kClampMs) v = kClampMs;
    // Round up: (count + 999) / 1000 is >=1 for any positive `v`.
    return static_cast<int>((v + 999) / 1000);
}

OtlpHttpExporter::TransportFn MakeOtlpTransport(
    std::weak_ptr<AUTH_NAMESPACE::UpstreamHttpClient> client_weak) {

    return [client_weak]
        (OtlpHttpExporter::ExportPayload payload,
         std::chrono::steady_clock::time_point deadline) -> ExportResult {

        auto client = client_weak.lock();
        if (!client) {
            return ExportResult::kFailedNotRetryable;
        }

        AUTH_NAMESPACE::UpstreamHttpClient::Request req;
        req.method  = "POST";
        req.path    = payload.path;
        req.headers = std::move(payload.headers);
        req.headers["content-type"] = "application/json";
        req.body    = std::move(payload.body);
        req.timeout_sec = OtlpTimeoutCeilSeconds(payload.timeout);
        // No req.issue_ctx: exporter activity is not traced.

        auto promise = std::make_shared<std::promise<ExportResult>>();
        auto fut = promise->get_future();
        client->Issue(
            payload.upstream_pool_name,
            /*dispatcher_index=*/0,
            std::move(req),
            [promise](AUTH_NAMESPACE::UpstreamHttpClient::Response resp) {
                if (!resp.error.empty()) {
                    promise->set_value(ExportResult::kFailedRetryable);
                    return;
                }
                if (resp.status_code >= 200 && resp.status_code < 300) {
                    promise->set_value(ExportResult::kSuccess);
                } else if (resp.status_code == 429
                        || resp.status_code == 503) {
                    promise->set_value(ExportResult::kFailedRetryable);
                } else {
                    promise->set_value(ExportResult::kFailedNotRetryable);
                }
            });
        // Defense-in-depth: even with timeout_sec armed, callback delivery
        // can stall (transport bug, dispatcher races at shutdown) and
        // fut.get() would block the worker forever. Bound the wait at
        // min(payload.timeout + 1s slack, time-until-caller-deadline) —
        // honoring the caller's deadline matters when the reader's
        // export_timeout_ms is shorter than otlp.timeout_ms or when
        // shutdown passes a tighter flush budget.
        //
        // On wait_for timeout we return kFailedRetryable, which tells
        // BatchSpanProcessor to retry with the same batch. If the
        // upstream eventually responds 200 OK seconds later, the
        // already-retried-and-succeeded duplicate batch will produce
        // duplicate spans downstream — this is the OTel-spec-acknowledged
        // at-most-once-vs-at-least-once trade-off. Operators seeing
        // duplicate spans should look for slow upstreams that exceed
        // both UpstreamHttpClient's deadline and this slack.
        const auto request_budget =
            std::max(payload.timeout, std::chrono::milliseconds{1000})
            + std::chrono::seconds{1};
        const auto now = std::chrono::steady_clock::now();
        const auto until_deadline =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
        // If the caller's deadline already expired we still wait the
        // upstream-deadline + slack: the request may have already been
        // sent and a fast reply could land. But we cap at request_budget.
        const auto wait_budget = until_deadline.count() > 0
            ? std::min(request_budget, until_deadline)
            : request_budget;
        if (fut.wait_for(wait_budget) == std::future_status::timeout) {
            return ExportResult::kFailedRetryable;
        }
        return fut.get();
    };
}

}  // namespace OBSERVABILITY_NAMESPACE
