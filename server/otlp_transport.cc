#include "observability/otlp_transport.h"

#include "auth/upstream_http_client.h"

#include <chrono>
#include <future>
#include <utility>

namespace OBSERVABILITY_NAMESPACE {

OtlpHttpExporter::TransportFn MakeOtlpTransport(
    std::weak_ptr<AUTH_NAMESPACE::UpstreamHttpClient> client_weak) {

    return [client_weak]
        (OtlpHttpExporter::ExportPayload payload,
         std::chrono::steady_clock::time_point /*deadline*/) -> ExportResult {

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
        req.timeout_sec = static_cast<int>(
            std::chrono::duration_cast<std::chrono::seconds>(
                payload.timeout).count());
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
        return fut.get();
    };
}

}  // namespace OBSERVABILITY_NAMESPACE
