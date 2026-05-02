#include "observability/metrics_handler.h"

#include "http/http_request.h"
#include "http/http_response.h"
#include "observability/meter_provider.h"
#include "observability/observability_manager.h"
#include "observability/prometheus_exporter.h"

namespace OBSERVABILITY_NAMESPACE {

namespace {

const std::string& AcceptHeader(const HttpRequest& req) {
    static const std::string kEmpty;
    auto it = req.headers.find("Accept");
    if (it != req.headers.end()) return it->second;
    auto it2 = req.headers.find("accept");
    if (it2 != req.headers.end()) return it2->second;
    return kEmpty;
}

}  // namespace

HttpRouter::Handler MakeMetricsHandler(
        std::weak_ptr<ObservabilityManager> manager) {
    return [manager](HttpRequest& req, HttpResponse& resp) {
        auto m = manager.lock();
        if (!m) {
            resp.Status(503).Text("Observability manager unavailable");
            return;
        }

        // Live runtime gate: metrics.enabled may have flipped via SIGHUP.
        // Per design §10.6 we keep the route registered across toggles
        // and respond 404 when disabled so reverse-proxy probes treat
        // it as not-present rather than a server-side error.
        if (!m->MetricsEnabled()) {
            resp.Status(404).Text("Not Found");
            return;
        }

        auto* mp = m->meter_provider();
        if (!mp) {
            resp.Status(503).Text("MeterProvider not initialized");
            return;
        }

        auto fmt = PrometheusExporter::ChooseFormat(AcceptHeader(req));

        MetricsSnapshot snap = mp->Snapshot();
        // include_target_info is live-reloadable — when false we still
        // call Render but strip the Resource so target_info is omitted.
        if (!m->IncludeTargetInfo()) {
            snap.resource.reset();
        }

        std::string body = PrometheusExporter::Render(snap, fmt);

        resp.Status(200);
        resp.Header("Content-Type", PrometheusExporter::ContentType(fmt));
        resp.Body(std::move(body));
    };
}

}  // namespace OBSERVABILITY_NAMESPACE
