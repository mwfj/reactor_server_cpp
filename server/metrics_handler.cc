#include "observability/metrics_handler.h"

#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_status.h"
#include "observability/meter_provider.h"
#include "observability/observability_manager.h"
#include "observability/prometheus_exporter.h"

namespace OBSERVABILITY_NAMESPACE {

HttpRouter::Handler MakeMetricsHandler(
        std::weak_ptr<ObservabilityManager> manager) {
    return [manager](HttpRequest& req, HttpResponse& resp) {
        auto m = manager.lock();
        if (!m) {
            resp.Status(HttpStatus::SERVICE_UNAVAILABLE)
                .Text("Observability manager unavailable");
            return;
        }

        // Keep the route registered across SIGHUP toggles; reply 404 when
        // metrics are off so probes treat it as not-present.
        if (!m->MetricsEnabled()) {
            resp.Status(HttpStatus::NOT_FOUND).Text("Not Found");
            return;
        }

        auto* mp = m->meter_provider();
        if (!mp) {
            resp.Status(HttpStatus::SERVICE_UNAVAILABLE)
                .Text("MeterProvider not initialized");
            return;
        }

        auto fmt = PrometheusExporter::ChooseFormat(req.GetHeader("accept"));

        MetricsSnapshot snap = mp->Snapshot();
        if (!m->IncludeTargetInfo()) {
            snap.resource.reset();
        }

        std::string body = PrometheusExporter::Render(snap, fmt);

        resp.Status(HttpStatus::OK);
        resp.Header("Content-Type", PrometheusExporter::ContentType(fmt));
        resp.Body(std::move(body));
    };
}

}  // namespace OBSERVABILITY_NAMESPACE
