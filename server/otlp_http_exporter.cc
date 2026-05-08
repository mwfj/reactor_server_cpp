#include "observability/otlp_http_exporter.h"

#include "log/logger.h"
#include "nlohmann/json.hpp"
#include "observability/instrumentation_scope.h"
#include "observability/resource.h"

#include "common.h"

namespace OBSERVABILITY_NAMESPACE {

using nlohmann::json;

namespace {

// Convert system_clock time_point to OTLP's nanosecond unix timestamp.
inline uint64_t ToUnixNs(std::chrono::system_clock::time_point t) noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            t.time_since_epoch()).count());
}

// Render an AttrValue as an OTLP `KeyValue` value JSON object.
json AttrValueToJson(const AttrValue& v) {
    return std::visit([](auto&& arg) -> json {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return json::object();  // empty value
        } else if constexpr (std::is_same_v<T, bool>) {
            return json{{"boolValue", arg}};
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return json{{"intValue", std::to_string(arg)}};  // OTLP uses string for int64
        } else if constexpr (std::is_same_v<T, double>) {
            return json{{"doubleValue", arg}};
        } else if constexpr (std::is_same_v<T, std::string>) {
            return json{{"stringValue", arg}};
        } else if constexpr (std::is_same_v<T, std::vector<bool>>) {
            json values = json::array();
            for (auto b : arg) values.push_back({{"boolValue", b}});
            return json{{"arrayValue", {{"values", values}}}};
        } else if constexpr (std::is_same_v<T, std::vector<int64_t>>) {
            json values = json::array();
            for (auto i : arg) values.push_back({{"intValue", std::to_string(i)}});
            return json{{"arrayValue", {{"values", values}}}};
        } else if constexpr (std::is_same_v<T, std::vector<double>>) {
            json values = json::array();
            for (auto d : arg) values.push_back({{"doubleValue", d}});
            return json{{"arrayValue", {{"values", values}}}};
        } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            json values = json::array();
            for (const auto& s : arg) values.push_back({{"stringValue", s}});
            return json{{"arrayValue", {{"values", values}}}};
        }
        return json::object();
    }, v.value);
}

// Sensitive-attribute denylist. Span / event / resource attribute
// keys matching any entry (case-insensitive, after lowercasing) are
// exported with their value replaced by "[REDACTED]" so tokens,
// cookies, and api keys never leave the process. The match is
// EXACT — partial matches like `myauthorization` are not redacted.
// Operators with additional keys to scrub should land them via a
// follow-up that surfaces the list as configuration; this minimal
// fixed set covers the headers the OTel HTTP semconv calls out.
bool IsSensitiveAttributeKey(const std::string& key) {
    static const char* const kDenylist[] = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "http.request.header.authorization",
        "http.request.header.proxy-authorization",
        "http.request.header.cookie",
        "http.request.header.x-api-key",
        "http.response.header.set-cookie",
    };
    if (key.empty()) return false;
    std::string lower;
    lower.reserve(key.size());
    for (char c : key) {
        lower.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    }
    for (const char* d : kDenylist) {
        if (lower == d) return true;
    }
    return false;
}

json AttributesToJson(const std::vector<Attribute>& attrs) {
    json arr = json::array();
    for (const auto& a : attrs) {
        if (IsSensitiveAttributeKey(a.key)) {
            arr.push_back({
                {"key", a.key},
                {"value", json{{"stringValue", "[REDACTED]"}}}
            });
            continue;
        }
        arr.push_back({
            {"key", a.key},
            {"value", AttrValueToJson(a.value)}
        });
    }
    return arr;
}

json ResourceToJson(const Resource* r) {
    json out;
    out["attributes"] = r ? AttributesToJson(r->attributes()) : json::array();
    return out;
}

json ScopeToJson(const InstrumentationScope* s) {
    json out;
    if (s) {
        out["name"]    = s->name();
        out["version"] = s->version();
    } else {
        out["name"] = "";
    }
    return out;
}

const char* SpanKindToOtlp(SpanKind k) {
    switch (k) {
        case SpanKind::INTERNAL: return "SPAN_KIND_INTERNAL";
        case SpanKind::SERVER:   return "SPAN_KIND_SERVER";
        case SpanKind::CLIENT:   return "SPAN_KIND_CLIENT";
        case SpanKind::PRODUCER: return "SPAN_KIND_PRODUCER";
        case SpanKind::CONSUMER: return "SPAN_KIND_CONSUMER";
    }
    return "SPAN_KIND_UNSPECIFIED";
}

int OtlpStatusCode(SpanStatusCode s) noexcept {
    switch (s) {
        case SpanStatusCode::UNSET: return 0;
        case SpanStatusCode::OK:    return 1;
        case SpanStatusCode::ERROR: return 2;
    }
    return 0;
}

const char* MetricKindToOtlpField(InstrumentKind kind) noexcept {
    switch (kind) {
        case InstrumentKind::Counter:       return "sum";
        case InstrumentKind::UpDownCounter: return "sum";
        case InstrumentKind::Histogram:     return "histogram";
    }
    return "sum";
}

json LabelSetToAttributes(const LabelSet& ls) {
    json arr = json::array();
    for (const auto& [k, v] : ls.kv) {
        arr.push_back({
            {"key", k},
            {"value", json{{"stringValue", v}}}
        });
    }
    return arr;
}

}  // namespace

std::string OtlpHttpExporter::SerializeSpansToJson(
    const std::vector<SpanData>& batch) {
    if (batch.empty()) return "{\"resourceSpans\":[]}";

    // Group by (Resource, InstrumentationScope) per OTLP schema. Most
    // gateway emissions share one Resource (built once at provider
    // construction), so this loop collapses fast in the common case.
    struct Key {
        const Resource* res;
        const InstrumentationScope* scope;
        bool operator==(const Key& o) const {
            return res == o.res && scope == o.scope;
        }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const {
            return std::hash<const void*>{}(k.res) ^
                   (std::hash<const void*>{}(k.scope) << 1);
        }
    };
    std::unordered_map<Key, std::vector<const SpanData*>, KeyHash> grouped;
    for (const auto& sd : batch) {
        grouped[Key{sd.resource.get(), sd.scope.get()}].push_back(&sd);
    }

    // resourceSpans[*].scopeSpans[*].spans[*]
    json resource_spans = json::array();
    // We collapse multiple scopes under the same Resource. For the
    // gateway's emission pattern there's typically one Resource +
    // one Scope, but the OTLP schema allows the full nesting.
    std::unordered_map<const Resource*, json> by_resource;
    for (auto& [key, ptrs] : grouped) {
        json scope_spans = json::object();
        scope_spans["scope"] = ScopeToJson(key.scope);
        json spans_arr = json::array();
        for (const auto* sd : ptrs) {
            json sj;
            sj["traceId"]           = sd->context.trace_id().ToHex();
            sj["spanId"]            = sd->context.span_id().ToHex();
            if (sd->has_parent && sd->parent_context.IsValid()) {
                sj["parentSpanId"]   = sd->parent_context.span_id().ToHex();
            }
            sj["name"]              = sd->name;
            sj["kind"]              = SpanKindToOtlp(sd->kind);
            sj["startTimeUnixNano"] = std::to_string(ToUnixNs(sd->start_time_system));
            sj["endTimeUnixNano"]   = std::to_string(ToUnixNs(sd->end_time_system));
            sj["attributes"]        = AttributesToJson(sd->attributes);
            // Status
            json status;
            if (!sd->status_description.empty()) {
                status["message"] = sd->status_description;
            }
            status["code"] = OtlpStatusCode(sd->status_code);
            sj["status"]   = status;
            // Events
            if (!sd->events.empty()) {
                json events = json::array();
                for (const auto& e : sd->events) {
                    json ej;
                    ej["timeUnixNano"] = std::to_string(ToUnixNs(e.timestamp));
                    ej["name"]         = e.name;
                    ej["attributes"]   = AttributesToJson(e.attributes);
                    events.push_back(std::move(ej));
                }
                sj["events"] = std::move(events);
            }
            spans_arr.push_back(std::move(sj));
        }
        scope_spans["spans"] = std::move(spans_arr);

        auto& rj = by_resource[key.res];
        if (rj.is_null()) {
            rj["resource"]   = ResourceToJson(key.res);
            rj["scopeSpans"] = json::array();
        }
        rj["scopeSpans"].push_back(std::move(scope_spans));
    }
    for (auto& [_, rj] : by_resource) {
        (void)_;
        resource_spans.push_back(std::move(rj));
    }
    json doc;
    doc["resourceSpans"] = std::move(resource_spans);
    return doc.dump();
}

std::string OtlpHttpExporter::SerializeMetricsToJson(
    const MetricsSnapshot& snap) {
    json doc;
    json resource_metrics = json::array();
    json one;
    one["resource"] = ResourceToJson(snap.resource.get());
    json scope_metrics = json::array();

    // Group instruments by scope.
    std::unordered_map<const InstrumentationScope*, std::vector<const InstrumentSnapshot*>> by_scope;
    for (const auto& inst : snap.instruments) {
        by_scope[inst.scope.get()].push_back(&inst);
    }

    for (auto& [scope, insts] : by_scope) {
        json sm;
        sm["scope"] = ScopeToJson(scope);
        json metrics_arr = json::array();
        for (const auto* inst : insts) {
            json mj;
            mj["name"]        = inst->name;
            mj["description"] = inst->description;
            mj["unit"]        = inst->unit;

            const char* field = MetricKindToOtlpField(inst->kind);
            json data;
            if (inst->kind == InstrumentKind::Counter ||
                inst->kind == InstrumentKind::UpDownCounter) {
                json points = json::array();
                for (const auto& p : inst->counter_points) {
                    json pj;
                    pj["attributes"]      = LabelSetToAttributes(p.labels);
                    pj["timeUnixNano"]    = std::to_string(ToUnixNs(snap.timestamp));
                    pj["asDouble"]        = p.value;
                    points.push_back(std::move(pj));
                }
                data["dataPoints"] = std::move(points);
                data["aggregationTemporality"] = 2;  // CUMULATIVE
                data["isMonotonic"] =
                    (inst->kind == InstrumentKind::Counter);
            } else if (inst->kind == InstrumentKind::Histogram) {
                json points = json::array();
                for (const auto& p : inst->histogram_points) {
                    json pj;
                    pj["attributes"]   = LabelSetToAttributes(p.labels);
                    pj["timeUnixNano"] = std::to_string(ToUnixNs(snap.timestamp));
                    pj["count"]        = std::to_string(p.count);
                    pj["sum"]          = p.sum;
                    if (p.has_min_max) {
                        pj["min"] = p.min;
                        pj["max"] = p.max;
                    }
                    json bucket_counts = json::array();
                    for (auto bc : p.bucket_counts) {
                        bucket_counts.push_back(std::to_string(bc));
                    }
                    pj["bucketCounts"]      = std::move(bucket_counts);
                    pj["explicitBounds"]    = p.bucket_boundaries;
                    points.push_back(std::move(pj));
                }
                data["dataPoints"] = std::move(points);
                data["aggregationTemporality"] = 2;  // CUMULATIVE
            }
            mj[field] = std::move(data);
            metrics_arr.push_back(std::move(mj));
        }
        sm["metrics"] = std::move(metrics_arr);
        scope_metrics.push_back(std::move(sm));
    }

    one["scopeMetrics"] = std::move(scope_metrics);
    resource_metrics.push_back(std::move(one));
    doc["resourceMetrics"] = std::move(resource_metrics);
    return doc.dump();
}

std::shared_ptr<OtlpHttpExporter> OtlpHttpExporter::Create(
    Options opts, TransportFn transport) {
    return std::shared_ptr<OtlpHttpExporter>(
        new OtlpHttpExporter(std::move(opts), std::move(transport)));
}

OtlpHttpExporter::OtlpHttpExporter(Options opts, TransportFn transport)
    : transport_(std::move(transport)),
      options_(std::make_shared<const Options>(std::move(opts))) {}

std::shared_ptr<const OtlpHttpExporter::Options>
OtlpHttpExporter::Snapshot() const noexcept {
    return std::atomic_load_explicit(&options_, std::memory_order_acquire);
}

ExportResult OtlpHttpExporter::Export(
    std::vector<SpanData> batch,
    std::chrono::steady_clock::time_point deadline) {
    if (shutting_down_.load(std::memory_order_acquire)) {
        exports_failed_.fetch_add(1, std::memory_order_relaxed);
        return ExportResult::kFailedNotRetryable;
    }
    if (batch.empty()) return ExportResult::kSuccess;

    exports_attempted_.fetch_add(1, std::memory_order_relaxed);
    active_exports_.fetch_add(1, std::memory_order_acq_rel);

    auto opts = Snapshot();
    ExportPayload payload;
    payload.upstream_pool_name = opts->traces.upstream_pool_name;
    payload.path               = opts->traces.path;
    payload.headers            = opts->traces.headers;
    payload.headers["content-type"] = "application/json";
    payload.body               = SerializeSpansToJson(batch);
    payload.timeout            = opts->traces.timeout;

    ExportResult result = ExportResult::kFailedNotRetryable;
    try {
        if (transport_) {
            result = transport_(std::move(payload), deadline);
        } else {
            // No transport wired (test / disabled deployment) — treat
            // as success so the processor's queue drains.
            result = ExportResult::kSuccess;
        }
    } catch (const std::exception& e) {
        logging::Get()->error("OtlpHttpExporter span transport threw: {}", e.what());
    } catch (...) {
        logging::Get()->error("OtlpHttpExporter span transport threw unknown exception");
    }

    active_exports_.fetch_sub(1, std::memory_order_acq_rel);
    if (result == ExportResult::kSuccess) {
        exports_succeeded_.fetch_add(1, std::memory_order_relaxed);
    } else {
        exports_failed_.fetch_add(1, std::memory_order_relaxed);
    }
    return result;
}

ExportResult OtlpHttpExporter::Export(
    MetricsSnapshot snapshot,
    std::chrono::steady_clock::time_point deadline) {
    if (shutting_down_.load(std::memory_order_acquire)) {
        exports_failed_.fetch_add(1, std::memory_order_relaxed);
        return ExportResult::kFailedNotRetryable;
    }
    if (snapshot.instruments.empty()) return ExportResult::kSuccess;

    exports_attempted_.fetch_add(1, std::memory_order_relaxed);
    active_exports_.fetch_add(1, std::memory_order_acq_rel);

    auto opts = Snapshot();
    ExportPayload payload;
    payload.upstream_pool_name = opts->metrics.upstream_pool_name;
    payload.path               = opts->metrics.path;
    payload.headers            = opts->metrics.headers;
    payload.headers["content-type"] = "application/json";
    payload.body               = SerializeMetricsToJson(snapshot);
    payload.timeout            = opts->metrics.timeout;

    ExportResult result = ExportResult::kFailedNotRetryable;
    try {
        if (transport_) {
            result = transport_(std::move(payload), deadline);
        } else {
            result = ExportResult::kSuccess;
        }
    } catch (const std::exception& e) {
        logging::Get()->error("OtlpHttpExporter metric transport threw: {}", e.what());
    } catch (...) {
        logging::Get()->error("OtlpHttpExporter metric transport threw unknown exception");
    }

    active_exports_.fetch_sub(1, std::memory_order_acq_rel);
    if (result == ExportResult::kSuccess) {
        exports_succeeded_.fetch_add(1, std::memory_order_relaxed);
    } else {
        exports_failed_.fetch_add(1, std::memory_order_relaxed);
    }
    return result;
}

void OtlpHttpExporter::SignalShutdown() {
    shutting_down_.store(true, std::memory_order_release);
}

void OtlpHttpExporter::CancelAllActiveExports() {
    // Invoked only from the self-dispatcher / single-dispatcher
    // shutdown branch. The transport callback honors the cancel —
    // typical implementations watch for shutting_down_ between retry
    // attempts. We bump the cancelled counter as a diagnostic signal;
    // the actual cancel is transport-specific.
    exports_cancelled_.fetch_add(active_exports_.load(std::memory_order_acquire),
                                  std::memory_order_relaxed);
}

void OtlpHttpExporter::ReloadHeaders(
    const std::map<std::string, std::string>& trace_headers,
    const std::map<std::string, std::string>& metric_headers,
    std::chrono::milliseconds trace_timeout,
    std::chrono::milliseconds metric_timeout) {
    // Controlled merge: clone the LIVE Options, overwrite ONLY the
    // live-reloadable subset (headers + timeout), atomic-store.
    // The mutex serialises Reload-vs-Reload; the atomic_load on
    // options_ pairs with Snapshot()'s atomic_load — without it, a
    // worker mid-Snapshot reading the same shared_ptr object races on
    // the control block / pointer fields.
    std::lock_guard<std::mutex> g(options_mtx_);
    auto live = std::atomic_load_explicit(&options_,
                                            std::memory_order_acquire);
    auto next = std::make_shared<Options>(*live);
    next->traces.headers  = trace_headers;
    next->traces.timeout  = trace_timeout;
    next->metrics.headers = metric_headers;
    next->metrics.timeout = metric_timeout;
    std::atomic_store_explicit(&options_, std::shared_ptr<const Options>(next),
                                 std::memory_order_release);
}

}  // namespace OBSERVABILITY_NAMESPACE
