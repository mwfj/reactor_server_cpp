#include "observability/prometheus_exporter.h"

#include "observability/resource.h"

#include <cmath>
#include <cstdio>
#include <variant>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Per design §8.3: replace every char outside [a-zA-Z0-9_] with '_'; if
// the resulting first char is a digit, prepend '_'. Empty input stays
// empty (caller's problem; the registry should reject empty names).
inline bool IsLegalChar(char c) noexcept {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '_';
}

// Escape a label-value per the Prometheus exposition spec:
//   '\' → '\\', '"' → '\"', '\n' → '\\n'
std::string EscapeLabelValue(const std::string& v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// Render a double in a Prometheus-friendly form. NaN → "NaN"; +Inf →
// "+Inf"; -Inf → "-Inf"; integers print without trailing ".0".
std::string FormatValue(double v) {
    if (std::isnan(v)) return "NaN";
    if (std::isinf(v)) return v > 0 ? "+Inf" : "-Inf";
    char buf[64];
    if (v == static_cast<double>(static_cast<int64_t>(v))
        && std::abs(v) < 1e15) {
        std::snprintf(buf, sizeof(buf), "%lld",
                      static_cast<long long>(v));
    } else {
        std::snprintf(buf, sizeof(buf), "%.17g", v);
    }
    return buf;
}

std::string FormatBoundary(double v) {
    if (std::isinf(v)) return "+Inf";
    char buf[64];
    if (v == static_cast<double>(static_cast<int64_t>(v))
        && std::abs(v) < 1e15) {
        std::snprintf(buf, sizeof(buf), "%lld",
                      static_cast<long long>(v));
    } else {
        std::snprintf(buf, sizeof(buf), "%g", v);
    }
    return buf;
}

void AppendLabels(std::string& out,
                   const std::vector<std::pair<std::string, std::string>>& kv,
                   const std::string* extra_key = nullptr,
                   const std::string* extra_value = nullptr) {
    bool first = true;
    out += '{';
    for (const auto& [k, v] : kv) {
        if (!first) out += ',';
        first = false;
        out += PrometheusExporter::SanitizeName(k);
        out += "=\"";
        out += EscapeLabelValue(v);
        out += '"';
    }
    if (extra_key) {
        if (!first) out += ',';
        out += *extra_key;
        out += "=\"";
        out += EscapeLabelValue(*extra_value);
        out += '"';
    }
    out += '}';
}

const char* TypeLine(InstrumentKind kind) noexcept {
    switch (kind) {
        case InstrumentKind::Counter:       return "counter";
        case InstrumentKind::UpDownCounter: return "gauge";
        case InstrumentKind::Histogram:     return "histogram";
    }
    return "untyped";
}

void RenderInstrument(std::string& out,
                       const InstrumentSnapshot& inst,
                       PrometheusExporter::Format fmt) {
    (void)fmt;
    const std::string base = PrometheusExporter::SanitizeName(inst.name);
    if (base.empty()) return;

    const std::string emit_name =
        (inst.kind == InstrumentKind::Counter) ? base + "_total" : base;

    if (!inst.description.empty()) {
        out += "# HELP ";
        out += emit_name;
        out += ' ';
        for (char c : inst.description) {
            if (c == '\\')      out += "\\\\";
            else if (c == '\n') out += "\\n";
            else                out += c;
        }
        out += '\n';
    }
    out += "# TYPE ";
    out += emit_name;
    out += ' ';
    out += TypeLine(inst.kind);
    out += '\n';

    if (inst.kind == InstrumentKind::Counter
        || inst.kind == InstrumentKind::UpDownCounter) {
        for (const auto& p : inst.counter_points) {
            out += emit_name;
            AppendLabels(out, p.labels.kv);
            out += ' ';
            out += FormatValue(p.value);
            out += '\n';
        }
        return;
    }

    // Histogram: cumulative buckets, then _sum + _count.
    static const std::string kLeKey = "le";
    for (const auto& p : inst.histogram_points) {
        uint64_t cumulative = 0;
        for (size_t i = 0; i < p.bucket_boundaries.size(); ++i) {
            cumulative += (i < p.bucket_counts.size()) ? p.bucket_counts[i] : 0;
            const std::string boundary = FormatBoundary(p.bucket_boundaries[i]);
            out += base;
            out += "_bucket";
            AppendLabels(out, p.labels.kv, &kLeKey, &boundary);
            out += ' ';
            out += std::to_string(cumulative);
            out += '\n';
        }
        // +Inf bucket = total count (last bucket overflow).
        if (!p.bucket_counts.empty()) {
            cumulative += p.bucket_counts.back();
        }
        const std::string inf_boundary = "+Inf";
        out += base;
        out += "_bucket";
        AppendLabels(out, p.labels.kv, &kLeKey, &inf_boundary);
        out += ' ';
        out += std::to_string(p.count);
        out += '\n';

        out += base;
        out += "_sum";
        AppendLabels(out, p.labels.kv);
        out += ' ';
        out += FormatValue(p.sum);
        out += '\n';

        out += base;
        out += "_count";
        AppendLabels(out, p.labels.kv);
        out += ' ';
        out += std::to_string(p.count);
        out += '\n';
    }
}

void RenderTargetInfo(std::string& out, const Resource* res) {
    if (!res || res->attributes().empty()) return;
    out += "# HELP target_info Target metadata\n";
    out += "# TYPE target_info gauge\n";
    out += "target_info{";
    bool first = true;
    for (const auto& a : res->attributes()) {
        if (!first) out += ',';
        first = false;
        out += PrometheusExporter::SanitizeName(a.key);
        out += "=\"";
        std::string sval;
        std::visit([&sval](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::string>) {
                sval = arg;
            } else if constexpr (std::is_same_v<T, bool>) {
                sval = arg ? "true" : "false";
            } else if constexpr (std::is_same_v<T, int64_t>) {
                sval = std::to_string(arg);
            } else if constexpr (std::is_same_v<T, double>) {
                sval = FormatValue(arg);
            }
        }, a.value.value);
        out += EscapeLabelValue(sval);
        out += '"';
    }
    out += "} 1\n";
}

}  // namespace

std::string PrometheusExporter::SanitizeName(std::string_view name) {
    if (name.empty()) return std::string();
    std::string out;
    out.reserve(name.size() + 1);
    for (char c : name) {
        out += IsLegalChar(c) ? c : '_';
    }
    if (out[0] >= '0' && out[0] <= '9') {
        out.insert(out.begin(), '_');
    }
    return out;
}

PrometheusExporter::Format PrometheusExporter::ChooseFormat(
        std::string_view accept_header) noexcept {
    // OpenMetrics media type takes precedence per OpenMetrics spec §6
    // when present anywhere in the Accept header.
    static constexpr std::string_view kOpenMetrics =
        "application/openmetrics-text";
    if (accept_header.find(kOpenMetrics) != std::string_view::npos) {
        return Format::OpenMetrics;
    }
    return Format::PrometheusExposition;
}

const char* PrometheusExporter::ContentType(Format fmt) noexcept {
    switch (fmt) {
        case Format::OpenMetrics:
            return "application/openmetrics-text; version=1.0.0; charset=utf-8";
        case Format::PrometheusExposition:
        default:
            return "text/plain; version=0.0.4; charset=utf-8";
    }
}

std::string PrometheusExporter::Render(const MetricsSnapshot& snap,
                                         Format fmt) {
    std::string out;
    out.reserve(2048);

    // target_info gauge — operators pivot on resource attributes via this
    // pseudo-metric in Prometheus / OpenMetrics. Caller decides whether
    // to include it (live-reloadable per §11.2); the exporter renders
    // unconditionally and lets the handler omit on the off-toggle.
    RenderTargetInfo(out, snap.resource.get());

    for (const auto& inst : snap.instruments) {
        RenderInstrument(out, inst, fmt);
    }

    if (fmt == Format::OpenMetrics) {
        out += "# EOF\n";
    }
    return out;
}

}  // namespace OBSERVABILITY_NAMESPACE
