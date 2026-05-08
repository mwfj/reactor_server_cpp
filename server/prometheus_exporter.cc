#include "observability/prometheus_exporter.h"

#include "log/logger.h"
#include "observability/resource.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <variant>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Replace every char outside [a-zA-Z0-9_] with '_'; if the result
// starts with a digit, prepend '_'. Empty input stays empty (the
// registry rejects empty names earlier).
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
//
// The magnitude check (`< kIntFormatLimit`) MUST run before the
// double→int64 conversion. C++ converts a finite double whose
// truncated value is outside the int64 range with undefined
// behaviour; checking magnitude first avoids the UB regardless of
// which compiler-defined trap a platform exhibits. 1e15 is well
// inside int64 range (~9.2e18) so anything within the gate is
// safely representable.
static constexpr double kIntFormatLimit = 1e15;
std::string FormatValue(double v) {
    if (std::isnan(v)) return "NaN";
    if (std::isinf(v)) return v > 0 ? "+Inf" : "-Inf";
    char buf[64];
    if (std::abs(v) < kIntFormatLimit
        && v == static_cast<double>(static_cast<int64_t>(v))) {
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
    if (std::abs(v) < kIntFormatLimit
        && v == static_cast<double>(static_cast<int64_t>(v))) {
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
    // Prometheus / OpenMetrics text format omits the label block
    // entirely for label-less samples: `active 11`, not `active{} 11`.
    // Some scrapers reject the empty-brace form. Skip the braces when
    // both the user labels and any extra_key (used for histogram
    // `le="..."`) are absent.
    if (kv.empty() && extra_key == nullptr) {
        return;
    }
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

    // Per OpenMetrics 1.0 §5.1, the `# HELP` / `# TYPE` lines carry
    // the bare family name; only individual samples carry the
    // Counter `_total` suffix. Strict validators (`promtool check
    // metrics --strict`) reject `# TYPE foo_total counter`. Use
    // `base` for the metadata lines and `emit_name` for the samples
    // below.
    if (!inst.description.empty()) {
        out += "# HELP ";
        out += base;
        out += ' ';
        for (char c : inst.description) {
            if (c == '\\')      out += "\\\\";
            else if (c == '\n') out += "\\n";
            else                out += c;
        }
        out += '\n';
    }
    out += "# TYPE ";
    out += base;
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
        // +Inf bucket = total count. Emitted from p.count directly
        // (the cumulative running total above is used only for the
        // finite-boundary lines).
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
    // RFC 7231 §5.3.2: media types are case-insensitive and may carry
    // q-values. A naive substring scan misses `Application/OpenMetrics-Text`
    // (legal casing) and ignores `q=0` (explicit rejection). We parse the
    // header into media-range/q pairs and pick OpenMetrics only when its
    // q-value is positive AND ≥ the q-value of any other range that would
    // otherwise win (text/plain or */*).
    static constexpr std::string_view kOpenMetrics =
        "application/openmetrics-text";

    auto trim = [](std::string_view s) {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
        while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
        return s;
    };
    auto iequals = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            unsigned char ca = static_cast<unsigned char>(a[i]);
            unsigned char cb = static_cast<unsigned char>(b[i]);
            if (std::tolower(ca) != std::tolower(cb)) return false;
        }
        return true;
    };
    // Best q-values seen so far. Default to "absent" via -1.
    double q_openmetrics = -1.0;
    double q_default     = -1.0;  // text/plain or */* — would win without OM

    size_t i = 0;
    while (i < accept_header.size()) {
        size_t comma = accept_header.find(',', i);
        std::string_view item = accept_header.substr(
            i, comma == std::string_view::npos ? std::string_view::npos : comma - i);
        i = (comma == std::string_view::npos) ? accept_header.size() : comma + 1;

        item = trim(item);
        if (item.empty()) continue;

        // Split media-range from parameters on the first ';'.
        size_t semi = item.find(';');
        std::string_view media = trim(item.substr(0, semi));
        double q = 1.0;
        if (semi != std::string_view::npos) {
            std::string_view params = item.substr(semi + 1);
            while (!params.empty()) {
                size_t s = params.find(';');
                std::string_view p = trim(
                    s == std::string_view::npos ? params : params.substr(0, s));
                params = (s == std::string_view::npos)
                    ? std::string_view{} : params.substr(s + 1);
                size_t eq = p.find('=');
                if (eq == std::string_view::npos) continue;
                std::string_view pname  = trim(p.substr(0, eq));
                std::string_view pvalue = trim(p.substr(eq + 1));
                if (iequals(pname, "q")) {
                    // Lenient parse — invalid → leave q at 1.0 (default).
                    char buf[32];
                    size_t n = std::min(pvalue.size(), sizeof(buf) - 1);
                    std::memcpy(buf, pvalue.data(), n);
                    buf[n] = '\0';
                    char* end = nullptr;
                    double parsed = std::strtod(buf, &end);
                    if (end != buf && parsed >= 0.0 && parsed <= 1.0) q = parsed;
                }
            }
        }

        if (iequals(media, kOpenMetrics)) {
            if (q > q_openmetrics) q_openmetrics = q;
        } else if (iequals(media, "text/plain") ||
                   iequals(media, "*/*") ||
                   iequals(media, "text/*") ||
                   iequals(media, "application/*")) {
            if (q > q_default) q_default = q;
        }
    }

    // Pick OpenMetrics only when explicitly accepted (q>0) and at least
    // as preferred as the default. Equal q ties break in OpenMetrics'
    // favor — preserves the historical behavior for the standard scraper
    // header `application/openmetrics-text;version=...,text/plain;...`
    // where both are present at q=1.
    if (q_openmetrics > 0.0 && q_openmetrics >= q_default) {
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

// Compute the wire-level emit name for an instrument: SanitizeName,
// plus the "_total" suffix that Counter renders use. Keep in lockstep
// with RenderInstrument's emit_name computation — collision dedup
// MUST key on this, not on SanitizeName alone, because Counter "foo"
// and Gauge "foo_total" both end up writing `# TYPE foo_total` and
// only an emit-name keyed map detects the collision.
std::string ComputeEmitName(const InstrumentSnapshot& inst) {
    std::string base = PrometheusExporter::SanitizeName(inst.name);
    if (base.empty()) return base;
    if (inst.kind == InstrumentKind::Counter) base += "_total";
    return base;
}

// Process-lifetime warned set, capped to bound memory growth from
// dynamic instrument registration (Phase 2+).
std::mutex& CollisionWarnedMtx() {
    static std::mutex m;
    return m;
}
std::unordered_set<std::string>& CollisionWarnedSet() {
    static std::unordered_set<std::string> s;
    return s;
}
void WarnCollisionOnce(const std::string&  key,
                        const std::string& a_name,
                        const std::string& b_name,
                        const std::string& emit_name) {
    static constexpr size_t kMaxWarnedCollisions = 1024;
    std::lock_guard<std::mutex> g(CollisionWarnedMtx());
    auto& warned = CollisionWarnedSet();
    if (warned.size() >= kMaxWarnedCollisions) return;
    if (!warned.insert(key).second) return;
    logging::Get()->warn(
        "prometheus: name collision — '{}' and '{}' both render as "
        "'{}'; the second instrument will be SUPPRESSED to keep "
        "output OpenMetrics-valid. Rename one of the OTel instruments.",
        a_name, b_name, emit_name);
}

std::string PrometheusExporter::Render(const MetricsSnapshot& snap,
                                         Format fmt) {
    std::string out;
    out.reserve(2048);

    // target_info — emitted from Resource attrs whenever the snapshot
    // carries a Resource. The handler clears snap.resource to suppress
    // it when include_target_info is off.
    RenderTargetInfo(out, snap.resource.get());

    // Dedup duplicates by emit_name within this scrape. The first
    // instrument with a given emit_name wins; subsequent ones are
    // skipped (and a once-per-process warn is emitted) so output
    // never contains conflicting `# TYPE` blocks for the same family.
    std::unordered_map<std::string, std::string> emitted_to_original;
    emitted_to_original.reserve(snap.instruments.size());
    for (const auto& inst : snap.instruments) {
        std::string emit = ComputeEmitName(inst);
        if (emit.empty()) continue;
        auto [it, inserted] =
            emitted_to_original.try_emplace(emit, inst.name);
        if (!inserted) {
            if (it->second == inst.name) continue;  // same instrument repeated
            WarnCollisionOnce(emit + "|" + it->second + "|" + inst.name,
                              it->second, inst.name, emit);
            continue;  // suppress conflicting render
        }
        RenderInstrument(out, inst, fmt);
    }

    if (fmt == Format::OpenMetrics) {
        out += "# EOF\n";
    }
    return out;
}

}  // namespace OBSERVABILITY_NAMESPACE
