#include "http/http2_trailer_sanitizer.h"

namespace http {

H2TrailerFieldResult SanitizeHttp2TrailerField(
    std::string_view name, std::string_view value) {

    // Caller must already have lowercased `name`. We still defensively check
    // the canonical forbidden set so a future caller that forgets is caught.
    H2TrailerFieldResult result;
    result.lower_name = std::string(name);
    if (IsForbiddenH2TrailerName(name)) {
        result.classification = H2TrailerClassification::Forbidden;
    } else {
        result.classification = H2TrailerClassification::Accept;
    }
    return result;
}

std::vector<std::pair<std::string, std::string>>
SanitizeHttp2TrailerFieldsForOutboundEmit(
    const std::vector<std::pair<std::string, std::string>>& input) {

    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(input.size());
    for (const auto& [name, value] : input) {
        // ASCII-only bitwise lowercase — locale-independent.
        std::string lower = name;
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c | 0x20);
        }
        if (!IsForbiddenH2TrailerName(lower)) {
            out.emplace_back(std::move(lower), value);
        }
    }
    return out;
}

}  // namespace http
