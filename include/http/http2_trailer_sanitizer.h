#pragma once
#include "common.h"

namespace http {

enum class H2TrailerClassification {
    Accept,
    Forbidden
};

// Caller must lowercase the name before calling.
inline bool IsForbiddenH2TrailerName(std::string_view lower_name) {
    if (lower_name.empty() || lower_name[0] == ':') return true;
    return lower_name == "connection" ||
           lower_name == "keep-alive" ||
           lower_name == "proxy-connection" ||
           lower_name == "transfer-encoding" ||
           lower_name == "upgrade" ||
           lower_name == "te" ||
           lower_name == "trailer" ||
           lower_name == "content-length" ||
           lower_name == "host" ||
           lower_name == "authorization" ||
           lower_name == "content-type" ||
           lower_name == "content-encoding" ||
           lower_name == "content-range";
}

struct H2TrailerFieldResult {
    H2TrailerClassification classification;
    std::string lower_name;
};

H2TrailerFieldResult SanitizeHttp2TrailerField(
    std::string_view name, std::string_view value);

std::vector<std::pair<std::string, std::string>>
SanitizeHttp2TrailerFieldsForOutboundEmit(
    const std::vector<std::pair<std::string, std::string>>& input);

}  // namespace http
