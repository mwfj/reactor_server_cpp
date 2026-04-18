#pragma once

#include "common.h"

inline bool IsForbiddenTrailerFieldName(const std::string& lower_name) {
    if (lower_name.empty()) return true;
    if (lower_name[0] == ':') return true;
    return lower_name == "connection" || lower_name == "keep-alive" ||
           lower_name == "proxy-connection" ||
           lower_name == "transfer-encoding" || lower_name == "upgrade" ||
           lower_name == "te" || lower_name == "content-length" ||
           lower_name == "host" || lower_name == "authorization" ||
           lower_name == "content-type" ||
           lower_name == "content-encoding" ||
           lower_name == "content-range";
}

inline std::string TrimOptionalWhitespace(std::string value) {
    size_t begin = 0;
    while (begin < value.size() &&
           (value[begin] == ' ' || value[begin] == '\t')) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin &&
           (value[end - 1] == ' ' || value[end - 1] == '\t')) {
        --end;
    }
    return value.substr(begin, end - begin);
}
