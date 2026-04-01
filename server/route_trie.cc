#include "http/route_trie.h"
#include "log/logger.h"

#include <regex>
#include <unordered_set>

namespace route_trie {

static bool IsValidNameChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static bool IsValidNameStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static void ValidateName(const std::string& name, const std::string& pattern) {
    if (name.empty()) {
        throw std::invalid_argument(
            "Empty parameter name in pattern: " + pattern);
    }
    if (!IsValidNameStart(name[0])) {
        throw std::invalid_argument(
            "Invalid parameter name '" + name +
            "' in pattern: " + pattern +
            " (must start with [a-zA-Z_])");
    }
    for (size_t i = 1; i < name.size(); ++i) {
        if (!IsValidNameChar(name[i])) {
            throw std::invalid_argument(
                "Invalid character in parameter name '" + name +
                "' in pattern: " + pattern);
        }
    }
}

// Extract balanced parentheses content starting at pos (which points at '(').
// Returns the regex string (without outer parens) and advances pos past ')'.
// Handles: backslash escapes (\( \)), character classes ([...]), and nesting.
static std::string ExtractConstraint(const std::string& pattern, size_t& pos) {
    if (pos >= pattern.size() || pattern[pos] != '(') {
        return "";
    }
    pos++;  // skip '('
    int depth = 1;
    bool in_char_class = false;
    size_t start = pos;
    while (pos < pattern.size() && depth > 0) {
        if (pattern[pos] == '\\' && pos + 1 < pattern.size()) {
            pos += 2;  // skip escaped character (e.g., \( \) \[ \])
            continue;
        }
        if (in_char_class) {
            if (pattern[pos] == ']') in_char_class = false;
            pos++;
            continue;
        }
        if (pattern[pos] == '[') {
            in_char_class = true;
            pos++;
            continue;
        }
        if (pattern[pos] == '(') depth++;
        else if (pattern[pos] == ')') depth--;
        if (depth > 0) pos++;
    }
    if (depth != 0) {
        throw std::invalid_argument(
            "Unbalanced parentheses in constraint in pattern: " + pattern);
    }
    std::string constraint = pattern.substr(start, pos - start);
    pos++;  // skip closing ')'
    if (constraint.empty()) {
        throw std::invalid_argument(
            "Empty regex constraint in pattern: " + pattern);
    }
    return constraint;
}

// ParsePattern produces segments where STATIC values include '/' separators.
// This preserves slash boundaries through node splitting, preventing
// /foobar and /foo/bar from colliding in the trie.
//
// Examples:
//   /health         → [STATIC "health"]
//   /foo/bar        → [STATIC "foo/bar"]
//   /users/:id      → [STATIC "users/", PARAM "id"]
//   /users/:id/ord  → [STATIC "users/", PARAM "id", STATIC "/ord"]
//   /:id            → [PARAM "id"]
//   /:id/bar        → [PARAM "id", STATIC "/bar"]
//   /static/*fp     → [STATIC "static/", CATCH_ALL "fp"]
//   /users/         → [STATIC "users/"]
//   /               → []
std::vector<Segment> ParsePattern(const std::string& pattern) {
    if (pattern.empty() || pattern[0] != '/') {
        throw std::invalid_argument(
            "Pattern must start with '/': " + pattern);
    }

    // Reject double slashes early
    if (pattern.find("//") != std::string::npos) {
        throw std::invalid_argument(
            "Empty path segment (double slash) in pattern: " + pattern);
    }

    // Root path "/" — zero segments, route terminates at root node
    if (pattern == "/") {
        return {};
    }

    std::vector<Segment> segments;
    size_t pos = 1;  // skip leading '/'
    std::string current_static;  // accumulates static text including '/' separators

    while (pos < pattern.size()) {
        if (pattern[pos] == '/') {
            // Slash separator — include it in the accumulated static text
            current_static += '/';
            pos++;
            if (pos >= pattern.size()) {
                // Trailing slash — the '/' is part of current_static
                break;
            }
            continue;
        }

        // ':' and '*' are only special at segment start (after '/' or at pos=1).
        // Mid-segment ':' or '*' (e.g., /v:version, /file*name) are static text.
        bool at_seg_start = current_static.empty() || current_static.back() == '/';

        if (at_seg_start && pattern[pos] == ':') {
            // PARAM — flush accumulated static (which includes trailing '/')
            if (!current_static.empty()) {
                Segment seg;
                seg.type = NodeType::STATIC;
                seg.value = std::move(current_static);
                segments.push_back(std::move(seg));
                current_static.clear();
            }

            pos++;  // skip ':'
            size_t name_start = pos;
            while (pos < pattern.size() && pattern[pos] != '/' && pattern[pos] != '(') {
                pos++;
            }
            std::string name = pattern.substr(name_start, pos - name_start);
            ValidateName(name, pattern);

            std::string constraint;
            if (pos < pattern.size() && pattern[pos] == '(') {
                constraint = ExtractConstraint(pattern, pos);
            }

            // After param name (and optional constraint), the next char must be
            // '/' or end-of-pattern. Trailing text like /:id.json or /:id([0-9]+).txt
            // would be unreachable because the PARAM node consumes the entire segment.
            if (pos < pattern.size() && pattern[pos] != '/') {
                throw std::invalid_argument(
                    "Trailing text after parameter ':" + name +
                    "' in pattern: " + pattern +
                    " (parameter must be the entire segment between '/' separators)");
            }

            Segment seg;
            seg.type = NodeType::PARAM;
            seg.param_name = std::move(name);
            seg.constraint = std::move(constraint);
            segments.push_back(std::move(seg));

        } else if (at_seg_start && pattern[pos] == '*') {
            // CATCH_ALL — flush accumulated static
            if (!current_static.empty()) {
                Segment seg;
                seg.type = NodeType::STATIC;
                seg.value = std::move(current_static);
                segments.push_back(std::move(seg));
                current_static.clear();
            }

            pos++;  // skip '*'
            size_t name_start = pos;
            while (pos < pattern.size() && pattern[pos] != '/') {
                pos++;
            }
            std::string name = pattern.substr(name_start, pos - name_start);
            if (!name.empty()) {
                ValidateName(name, pattern);
            }

            if (pos < pattern.size()) {
                throw std::invalid_argument(
                    "Catch-all must be the last segment in pattern: " + pattern);
            }

            Segment seg;
            seg.type = NodeType::CATCH_ALL;
            seg.param_name = std::move(name);
            segments.push_back(std::move(seg));

        } else {
            // Static text — accumulate (including any preceding '/' already added)
            while (pos < pattern.size() && pattern[pos] != '/') {
                current_static += pattern[pos];
                pos++;
            }
        }
    }

    // Flush remaining static text
    if (!current_static.empty()) {
        Segment seg;
        seg.type = NodeType::STATIC;
        seg.value = std::move(current_static);
        segments.push_back(std::move(seg));
    }

    return segments;
}

std::shared_ptr<void> CompileRegex(const std::string& pattern,
                                   const std::string& full_route) {
    try {
        auto re = std::make_shared<std::regex>(
            pattern, std::regex_constants::ECMAScript);
        return re;
    } catch (const std::regex_error& e) {
        throw std::invalid_argument(
            "Invalid regex constraint '(" + pattern +
            ")' in pattern: " + full_route + " — " + e.what());
    }
}

bool MatchRegex(const void* compiled, const std::string& segment) {
    if (!compiled) return true;
    const auto* re = static_cast<const std::regex*>(compiled);
    try {
        return std::regex_match(segment, *re);
    } catch (const std::regex_error&) {
        return false;
    }
}

void ValidatePattern(const std::string& pattern,
                     const std::vector<Segment>& segments) {
    // Check for duplicate parameter names within a single route
    std::unordered_set<std::string> names;
    for (const auto& seg : segments) {
        if (seg.type == NodeType::PARAM || seg.type == NodeType::CATCH_ALL) {
            if (!seg.param_name.empty()) {
                if (!names.insert(seg.param_name).second) {
                    throw std::invalid_argument(
                        "Duplicate parameter name '" + seg.param_name +
                        "' in pattern: " + pattern);
                }
            }
        }
    }

    // Catch-all must be last (already enforced by ParsePattern, but double-check)
    for (size_t i = 0; i < segments.size(); ++i) {
        if (segments[i].type == NodeType::CATCH_ALL && i != segments.size() - 1) {
            throw std::invalid_argument(
                "Catch-all must be the last segment in pattern: " + pattern);
        }
    }
}

}  // namespace route_trie
