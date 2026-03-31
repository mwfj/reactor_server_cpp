#pragma once

#include "common.h"
// <string>, <vector>, <memory>, <functional>, <algorithm>, <stdexcept> from common.h

// <unordered_map> provided by common.h
// <regex> is NOT included here — it is one of the heaviest standard headers
// and would propagate compile cost to all HTTP translation units. Instead,
// RegexConstraint is an opaque type whose definition lives in route_trie.cc.

#include "log/logger.h"

namespace route_trie {

enum class NodeType : uint8_t {
    STATIC,     // Literal path prefix
    PARAM,      // :name parameter
    CATCH_ALL   // *name wildcard
};

// Segment produced by ParsePattern — represents one piece of a route pattern.
struct Segment {
    NodeType type = NodeType::STATIC;
    std::string value;       // For STATIC: the literal text between slashes
    std::string param_name;  // For PARAM/CATCH_ALL: the parameter name
    std::string constraint;  // For PARAM: the regex string (empty if none)
};

// Non-template helpers (implemented in route_trie.cc)
std::vector<Segment> ParsePattern(const std::string& pattern);
void ValidatePattern(const std::string& pattern,
                     const std::vector<Segment>& segments);

// Regex helpers (implemented in route_trie.cc — <regex> stays there).
// The compiled regex is returned as a type-erased shared_ptr<void> so that
// <regex> is never included in this header. The deleter is captured at
// CompileRegex() call time inside route_trie.cc.
std::shared_ptr<void> CompileRegex(const std::string& pattern,
                                   const std::string& full_route);
bool MatchRegex(const void* compiled, const std::string& segment);

}  // namespace route_trie


// Compressed radix trie for URL route matching.
// One trie per HTTP method (GET, POST, etc.) or for WebSocket routes.
// Template on HandlerType to support both HTTP handlers and WS handlers.
//
// Thread-safety invariant: all Insert() calls must complete before the server
// calls Start() and begins dispatching requests. After Start(), the trie is
// read-only on all threads. The raw pointer returned in SearchResult is safe
// to dereference as long as no new routes are inserted after Start().
template<typename HandlerType>
class RouteTrie {
public:
    struct SearchResult {
        const HandlerType* handler = nullptr;
        std::string matched_pattern;
    };

    // Insert a route pattern with its handler.
    // Throws std::invalid_argument on invalid patterns or true conflicts.
    void Insert(const std::string& pattern, HandlerType handler) {
        auto segments = route_trie::ParsePattern(pattern);
        route_trie::ValidatePattern(pattern, segments);

        if (!root_) {
            root_ = std::make_unique<Node>();
            root_->type = route_trie::NodeType::STATIC;
        }

        // Root route "/" — zero segments, leaf on root
        if (segments.empty()) {
            if (root_->is_leaf) {
                throw std::invalid_argument(
                    "Duplicate route: " + pattern);
            }
            root_->is_leaf = true;
            root_->handler = std::move(handler);
            root_->pattern = pattern;
            return;
        }

        InsertSegments(root_.get(), segments, 0, std::move(handler), pattern);
    }

    // Search for a handler matching the given path.
    // Populates params with extracted parameter key-value pairs on match.
    SearchResult Search(const std::string& path,
                        std::unordered_map<std::string, std::string>& params) const {
        SearchResult result;
        if (!root_) return result;
        if (path.empty() || path[0] != '/') return result;

        // Root route "/"
        if (path.size() == 1) {
            if (root_->is_leaf) {
                result.handler = &root_->handler;
                result.matched_pattern = root_->pattern;
                return result;
            }
            // Root is not a leaf — check for catch-all child (e.g., /*rest)
            // that should match "/" with an empty captured tail.
            const HandlerType* found_handler = nullptr;
            std::string matched;
            if (SearchChildren(root_.get(), "", 0, params,
                               found_handler, matched, true)) {
                result.handler = found_handler;
                result.matched_pattern = std::move(matched);
            }
            return result;
        }

        // Strip leading '/' and search children at a segment boundary
        const char* p = path.data() + 1;
        size_t remaining = path.size() - 1;
        const HandlerType* found_handler = nullptr;
        std::string matched;
        if (SearchChildren(root_.get(), p, remaining, params,
                           found_handler, matched, true)) {
            result.handler = found_handler;
            result.matched_pattern = std::move(matched);
        }
        return result;
    }

    // Check if any route matches this path (for HasWebSocketRoute / 405 detection).
    // Lightweight: no param extraction, no map allocation.
    bool HasMatch(const std::string& path) const {
        if (!root_) return false;
        if (path.empty() || path[0] != '/') return false;

        if (path.size() == 1) {
            if (root_->is_leaf) return true;
            return HasMatchChildren(root_.get(), "", 0, true);
        }

        return HasMatchChildren(root_.get(), path.data() + 1, path.size() - 1, true);
    }

    bool Empty() const { return !root_; }

private:
    struct Node {
        std::string prefix;                          // For STATIC: the text content
        route_trie::NodeType type = route_trie::NodeType::STATIC;
        std::string param_name;                      // For PARAM/CATCH_ALL
        std::shared_ptr<void> constraint;            // For PARAM: type-erased compiled regex
        std::string constraint_str;                  // For PARAM: regex source string
        std::vector<std::unique_ptr<Node>> children;
        bool is_leaf = false;
        HandlerType handler{};                       // Valid when is_leaf == true
        std::string pattern;                         // Full original pattern string
    };

    std::unique_ptr<Node> root_;

    // Maximum segment length for regex constraint evaluation (ReDoS defense).
    static constexpr size_t MAX_CONSTRAINT_SEGMENT_LEN = 256;

    // Sort children by type priority: STATIC first, then PARAM, then CATCH_ALL.
    // Within STATIC children, sort by first character of prefix for fast lookup.
    static void SortChildren(Node* node) {
        std::stable_sort(node->children.begin(), node->children.end(),
            [](const std::unique_ptr<Node>& a, const std::unique_ptr<Node>& b) {
                if (a->type != b->type) {
                    return static_cast<uint8_t>(a->type) < static_cast<uint8_t>(b->type);
                }
                // Within STATIC nodes: empty prefix (trailing-slash sentinel)
                // sorts before non-empty prefixes, then by first character.
                if (a->type == route_trie::NodeType::STATIC) {
                    if (a->prefix.empty() != b->prefix.empty()) {
                        return a->prefix.empty();
                    }
                    if (!a->prefix.empty()) {
                        return a->prefix[0] < b->prefix[0];
                    }
                }
                return false;
            });
    }

    // Split a static node at position 'at'. The original node keeps prefix[0..at),
    // and a new child gets prefix[at..) along with the original's children/leaf/handler.
    static void SplitNode(Node* node, size_t at) {
        auto child = std::make_unique<Node>();
        child->prefix = node->prefix.substr(at);
        child->type = node->type;
        child->param_name = std::move(node->param_name);
        child->constraint = std::move(node->constraint);
        child->constraint_str = std::move(node->constraint_str);
        child->children = std::move(node->children);
        child->is_leaf = node->is_leaf;
        if (node->is_leaf) {
            child->handler = std::move(node->handler);
            child->pattern = std::move(node->pattern);
        }

        node->prefix = node->prefix.substr(0, at);
        node->children.clear();
        node->children.push_back(std::move(child));
        node->is_leaf = false;
        node->handler = HandlerType{};
        node->pattern.clear();
        node->param_name.clear();
        node->constraint.reset();
        node->constraint_str.clear();
    }

    // Find the length of the common prefix between two strings.
    static size_t CommonPrefixLen(const std::string& a, const std::string& b) {
        size_t len = std::min(a.size(), b.size());
        for (size_t i = 0; i < len; ++i) {
            if (a[i] != b[i]) return i;
        }
        return len;
    }

    // Recursive insertion of parsed segments into the trie.
    // static_remaining: non-empty when descending into a child whose prefix
    // matched only part of the current STATIC segment's value. Avoids copying
    // the entire segments vector just to modify one element.
    void InsertSegments(Node* node, const std::vector<route_trie::Segment>& segments,
                        size_t seg_idx, HandlerType handler,
                        const std::string& full_pattern,
                        const std::string& static_remaining = "") {
        if (seg_idx == segments.size()) {
            if (node->is_leaf) {
                throw std::invalid_argument(
                    "Duplicate route: " + full_pattern +
                    " conflicts with " + node->pattern);
            }
            node->is_leaf = true;
            node->handler = std::move(handler);
            node->pattern = full_pattern;
            return;
        }

        const auto& seg = segments[seg_idx];
        // Effective value for STATIC segments: use static_remaining if provided,
        // otherwise use the segment's value directly.
        const std::string& seg_value =
            (!static_remaining.empty() && seg.type == route_trie::NodeType::STATIC)
            ? static_remaining : seg.value;

        if (seg.type == route_trie::NodeType::STATIC) {
            // Try to find a child with a matching prefix
            for (auto& child_ptr : node->children) {
                if (child_ptr->type != route_trie::NodeType::STATIC) continue;

                size_t common = CommonPrefixLen(child_ptr->prefix, seg_value);
                if (common == 0) continue;

                if (common == child_ptr->prefix.size() && common == seg_value.size()) {
                    // Exact match — continue with next segment
                    InsertSegments(child_ptr.get(), segments, seg_idx + 1,
                                   std::move(handler), full_pattern);
                    return;
                }

                if (common == child_ptr->prefix.size()) {
                    // Child prefix is a prefix of segment — descend with remaining text
                    InsertSegments(child_ptr.get(), segments, seg_idx,
                                   std::move(handler), full_pattern,
                                   seg_value.substr(common));
                    return;
                }

                if (common == seg_value.size()) {
                    // Segment is a prefix of child — split child
                    SplitNode(child_ptr.get(), common);
                    InsertSegments(child_ptr.get(), segments, seg_idx + 1,
                                   std::move(handler), full_pattern);
                    return;
                }

                // Partial overlap — split child, create sibling
                SplitNode(child_ptr.get(), common);
                auto new_child = std::make_unique<Node>();
                new_child->prefix = seg_value.substr(common);
                new_child->type = route_trie::NodeType::STATIC;
                Node* new_child_ptr = new_child.get();
                child_ptr->children.push_back(std::move(new_child));
                SortChildren(child_ptr.get());
                InsertSegments(new_child_ptr, segments, seg_idx + 1,
                               std::move(handler), full_pattern);
                return;
            }

            // No matching child — create a new one
            auto new_child = std::make_unique<Node>();
            new_child->prefix = seg_value;
            new_child->type = route_trie::NodeType::STATIC;
            Node* new_child_ptr = new_child.get();
            node->children.push_back(std::move(new_child));
            SortChildren(node);
            InsertSegments(new_child_ptr, segments, seg_idx + 1,
                           std::move(handler), full_pattern);

        } else if (seg.type == route_trie::NodeType::PARAM) {
            // Check for existing PARAM child (at most one per node)
            for (auto& child_ptr : node->children) {
                if (child_ptr->type != route_trie::NodeType::PARAM) continue;

                // Constraint mismatch is a real conflict
                if (child_ptr->constraint_str != seg.constraint) {
                    throw std::invalid_argument(
                        "Conflicting constraints for param at same position: (:" +
                        child_ptr->param_name + " with '" + child_ptr->constraint_str +
                        "') vs (:" + seg.param_name + " with '" + seg.constraint +
                        "') in route " + full_pattern);
                }
                // Different param names are allowed — shared node, first name wins.
                // Log a warning so developers notice the name sharing.
                if (child_ptr->param_name != seg.param_name) {
                    logging::Get()->warn(
                        "Route {} uses param name '{}' at same position as existing "
                        "'{}'; handlers will receive the value under '{}'",
                        full_pattern, seg.param_name,
                        child_ptr->param_name, child_ptr->param_name);
                }
                InsertSegments(child_ptr.get(), segments, seg_idx + 1,
                               std::move(handler), full_pattern);
                return;
            }

            // No existing PARAM child — create one.
            // ReDoS warning: std::regex_match on untrusted path segments can
            // exhibit catastrophic backtracking with certain patterns (e.g.
            // "(a+)+" on long input). Mitigated at search time by the
            // MAX_CONSTRAINT_SEGMENT_LEN guard, and at the network boundary by
            // max_header_size_. Avoid user-supplied regexes in production routes.
            auto new_child = std::make_unique<Node>();
            new_child->type = route_trie::NodeType::PARAM;
            new_child->param_name = seg.param_name;
            if (!seg.constraint.empty()) {
                // CompileRegex returns a type-erased shared_ptr<void>;
                // throws std::invalid_argument on bad regex patterns.
                new_child->constraint = route_trie::CompileRegex(
                    seg.constraint, full_pattern);
                new_child->constraint_str = seg.constraint;
            }
            Node* new_child_ptr = new_child.get();
            node->children.push_back(std::move(new_child));
            SortChildren(node);
            InsertSegments(new_child_ptr, segments, seg_idx + 1,
                           std::move(handler), full_pattern);

        } else {
            // CATCH_ALL — must be the last segment (enforced by ParsePattern)
            // Check for existing CATCH_ALL child (at most one)
            for (auto& child_ptr : node->children) {
                if (child_ptr->type == route_trie::NodeType::CATCH_ALL) {
                    throw std::invalid_argument(
                        "Duplicate catch-all route: " + full_pattern +
                        " conflicts with " + child_ptr->pattern);
                }
            }

            auto new_child = std::make_unique<Node>();
            new_child->type = route_trie::NodeType::CATCH_ALL;
            new_child->param_name = seg.param_name;
            new_child->is_leaf = true;
            new_child->handler = std::move(handler);
            new_child->pattern = full_pattern;
            node->children.push_back(std::move(new_child));
            SortChildren(node);
        }
    }

    // Recursive search through children of a node.
    // at_segment_start: true when we're at a '/' boundary (param/catch-all eligible),
    //                   false when we're mid-segment after a static node split.
    // Stack depth is bounded by route depth (number of '/' segments + split nodes),
    // which is controlled by the developer at registration time, not by clients.
    bool SearchChildren(const Node* node, const char* path, size_t path_len,
                        std::unordered_map<std::string, std::string>& params,
                        const HandlerType*& out_handler,
                        std::string& matched_pattern,
                        bool at_segment_start) const {
        // Try STATIC children first (highest priority).
        // Children are sorted: STATIC first, then PARAM, then CATCH_ALL.
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::STATIC) break;

            if (child->prefix.empty()) {
                // Empty-string sentinel (trailing-slash node)
                if (path_len == 0 && child->is_leaf) {
                    out_handler = &child->handler;
                    matched_pattern = child->pattern;
                    return true;
                }
                continue;
            }

            if (path_len < child->prefix.size()) continue;
            if (std::memcmp(path, child->prefix.data(), child->prefix.size()) != 0) continue;

            size_t consumed = child->prefix.size();

            if (consumed == path_len) {
                // Consumed entire remaining path
                if (child->is_leaf) {
                    out_handler = &child->handler;
                    matched_pattern = child->pattern;
                    return true;
                }
                // Do NOT recurse into children here — that would allow
                // "/users" to match the trailing-slash sentinel for "/users/",
                // breaking the documented distinction between the two paths.
            } else if (path[consumed] == '/') {
                // Segment boundary — consume '/' and recurse
                if (SearchChildren(child.get(), path + consumed + 1,
                                   path_len - consumed - 1,
                                   params, out_handler, matched_pattern, true)) {
                    return true;
                }
            } else {
                // Same-segment recursion: static prefix matched but more
                // non-slash chars remain (node was split, e.g., "health"+"check")
                if (SearchChildren(child.get(), path + consumed,
                                   path_len - consumed,
                                   params, out_handler, matched_pattern, false)) {
                    return true;
                }
            }
        }

        // PARAM and CATCH_ALL only at segment boundaries
        if (!at_segment_start) return false;

        // Try PARAM children (second priority).
        // At most one PARAM child per node (enforced by InsertSegments).
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::PARAM) continue;

            // Extract segment: everything up to next '/' or end of path
            size_t seg_end = 0;
            while (seg_end < path_len && path[seg_end] != '/') {
                seg_end++;
            }
            if (seg_end == 0) continue;  // empty segment — params must be non-empty

            std::string segment(path, seg_end);

            // Check regex constraint if present.
            // Defense-in-depth against ReDoS: skip regex evaluation on
            // abnormally long segments. The global max_header_size_ (8 KB)
            // already bounds total path length, but a single segment could
            // still consume excessive CPU with a pathological pattern.
            // 256 bytes is a generous upper bound for any legitimate segment.
            if (child->constraint) {
                if (seg_end > MAX_CONSTRAINT_SEGMENT_LEN) {
                    // Segment too long to safely evaluate the regex — non-match.
                    continue;
                }
                if (!route_trie::MatchRegex(child->constraint.get(), segment)) {
                    continue;
                }
            }

            // Tentatively add param
            params[child->param_name] = segment;

            if (seg_end == path_len) {
                // Consumed entire remaining path
                if (child->is_leaf) {
                    out_handler = &child->handler;
                    matched_pattern = child->pattern;
                    return true;
                }
                // Do NOT recurse into children here — that would allow
                // "/users/42" to match the trailing-slash sentinel for
                // "/users/:id/", breaking the documented distinction.
                // Same discipline as the STATIC node case above.
            } else {
                // path[seg_end] == '/' — more segments follow
                if (SearchChildren(child.get(), path + seg_end + 1,
                                   path_len - seg_end - 1,
                                   params, out_handler, matched_pattern, true)) {
                    return true;
                }
            }

            // Backtrack: remove param
            params.erase(child->param_name);
        }

        // Try CATCH_ALL children (lowest priority).
        // Convention (matching Gin/httprouter): the captured tail does NOT
        // include a leading '/'. For example, pattern "/static/*filepath"
        // matching "/static/css/style.css" captures "css/style.css" — the
        // separator before the wildcard is consumed by the trie traversal.
        // Callers that want the full sub-path must prepend '/' themselves.
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::CATCH_ALL) continue;

            std::string remaining(path, path_len);
            if (!child->param_name.empty()) {
                params[child->param_name] = remaining;
            }
            out_handler = &child->handler;
            matched_pattern = child->pattern;
            return true;
        }

        return false;
    }

    // Lightweight match check — no param extraction, no map allocation.
    // Used by HasMatch() for 405 detection where only a bool is needed.
    bool HasMatchChildren(const Node* node, const char* path, size_t path_len,
                          bool at_segment_start) const {
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::STATIC) break;

            if (child->prefix.empty()) {
                if (path_len == 0 && child->is_leaf) return true;
                continue;
            }

            if (path_len < child->prefix.size()) continue;
            if (std::memcmp(path, child->prefix.data(), child->prefix.size()) != 0) continue;

            size_t consumed = child->prefix.size();
            if (consumed == path_len) {
                if (child->is_leaf) return true;
            } else if (path[consumed] == '/') {
                if (HasMatchChildren(child.get(), path + consumed + 1,
                                     path_len - consumed - 1, true))
                    return true;
            } else {
                if (HasMatchChildren(child.get(), path + consumed,
                                     path_len - consumed, false))
                    return true;
            }
        }

        if (!at_segment_start) return false;

        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::PARAM) continue;

            size_t seg_end = 0;
            while (seg_end < path_len && path[seg_end] != '/') seg_end++;
            if (seg_end == 0) continue;

            if (child->constraint) {
                if (seg_end > MAX_CONSTRAINT_SEGMENT_LEN) continue;
                std::string segment(path, seg_end);
                if (!route_trie::MatchRegex(child->constraint.get(), segment))
                    continue;
            }

            if (seg_end == path_len) {
                if (child->is_leaf) return true;
            } else {
                if (HasMatchChildren(child.get(), path + seg_end + 1,
                                     path_len - seg_end - 1, true))
                    return true;
            }
        }

        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::CATCH_ALL) continue;
            return true;
        }

        return false;
    }
};
