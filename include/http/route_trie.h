#pragma once

#include "common.h"
// <string>, <vector>, <memory>, <functional>, <algorithm>, <stdexcept>,
// <unordered_map> from common.h

// <regex> is NOT included here — it is one of the heaviest standard headers
// and would propagate compile cost to all HTTP translation units. Instead,
// the compiled regex is type-erased as shared_ptr<void> with implementation
// in route_trie.cc.

#include "log/logger.h"

namespace route_trie {

enum class NodeType : uint8_t {
    STATIC,     // Literal path prefix (including '/' separators)
    PARAM,      // :name parameter
    CATCH_ALL   // *name wildcard
};

// Segment produced by ParsePattern — represents one piece of a route pattern.
// STATIC values include '/' separators to preserve slash boundaries through
// node splitting (e.g., "/foo/bar" → STATIC "foo/bar", not two separate nodes).
struct Segment {
    NodeType type = NodeType::STATIC;
    std::string value;       // For STATIC: literal text including '/' separators
    std::string param_name;  // For PARAM/CATCH_ALL: the parameter name
    std::string constraint;  // For PARAM: the regex string (empty if none)
};

// Non-template helpers (implemented in route_trie.cc)
std::vector<Segment> ParsePattern(const std::string& pattern);
void ValidatePattern(const std::string& pattern,
                     const std::vector<Segment>& segments);

// Regex helpers (implemented in route_trie.cc — <regex> stays there).
std::shared_ptr<void> CompileRegex(const std::string& pattern,
                                   const std::string& full_route);
bool MatchRegex(const void* compiled, const std::string& segment);

}  // namespace route_trie


// Compressed radix trie for URL route matching.
// One trie per HTTP method (GET, POST, etc.) or for WebSocket routes.
// Template on HandlerType to support both HTTP handlers and WS handlers.
//
// Slash handling: '/' separators are stored as part of STATIC node prefixes,
// not consumed separately during search. This ensures node splitting preserves
// slash boundaries (e.g., /foobar and /foo/bar never collide).
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
                throw std::invalid_argument("Duplicate route: " + pattern);
            }
            root_->is_leaf = true;
            root_->handler = std::move(handler);
            root_->pattern = pattern;
            return;
        }

        InsertSegments(root_.get(), segments, 0, std::move(handler), pattern);
    }

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
            // Check root children (e.g., catch-all /*rest should match "/")
            const HandlerType* found = nullptr;
            std::string matched;
            if (SearchChildren(root_.get(), "", 0, params, found, matched, true)) {
                result.handler = found;
                result.matched_pattern = std::move(matched);
            }
            return result;
        }

        // Strip leading '/' and search children at a segment boundary
        const char* p = path.data() + 1;
        size_t remaining = path.size() - 1;
        const HandlerType* found = nullptr;
        std::string matched;
        if (SearchChildren(root_.get(), p, remaining, params, found, matched, true)) {
            result.handler = found;
            result.matched_pattern = std::move(matched);
        }
        return result;
    }

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
        std::string prefix;
        route_trie::NodeType type = route_trie::NodeType::STATIC;
        std::string param_name;
        std::shared_ptr<void> constraint;
        std::string constraint_str;
        std::vector<std::unique_ptr<Node>> children;
        bool is_leaf = false;
        HandlerType handler{};
        std::string pattern;
    };

    std::unique_ptr<Node> root_;

    // Maximum segment length for regex constraint evaluation (ReDoS defense).
    static constexpr size_t MAX_CONSTRAINT_SEGMENT_LEN = 256;

    static void SortChildren(Node* node) {
        std::stable_sort(node->children.begin(), node->children.end(),
            [](const std::unique_ptr<Node>& a, const std::unique_ptr<Node>& b) {
                if (a->type != b->type) {
                    return static_cast<uint8_t>(a->type) < static_cast<uint8_t>(b->type);
                }
                if (a->type == route_trie::NodeType::STATIC &&
                    !a->prefix.empty() && !b->prefix.empty()) {
                    return a->prefix[0] < b->prefix[0];
                }
                return false;
            });
    }

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

    static size_t CommonPrefixLen(const std::string& a, const std::string& b) {
        size_t len = std::min(a.size(), b.size());
        for (size_t i = 0; i < len; ++i) {
            if (a[i] != b[i]) return i;
        }
        return len;
    }

    // Recursive insertion.
    // static_remaining: non-empty when a STATIC segment's prefix partially
    // matched a child — pass the suffix instead of copying the segment vector.
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
        const std::string& seg_value =
            (!static_remaining.empty() && seg.type == route_trie::NodeType::STATIC)
            ? static_remaining : seg.value;

        if (seg.type == route_trie::NodeType::STATIC) {
            for (auto& child_ptr : node->children) {
                if (child_ptr->type != route_trie::NodeType::STATIC) continue;

                size_t common = CommonPrefixLen(child_ptr->prefix, seg_value);
                if (common == 0) continue;

                if (common == child_ptr->prefix.size() && common == seg_value.size()) {
                    InsertSegments(child_ptr.get(), segments, seg_idx + 1,
                                   std::move(handler), full_pattern);
                    return;
                }

                if (common == child_ptr->prefix.size()) {
                    InsertSegments(child_ptr.get(), segments, seg_idx,
                                   std::move(handler), full_pattern,
                                   seg_value.substr(common));
                    return;
                }

                if (common == seg_value.size()) {
                    SplitNode(child_ptr.get(), common);
                    InsertSegments(child_ptr.get(), segments, seg_idx + 1,
                                   std::move(handler), full_pattern);
                    return;
                }

                SplitNode(child_ptr.get(), common);
                auto new_child = std::make_unique<Node>();
                new_child->prefix = seg_value.substr(common);
                new_child->type = route_trie::NodeType::STATIC;
                Node* nc = new_child.get();
                child_ptr->children.push_back(std::move(new_child));
                SortChildren(child_ptr.get());
                InsertSegments(nc, segments, seg_idx + 1,
                               std::move(handler), full_pattern);
                return;
            }

            auto new_child = std::make_unique<Node>();
            new_child->prefix = seg_value;
            new_child->type = route_trie::NodeType::STATIC;
            Node* nc = new_child.get();
            node->children.push_back(std::move(new_child));
            SortChildren(node);
            InsertSegments(nc, segments, seg_idx + 1,
                           std::move(handler), full_pattern);

        } else if (seg.type == route_trie::NodeType::PARAM) {
            for (auto& child_ptr : node->children) {
                if (child_ptr->type != route_trie::NodeType::PARAM) continue;

                if (child_ptr->constraint_str != seg.constraint) {
                    throw std::invalid_argument(
                        "Conflicting constraints for param at same position: (:" +
                        child_ptr->param_name + " with '" + child_ptr->constraint_str +
                        "') vs (:" + seg.param_name + " with '" + seg.constraint +
                        "') in route " + full_pattern);
                }
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

            // ReDoS warning: std::regex_match on untrusted path segments can
            // exhibit catastrophic backtracking with certain patterns (e.g.
            // "(a+)+" on long input). Mitigated at search time by the
            // MAX_CONSTRAINT_SEGMENT_LEN guard, and at the network boundary by
            // max_header_size_. Avoid user-supplied regexes in production routes.
            auto new_child = std::make_unique<Node>();
            new_child->type = route_trie::NodeType::PARAM;
            new_child->param_name = seg.param_name;
            if (!seg.constraint.empty()) {
                new_child->constraint = route_trie::CompileRegex(
                    seg.constraint, full_pattern);
                new_child->constraint_str = seg.constraint;
            }
            Node* nc = new_child.get();
            node->children.push_back(std::move(new_child));
            SortChildren(node);
            InsertSegments(nc, segments, seg_idx + 1,
                           std::move(handler), full_pattern);

        } else {
            // CATCH_ALL
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

    // Search children of a node.
    // at_segment_start: true at '/' boundaries (PARAM/CATCH_ALL eligible).
    //   Determined by whether the consumed prefix ended with '/'.
    // Stack depth bounded by route depth, controlled by developer not clients.
    bool SearchChildren(const Node* node, const char* path, size_t path_len,
                        std::unordered_map<std::string, std::string>& params,
                        const HandlerType*& out_handler,
                        std::string& matched_pattern,
                        bool at_segment_start) const {
        // Try STATIC children first (highest priority).
        // Children sorted: STATIC, then PARAM, then CATCH_ALL.
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::STATIC) break;

            if (path_len < child->prefix.size()) continue;
            if (std::memcmp(path, child->prefix.data(), child->prefix.size()) != 0) continue;

            size_t consumed = child->prefix.size();

            if (consumed == path_len) {
                if (child->is_leaf) {
                    out_handler = &child->handler;
                    matched_pattern = child->pattern;
                    return true;
                }
                // Recurse with empty remaining — allows catch-all children to
                // match (e.g., /static/*fp matching /static/ when prefix="static/").
                bool child_at_seg = !child->prefix.empty() && child->prefix.back() == '/';
                if (SearchChildren(child.get(), path + consumed, 0,
                                   params, out_handler, matched_pattern, child_at_seg)) {
                    return true;
                }
            } else {
                // More chars remain — determine if this is a segment boundary.
                // Prefix ending with '/' means remaining is at a new segment.
                bool child_at_seg = !child->prefix.empty() && child->prefix.back() == '/';
                if (SearchChildren(child.get(), path + consumed,
                                   path_len - consumed,
                                   params, out_handler, matched_pattern, child_at_seg)) {
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

            // ReDoS defense: skip regex on abnormally long segments.
            if (child->constraint) {
                if (seg_end > MAX_CONSTRAINT_SEGMENT_LEN) continue;
                if (!route_trie::MatchRegex(child->constraint.get(), segment))
                    continue;
            }

            params[child->param_name] = segment;

            // After PARAM, remaining includes the '/' (consumed by next child's
            // static prefix). Do NOT skip the '/'.
            const char* after = path + seg_end;
            size_t after_len = path_len - seg_end;

            if (after_len == 0) {
                if (child->is_leaf) {
                    out_handler = &child->handler;
                    matched_pattern = child->pattern;
                    return true;
                }
                // Recurse for catch-all children on empty remaining
                if (SearchChildren(child.get(), after, 0,
                                   params, out_handler, matched_pattern, true)) {
                    return true;
                }
            } else {
                // after[0] == '/' — pass to children including the '/'
                if (SearchChildren(child.get(), after, after_len,
                                   params, out_handler, matched_pattern, true)) {
                    return true;
                }
            }

            params.erase(child->param_name);
        }

        // Try CATCH_ALL children (lowest priority).
        // Convention (matching Gin/httprouter): captured tail does NOT include
        // leading '/'. The '/' is consumed by the preceding static prefix.
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
    bool HasMatchChildren(const Node* node, const char* path, size_t path_len,
                          bool at_segment_start) const {
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::STATIC) break;

            if (path_len < child->prefix.size()) continue;
            if (std::memcmp(path, child->prefix.data(), child->prefix.size()) != 0) continue;

            size_t consumed = child->prefix.size();
            bool child_at_seg = !child->prefix.empty() && child->prefix.back() == '/';

            if (consumed == path_len) {
                if (child->is_leaf) return true;
                if (HasMatchChildren(child.get(), path + consumed, 0, child_at_seg))
                    return true;
            } else {
                if (HasMatchChildren(child.get(), path + consumed,
                                     path_len - consumed, child_at_seg))
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
                if (HasMatchChildren(child.get(), path + seg_end, 0, true))
                    return true;
            } else {
                if (HasMatchChildren(child.get(), path + seg_end,
                                     path_len - seg_end, true))
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
