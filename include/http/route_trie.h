#pragma once

#include "common.h"
// <string>, <vector>, <memory>, <functional>, <algorithm>, <stdexcept>,
// <unordered_map> from common.h

// <regex> is NOT included here — it is one of the heaviest standard headers.
// The compiled regex is type-erased as shared_ptr<void>; implementation in
// route_trie.cc.

#include "log/logger.h"

namespace route_trie {

enum class NodeType : uint8_t {
    STATIC,     // Literal path prefix (including '/' separators)
    PARAM,      // :name parameter
    CATCH_ALL   // *name wildcard
};

// Segment produced by ParsePattern.
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
//
// Slash handling: '/' separators are stored as part of STATIC node prefixes.
// This ensures node splitting preserves slash boundaries.
//
// Param names: each leaf stores its own ordered list of param names. This
// allows routes like /users/:id and /users/:user_id/orders to share a PARAM
// node but use different names in their respective handlers.
//
// Thread-safety: all Insert() calls must complete before Start(). After that,
// the trie is read-only and the raw pointer in SearchResult is safe.
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

        // Collect ordered param/catch-all names for this route
        std::vector<std::string> param_names;
        for (const auto& seg : segments) {
            if ((seg.type == route_trie::NodeType::PARAM ||
                 seg.type == route_trie::NodeType::CATCH_ALL) &&
                !seg.param_name.empty()) {
                param_names.push_back(seg.param_name);
            }
        }

        if (segments.empty()) {
            if (root_->is_leaf) {
                throw std::invalid_argument("Duplicate route: " + pattern);
            }
            root_->is_leaf = true;
            root_->handler = std::move(handler);
            root_->pattern = pattern;
            root_->param_names = std::move(param_names);
            return;
        }

        InsertSegments(root_.get(), segments, 0, std::move(handler),
                       pattern, std::move(param_names));
    }

    SearchResult Search(const std::string& path,
                        std::unordered_map<std::string, std::string>& params) const {
        SearchResult result;
        if (!root_) return result;
        if (path.empty() || path[0] != '/') return result;

        // Collect param values in encounter order during traversal
        std::vector<std::string> values;

        if (path.size() == 1) {
            if (root_->is_leaf) {
                result.handler = &root_->handler;
                result.matched_pattern = root_->pattern;
                return result;
            }
            const HandlerType* found = nullptr;
            std::string matched;
            const std::vector<std::string>* leaf_names = nullptr;
            if (SearchChildren(root_.get(), "", 0, values, found, matched,
                               leaf_names, true)) {
                result.handler = found;
                result.matched_pattern = std::move(matched);
                PopulateParams(params, leaf_names, values);
            }
            return result;
        }

        const char* p = path.data() + 1;
        size_t remaining = path.size() - 1;
        const HandlerType* found = nullptr;
        std::string matched;
        const std::vector<std::string>* leaf_names = nullptr;
        if (SearchChildren(root_.get(), p, remaining, values, found, matched,
                           leaf_names, true)) {
            result.handler = found;
            result.matched_pattern = std::move(matched);
            PopulateParams(params, leaf_names, values);
        }
        return result;
    }

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
        std::string param_name;              // For PARAM/CATCH_ALL (used for constraint matching)
        std::shared_ptr<void> constraint;
        std::string constraint_str;
        std::vector<std::unique_ptr<Node>> children;
        bool is_leaf = false;
        HandlerType handler{};
        std::string pattern;
        std::vector<std::string> param_names; // Ordered param names for THIS route (leaf only)
    };

    std::unique_ptr<Node> root_;

    static constexpr size_t MAX_CONSTRAINT_SEGMENT_LEN = 256;

    // Zip ordered param values with the leaf's param names into the output map.
    static void PopulateParams(std::unordered_map<std::string, std::string>& params,
                               const std::vector<std::string>* names,
                               const std::vector<std::string>& values) {
        if (!names) return;
        size_t n = std::min(names->size(), values.size());
        for (size_t i = 0; i < n; ++i) {
            params[(*names)[i]] = values[i];
        }
    }

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
            child->param_names = std::move(node->param_names);
        }

        node->prefix = node->prefix.substr(0, at);
        node->children.clear();
        node->children.push_back(std::move(child));
        node->is_leaf = false;
        node->handler = HandlerType{};
        node->pattern.clear();
        node->param_name.clear();
        node->param_names.clear();
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

    void InsertSegments(Node* node, const std::vector<route_trie::Segment>& segments,
                        size_t seg_idx, HandlerType handler,
                        const std::string& full_pattern,
                        std::vector<std::string> param_names,
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
            node->param_names = std::move(param_names);
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
                                   std::move(handler), full_pattern,
                                   std::move(param_names));
                    return;
                }

                if (common == child_ptr->prefix.size()) {
                    InsertSegments(child_ptr.get(), segments, seg_idx,
                                   std::move(handler), full_pattern,
                                   std::move(param_names),
                                   seg_value.substr(common));
                    return;
                }

                if (common == seg_value.size()) {
                    SplitNode(child_ptr.get(), common);
                    InsertSegments(child_ptr.get(), segments, seg_idx + 1,
                                   std::move(handler), full_pattern,
                                   std::move(param_names));
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
                               std::move(handler), full_pattern,
                               std::move(param_names));
                return;
            }

            auto new_child = std::make_unique<Node>();
            new_child->prefix = seg_value;
            new_child->type = route_trie::NodeType::STATIC;
            Node* nc = new_child.get();
            node->children.push_back(std::move(new_child));
            SortChildren(node);
            InsertSegments(nc, segments, seg_idx + 1,
                           std::move(handler), full_pattern,
                           std::move(param_names));

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
                // Different param names at same position are allowed — the trie
                // node is shared but each leaf stores its own param_names list,
                // so handlers get the correct names for their route.
                InsertSegments(child_ptr.get(), segments, seg_idx + 1,
                               std::move(handler), full_pattern,
                               std::move(param_names));
                return;
            }

            // ReDoS warning: mitigated by MAX_CONSTRAINT_SEGMENT_LEN at search
            // time and max_header_size_ at the network boundary.
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
                           std::move(handler), full_pattern,
                           std::move(param_names));

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
            new_child->param_names = std::move(param_names);
            node->children.push_back(std::move(new_child));
            SortChildren(node);
        }
    }

    // Search: collects param VALUES in order; leaf's param_names zips them.
    bool SearchChildren(const Node* node, const char* path, size_t path_len,
                        std::vector<std::string>& values,
                        const HandlerType*& out_handler,
                        std::string& matched_pattern,
                        const std::vector<std::string>*& out_names,
                        bool at_segment_start) const {
        // STATIC children first
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::STATIC) break;

            if (path_len < child->prefix.size()) continue;
            if (std::memcmp(path, child->prefix.data(), child->prefix.size()) != 0) continue;

            size_t consumed = child->prefix.size();

            if (consumed == path_len) {
                if (child->is_leaf) {
                    out_handler = &child->handler;
                    matched_pattern = child->pattern;
                    out_names = &child->param_names;
                    return true;
                }
                bool child_at_seg = !child->prefix.empty() && child->prefix.back() == '/';
                if (SearchChildren(child.get(), path + consumed, 0, values,
                                   out_handler, matched_pattern, out_names,
                                   child_at_seg))
                    return true;
            } else {
                bool child_at_seg = !child->prefix.empty() && child->prefix.back() == '/';
                if (SearchChildren(child.get(), path + consumed, path_len - consumed,
                                   values, out_handler, matched_pattern, out_names,
                                   child_at_seg))
                    return true;
            }
        }

        if (!at_segment_start) return false;

        // PARAM children
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::PARAM) continue;

            size_t seg_end = 0;
            while (seg_end < path_len && path[seg_end] != '/') seg_end++;
            if (seg_end == 0) continue;

            std::string segment(path, seg_end);

            if (child->constraint) {
                if (seg_end > MAX_CONSTRAINT_SEGMENT_LEN) continue;
                if (!route_trie::MatchRegex(child->constraint.get(), segment))
                    continue;
            }

            // Push value (name comes from leaf's param_names later)
            values.push_back(std::move(segment));

            const char* after = path + seg_end;
            size_t after_len = path_len - seg_end;

            if (after_len == 0) {
                if (child->is_leaf) {
                    out_handler = &child->handler;
                    matched_pattern = child->pattern;
                    out_names = &child->param_names;
                    return true;
                }
                if (SearchChildren(child.get(), after, 0, values,
                                   out_handler, matched_pattern, out_names, true))
                    return true;
            } else {
                if (SearchChildren(child.get(), after, after_len, values,
                                   out_handler, matched_pattern, out_names, true))
                    return true;
            }

            // Backtrack
            values.pop_back();
        }

        // CATCH_ALL children
        for (const auto& child : node->children) {
            if (child->type != route_trie::NodeType::CATCH_ALL) continue;

            if (!child->param_name.empty()) {
                values.push_back(std::string(path, path_len));
            }
            out_handler = &child->handler;
            matched_pattern = child->pattern;
            out_names = &child->param_names;
            return true;
        }

        return false;
    }

    // Lightweight: no param extraction.
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
