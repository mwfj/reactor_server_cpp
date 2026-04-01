#pragma once

#include "common.h"
// <string>, <vector>, <memory>, <functional>, <algorithm>, <stdexcept>,
// <unordered_map> from common.h

// <regex> is NOT included here — it is one of the heaviest standard headers.
// The compiled regex is type-erased as shared_ptr<void>; implementation in
// route_trie.cc.

#include "log/logger.h"

namespace ROUTE_TRIE {

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

}  // namespace ROUTE_TRIE


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

    void Insert(const std::string& pattern, HandlerType handler);

    SearchResult Search(const std::string& path,
                        std::unordered_map<std::string, std::string>& params) const;

    bool HasMatch(const std::string& path) const {
        if (!root_) return false;
        if (path.empty()) return false;
        // Non-origin-form: exact-match static children only
        if (path[0] != '/') {
            return HasMatchChildren(root_.get(), path.data(), path.size(), false);
        }
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
        ROUTE_TRIE::NodeType type = ROUTE_TRIE::NodeType::STATIC;
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
                if (a->type == ROUTE_TRIE::NodeType::STATIC &&
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

    void InsertSegments(Node* node, const std::vector<ROUTE_TRIE::Segment>& segments,
                        size_t seg_idx, HandlerType handler,
                        const std::string& full_pattern,
                        std::vector<std::string> param_names,
                        const std::string& static_remaining = "");

    bool SearchChildren(const Node* node, const char* path, size_t path_len,
                        std::vector<std::string>& values,
                        const HandlerType*& out_handler,
                        std::string& matched_pattern,
                        const std::vector<std::string>*& out_names,
                        bool at_segment_start) const;

    bool HasMatchChildren(const Node* node, const char* path, size_t path_len,
                          bool at_segment_start) const;
};

#include "http/route_trie_impl.h"
