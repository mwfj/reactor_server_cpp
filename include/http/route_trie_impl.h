#pragma once

// Implementation file for RouteTrie<HandlerType> template methods.
// Included at the bottom of route_trie.h — do not include directly.
//
// Kept separate because each method exceeds ~20 lines of template code.
// Including <regex> is intentionally avoided here — constraint matching is
// type-erased through shared_ptr<void> and MatchRegex() from route_trie.cc.

#include "log/logger.h"

template<typename HandlerType>
void RouteTrie<HandlerType>::Insert(const std::string& pattern, HandlerType handler) {
    auto segments = ROUTE_TRIE::ParsePattern(pattern);
    ROUTE_TRIE::ValidatePattern(pattern, segments);

    if (!root_) {
        root_ = std::make_unique<Node>();
        root_->type = ROUTE_TRIE::NodeType::STATIC;
    }

    // Collect ordered param/catch-all names for this route
    std::vector<std::string> param_names;
    for (const auto& seg : segments) {
        if ((seg.type == ROUTE_TRIE::NodeType::PARAM ||
             seg.type == ROUTE_TRIE::NodeType::CATCH_ALL) &&
            !seg.param_name.empty()) {
            param_names.push_back(seg.param_name);
        }
    }

    if (segments.empty()) {
        if (root_->is_leaf) {
            logging::Get()->warn("Route insert: duplicate route '{}'", pattern);
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

template<typename HandlerType>
typename RouteTrie<HandlerType>::SearchResult
RouteTrie<HandlerType>::Search(const std::string& path,
                               std::unordered_map<std::string, std::string>& params) const {
    SearchResult result;
    params.clear();  // Output parameter — clear stale keys from prior searches
    if (!root_) {
        logging::Get()->debug("Route search: empty path or no routes registered");
        return result;
    }
    if (path.empty()) {
        logging::Get()->debug("Route search: empty path or no routes registered");
        return result;
    }

    // Non-origin-form paths (CONNECT authority-form, OPTIONS *) don't start
    // with '/'. Search them as exact-match static children of root.
    if (path[0] != '/') {
        std::vector<std::string> values;
        const HandlerType* found = nullptr;
        std::string matched;
        const std::vector<std::string>* leaf_names = nullptr;
        if (SearchChildren(root_.get(), path.data(), path.size(), values,
                           found, matched, leaf_names, false)) {
            result.handler = found;
            result.matched_pattern = std::move(matched);
            PopulateParams(params, leaf_names, values);
        }
        return result;
    }

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

template<typename HandlerType>
void RouteTrie<HandlerType>::InsertSegments(
        Node* node, const std::vector<ROUTE_TRIE::Segment>& segments,
        size_t seg_idx, HandlerType handler,
        const std::string& full_pattern,
        std::vector<std::string> param_names,
        const std::string& static_remaining) {
    if (seg_idx == segments.size()) {
        if (node->is_leaf) {
            logging::Get()->warn(
                "Route insert: duplicate route '{}' conflicts with '{}'",
                full_pattern, node->pattern);
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
        (!static_remaining.empty() && seg.type == ROUTE_TRIE::NodeType::STATIC)
        ? static_remaining : seg.value;

    if (seg.type == ROUTE_TRIE::NodeType::STATIC) {
        for (auto& child_ptr : node->children) {
            if (child_ptr->type != ROUTE_TRIE::NodeType::STATIC) continue;

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
            new_child->type = ROUTE_TRIE::NodeType::STATIC;
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
        new_child->type = ROUTE_TRIE::NodeType::STATIC;
        Node* nc = new_child.get();
        node->children.push_back(std::move(new_child));
        SortChildren(node);
        InsertSegments(nc, segments, seg_idx + 1,
                       std::move(handler), full_pattern,
                       std::move(param_names));

    } else if (seg.type == ROUTE_TRIE::NodeType::PARAM) {
        for (auto& child_ptr : node->children) {
            if (child_ptr->type != ROUTE_TRIE::NodeType::PARAM) continue;

            if (child_ptr->constraint_str != seg.constraint) {
                logging::Get()->warn(
                    "Route insert: conflicting constraints for param at same "
                    "position: (:{}  '{}') vs (:{} '{}') in route '{}'",
                    child_ptr->param_name, child_ptr->constraint_str,
                    seg.param_name, seg.constraint, full_pattern);
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

        // ReDoS warning: total path length is bounded by max_header_size_
        // (default 8KB) at the network boundary.
        auto new_child = std::make_unique<Node>();
        new_child->type = ROUTE_TRIE::NodeType::PARAM;
        new_child->param_name = seg.param_name;
        if (!seg.constraint.empty()) {
            new_child->constraint = ROUTE_TRIE::CompileRegex(
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
            if (child_ptr->type == ROUTE_TRIE::NodeType::CATCH_ALL) {
                logging::Get()->warn(
                    "Route insert: duplicate catch-all route '{}' conflicts with '{}'",
                    full_pattern, child_ptr->pattern);
                throw std::invalid_argument(
                    "Duplicate catch-all route: " + full_pattern +
                    " conflicts with " + child_ptr->pattern);
            }
        }

        auto new_child = std::make_unique<Node>();
        new_child->type = ROUTE_TRIE::NodeType::CATCH_ALL;
        new_child->param_name = seg.param_name;
        new_child->is_leaf = true;
        new_child->handler = std::move(handler);
        new_child->pattern = full_pattern;
        new_child->param_names = std::move(param_names);
        node->children.push_back(std::move(new_child));
        SortChildren(node);
    }
}

template<typename HandlerType>
bool RouteTrie<HandlerType>::SearchChildren(
        const Node* node, const char* path, size_t path_len,
        std::vector<std::string>& values,
        const HandlerType*& out_handler,
        std::string& matched_pattern,
        const std::vector<std::string>*& out_names,
        bool at_segment_start) const {
    // STATIC children first
    for (const auto& child : node->children) {
        if (child->type != ROUTE_TRIE::NodeType::STATIC) break;

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
        if (child->type != ROUTE_TRIE::NodeType::PARAM) continue;

        size_t seg_end = 0;
        while (seg_end < path_len && path[seg_end] != '/') seg_end++;
        if (seg_end == 0) continue;

        std::string segment(path, seg_end);

        if (child->constraint) {
            if (!ROUTE_TRIE::MatchRegex(child->constraint.get(), segment)) {
                logging::Get()->debug(
                    "Route constraint rejected segment '{}' for param :{}",
                    segment, child->param_name);
                continue;
            }
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
        logging::Get()->debug(
            "Route param backtrack: :{} did not lead to complete match",
            child->param_name);
        values.pop_back();
    }

    // CATCH_ALL children.
    // The captured tail is the raw remaining path. With slashes-in-prefixes,
    // the preceding static prefix already consumed the '/' separator, so
    // normal paths never have a leading '/'. Paths with '//' are passed
    // through as-is (no normalization — consistent with raw path handling).
    for (const auto& child : node->children) {
        if (child->type != ROUTE_TRIE::NodeType::CATCH_ALL) continue;

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

template<typename HandlerType>
bool RouteTrie<HandlerType>::HasMatchChildren(
        const Node* node, const char* path, size_t path_len,
        bool at_segment_start) const {
    for (const auto& child : node->children) {
        if (child->type != ROUTE_TRIE::NodeType::STATIC) break;

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
        if (child->type != ROUTE_TRIE::NodeType::PARAM) continue;

        size_t seg_end = 0;
        while (seg_end < path_len && path[seg_end] != '/') seg_end++;
        if (seg_end == 0) continue;

        if (child->constraint) {
            std::string segment(path, seg_end);
            if (!ROUTE_TRIE::MatchRegex(child->constraint.get(), segment)) {
                logging::Get()->debug(
                    "Route constraint rejected segment '{}' for param :{}",
                    segment, child->param_name);
                continue;
            }
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
        if (child->type != ROUTE_TRIE::NodeType::CATCH_ALL) continue;
        return true;
    }

    return false;
}
