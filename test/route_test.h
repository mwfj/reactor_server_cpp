#pragma once

#include "test_framework.h"
#include "http/route_trie.h"
#include "http/http_router.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_server.h"

#include <string>
#include <stdexcept>

// =============================================================================
// RouteTests — comprehensive tests for RouteTrie and HttpRouter pattern matching
//
// Port range: 10600-10650 (reserved for this suite; no live server used here)
//
// Dimensions covered:
//   1. RouteTrie unit tests  — direct trie API (no HTTP server)
//   2. HttpRouter integration — router dispatch, params, 405, HEAD fallback,
//                               middleware interaction, and params reset
// =============================================================================

namespace RouteTests {

// ---------------------------------------------------------------------------
// Convenience alias: trie keyed on simple int handlers
// ---------------------------------------------------------------------------
using IntTrie = RouteTrie<int>;

// ---------------------------------------------------------------------------
// RouteTrie Unit Tests
// ---------------------------------------------------------------------------

// Test 1: static route matches exactly
void TestTrieExactMatch() {
    try {
        IntTrie trie;
        trie.Insert("/health", 42);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/health", params);

        bool pass = (result.handler != nullptr) &&
                    (*result.handler == 42) &&
                    params.empty();
        TestFramework::RecordTest(
            "RouteTrie: exact static match /health",
            pass, pass ? "" : "handler not found or wrong value",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: exact static match /health",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 2: single :id parameter extraction
void TestTrieParameterMatch() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id", 1);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/users/42", params);

        bool pass = (result.handler != nullptr) &&
                    (params.count("id") == 1) &&
                    (params.at("id") == "42");
        TestFramework::RecordTest(
            "RouteTrie: parameter :id extraction",
            pass, pass ? "" : "handler null or params wrong",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: parameter :id extraction",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 3: two parameters in one route
void TestTrieMultipleParameters() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id/orders/:oid", 2);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/users/99/orders/7", params);

        bool pass = (result.handler != nullptr) &&
                    (params.count("id") == 1) && (params.at("id") == "99") &&
                    (params.count("oid") == 1) && (params.at("oid") == "7");
        TestFramework::RecordTest(
            "RouteTrie: multiple parameters :id and :oid",
            pass, pass ? "" : "params mismatch",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: multiple parameters :id and :oid",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 4: /users/:id must NOT match /users/ (empty segment)
void TestTrieParameterNoMatch() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id", 1);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/users/", params);

        // /users/ has an empty segment after the slash — params require non-empty
        bool pass = (result.handler == nullptr);
        TestFramework::RecordTest(
            "RouteTrie: param does not match empty segment /users/",
            pass, pass ? "" : "handler should be null for empty segment",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: param does not match empty segment /users/",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 5: constrained param (\d+) matches digits
void TestTrieConstrainedParameter() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id(\\d+)", 5);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/users/42", params);

        bool pass = (result.handler != nullptr) &&
                    (params.count("id") == 1) && (params.at("id") == "42");
        TestFramework::RecordTest(
            "RouteTrie: constrained param :id(\\d+) matches digits",
            pass, pass ? "" : "constrained param did not match digits",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: constrained param :id(\\d+) matches digits",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 6: constrained param (\d+) rejects alphabetic value
void TestTrieConstrainedParameterFail() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id(\\d+)", 5);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/users/abc", params);

        bool pass = (result.handler == nullptr);
        TestFramework::RecordTest(
            "RouteTrie: constrained param :id(\\d+) rejects alpha",
            pass, pass ? "" : "should not match alphabetic segment",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: constrained param :id(\\d+) rejects alpha",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 7: catch-all *filepath captures tail without leading slash
void TestTrieCatchAll() {
    try {
        IntTrie trie;
        trie.Insert("/static/*filepath", 7);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/static/css/a.css", params);

        // Per trie convention: captured tail does NOT include the leading '/'
        bool pass = (result.handler != nullptr) &&
                    (params.count("filepath") == 1) &&
                    (params.at("filepath") == "css/a.css");
        TestFramework::RecordTest(
            "RouteTrie: catch-all *filepath captures tail without leading /",
            pass, pass ? "" :
                "handler null or filepath='" + params["filepath"] + "' (expected 'css/a.css')",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: catch-all *filepath captures tail without leading /",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 8: catch-all matches path with empty tail (/static/)
void TestTrieCatchAllEmpty() {
    try {
        IntTrie trie;
        trie.Insert("/static/*filepath", 7);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/static/", params);

        // After consuming "/static/" the remaining path is empty string
        bool pass = (result.handler != nullptr) &&
                    (params.count("filepath") == 1) &&
                    (params.at("filepath").empty());
        TestFramework::RecordTest(
            "RouteTrie: catch-all *filepath captures empty tail /static/",
            pass, pass ? "" :
                "handler null or unexpected filepath value",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: catch-all *filepath captures empty tail /static/",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 9: unnamed catch-all /api/* still matches
void TestTrieCatchAllUnnamed() {
    try {
        IntTrie trie;
        trie.Insert("/api/*", 9);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/api/v1/users", params);

        // Unnamed catch-all: no param_name, so no entry in params
        bool pass = (result.handler != nullptr) && params.empty();
        TestFramework::RecordTest(
            "RouteTrie: unnamed catch-all /api/* matches any tail",
            pass, pass ? "" : "handler null or unexpected params",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: unnamed catch-all /api/* matches any tail",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 10: static child beats param child at same level
void TestTriePriorityStaticOverParam() {
    try {
        IntTrie trie;
        trie.Insert("/users/admin", 10);
        trie.Insert("/users/:id", 11);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/users/admin", params);

        bool pass = (result.handler != nullptr) &&
                    (*result.handler == 10) &&
                    params.empty();
        TestFramework::RecordTest(
            "RouteTrie: static /users/admin beats param /users/:id",
            pass, pass ? "" :
                "wrong handler=" + (result.handler ? std::to_string(*result.handler) : "null"),
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: static /users/admin beats param /users/:id",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 11: param beats catch-all; catch-all used when param can't match deeper path
void TestTriePriorityParamOverCatchAll() {
    try {
        IntTrie trie;
        trie.Insert("/api/:version", 20);
        trie.Insert("/api/*rest", 21);

        bool pass = true;
        std::string err;

        // /api/v1 — single segment, should hit param
        {
            std::unordered_map<std::string, std::string> params;
            auto result = trie.Search("/api/v1", params);
            if (!result.handler || *result.handler != 20) {
                pass = false;
                err += "/api/v1 should hit param handler (20); ";
            }
            if (params.count("version") == 0 || params.at("version") != "v1") {
                pass = false;
                err += "version param missing or wrong; ";
            }
        }

        // /api/v1/docs — two segments, param can't match (param is leaf after one segment)
        // so catch-all takes over
        {
            std::unordered_map<std::string, std::string> params;
            auto result = trie.Search("/api/v1/docs", params);
            if (!result.handler || *result.handler != 21) {
                pass = false;
                err += "/api/v1/docs should fall back to catch-all (21); ";
            }
        }

        TestFramework::RecordTest(
            "RouteTrie: param beats catch-all; catch-all on deeper path",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: param beats catch-all; catch-all on deeper path",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 12: registering the same pattern twice throws
void TestTrieConflictDuplicateRoute() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id", 1);

        bool threw = false;
        try {
            trie.Insert("/users/:id", 2);
        } catch (const std::invalid_argument&) {
            threw = true;
        }

        TestFramework::RecordTest(
            "RouteTrie: duplicate route /users/:id throws",
            threw, threw ? "" : "expected std::invalid_argument",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: duplicate route /users/:id throws",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 13: same param position with different constraints throws
void TestTrieConflictConstraintClash() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id(\\d+)", 1);

        bool threw = false;
        try {
            trie.Insert("/users/:id([a-z]+)", 2);
        } catch (const std::invalid_argument&) {
            threw = true;
        }

        TestFramework::RecordTest(
            "RouteTrie: different constraints at same position throws",
            threw, threw ? "" : "expected std::invalid_argument for constraint clash",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: different constraints at same position throws",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 14: two catch-alls at the same level throw
void TestTrieConflictDuplicateCatchAll() {
    try {
        IntTrie trie;
        trie.Insert("/static/*filepath", 1);

        bool threw = false;
        try {
            trie.Insert("/static/*rest", 2);
        } catch (const std::invalid_argument&) {
            threw = true;
        }

        TestFramework::RecordTest(
            "RouteTrie: duplicate catch-all at same level throws",
            threw, threw ? "" : "expected std::invalid_argument for duplicate catch-all",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: duplicate catch-all at same level throws",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 15: different param names at same position — each route gets its own names
void TestTrieParamNameSharesNode() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id", 1);
        trie.Insert("/users/:user_id/orders", 2);

        bool pass = true;
        std::string err;

        // /users/42 should match first route with param key "id"
        {
            std::unordered_map<std::string, std::string> params;
            auto result = trie.Search("/users/42", params);
            if (!result.handler || *result.handler != 1) {
                pass = false; err += "/users/42 handler wrong; ";
            }
            if (params.count("id") == 0 || params["id"] != "42") {
                pass = false; err += "param key 'id' not found or wrong value; ";
            }
        }

        // /users/42/orders should match second route with param key "user_id"
        {
            std::unordered_map<std::string, std::string> params;
            auto result = trie.Search("/users/42/orders", params);
            if (!result.handler || *result.handler != 2) {
                pass = false; err += "/users/42/orders handler wrong; ";
            }
            if (params.count("user_id") == 0 || params["user_id"] != "42") {
                pass = false; err += "param key 'user_id' not found or wrong value; ";
            }
        }

        TestFramework::RecordTest(
            "RouteTrie: different param names — each route uses its own names",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: different param names — each route uses its own names",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 16: non-origin-form patterns (CONNECT authority, OPTIONS *) work as exact match
void TestTrieNonOriginForm() {
    try {
        IntTrie trie;
        trie.Insert("example.com:443", 1);  // CONNECT authority-form
        trie.Insert("*", 2);                 // OPTIONS asterisk-form

        std::unordered_map<std::string, std::string> params;
        auto r1 = trie.Search("example.com:443", params);
        auto r2 = trie.Search("*", params);
        auto r3 = trie.Search("other.com:443", params);

        bool pass = (r1.handler && *r1.handler == 1) &&
                    (r2.handler && *r2.handler == 2) &&
                    (r3.handler == nullptr);
        std::string err;
        if (!r1.handler) err = "CONNECT authority-form not matched";
        else if (!r2.handler) err = "OPTIONS asterisk-form not matched";
        else if (r3.handler) err = "unregistered authority should not match";

        // Empty pattern still throws
        bool empty_threw = false;
        try { trie.Insert("", 3); } catch (const std::invalid_argument&) { empty_threw = true; }
        if (!empty_threw) { pass = false; err += "empty pattern should throw; "; }

        TestFramework::RecordTest(
            "RouteTrie: non-origin-form patterns (CONNECT, OPTIONS *) as exact match",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: non-origin-form patterns (CONNECT, OPTIONS *) as exact match",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 17: empty param name /: throws
void TestTrieInvalidPatternEmptyParam() {
    try {
        IntTrie trie;
        bool threw = false;
        try {
            trie.Insert("/:", 1);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "RouteTrie: empty param name /: throws",
            threw, threw ? "" : "expected std::invalid_argument for /:  ",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: empty param name /: throws",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 18: catch-all in non-terminal position throws
void TestTrieInvalidPatternCatchAllNotLast() {
    try {
        IntTrie trie;
        bool threw = false;
        try {
            trie.Insert("/*/rest", 1);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "RouteTrie: catch-all not last throws /*/rest",
            threw, threw ? "" : "expected std::invalid_argument",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: catch-all not last throws /*/rest",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 19: invalid regex constraint throws on Insert
void TestTrieInvalidRegex() {
    try {
        IntTrie trie;
        bool threw = false;
        try {
            // "(++)" is an invalid regex (quantifier on quantifier)
            trie.Insert("/users/:id(++)", 1);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "RouteTrie: invalid regex constraint throws",
            threw, threw ? "" : "expected std::invalid_argument for bad regex",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: invalid regex constraint throws",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 20: non-matching path returns null handler
void TestTrieNoMatch404() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id", 1);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/products/99", params);

        bool pass = (result.handler == nullptr);
        TestFramework::RecordTest(
            "RouteTrie: non-matching path returns nullptr",
            pass, pass ? "" : "expected no match for /products/99",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: non-matching path returns nullptr",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 21: /users and /users/ are distinct routes
void TestTrieTrailingSlash() {
    try {
        IntTrie trie;
        trie.Insert("/users", 100);
        trie.Insert("/users/", 200);

        bool pass = true;
        std::string err;

        {
            std::unordered_map<std::string, std::string> p;
            auto r = trie.Search("/users", p);
            if (!r.handler || *r.handler != 100) {
                pass = false; err += "/users got wrong handler; ";
            }
        }
        {
            std::unordered_map<std::string, std::string> p;
            auto r = trie.Search("/users/", p);
            if (!r.handler || *r.handler != 200) {
                pass = false; err += "/users/ got wrong handler; ";
            }
        }

        TestFramework::RecordTest(
            "RouteTrie: /users and /users/ are distinct routes",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: /users and /users/ are distinct routes",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 22: root route "/" matches exactly
void TestTrieRootRoute() {
    try {
        IntTrie trie;
        trie.Insert("/", 0);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/", params);

        bool pass = (result.handler != nullptr) && (*result.handler == 0);
        TestFramework::RecordTest(
            "RouteTrie: root route / matches",
            pass, pass ? "" : "root handler not found",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: root route / matches",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 23: /health and /healthcheck coexist (split static segment)
void TestTrieSplitStaticSameSegment() {
    try {
        IntTrie trie;
        trie.Insert("/health", 30);
        trie.Insert("/healthcheck", 31);

        bool pass = true;
        std::string err;

        {
            std::unordered_map<std::string, std::string> p;
            auto r = trie.Search("/health", p);
            if (!r.handler || *r.handler != 30) {
                pass = false; err += "/health wrong handler; ";
            }
        }
        {
            std::unordered_map<std::string, std::string> p;
            auto r = trie.Search("/healthcheck", p);
            if (!r.handler || *r.handler != 31) {
                pass = false; err += "/healthcheck wrong handler; ";
            }
        }
        // /healthc should not match either
        {
            std::unordered_map<std::string, std::string> p;
            auto r = trie.Search("/healthc", p);
            if (r.handler) {
                pass = false; err += "/healthc should not match; ";
            }
        }

        TestFramework::RecordTest(
            "RouteTrie: /health and /healthcheck coexist after split",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: /health and /healthcheck coexist after split",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 24: percent-encoded path is matched as-is (no decoding by trie)
void TestTrieRawPercentEncoded() {
    try {
        IntTrie trie;
        trie.Insert("/foo%20bar", 24);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/foo%20bar", params);

        bool pass = (result.handler != nullptr) && (*result.handler == 24);
        TestFramework::RecordTest(
            "RouteTrie: percent-encoded path /foo%20bar matched as-is",
            pass, pass ? "" : "handler not found for percent-encoded path",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RouteTrie: percent-encoded path /foo%20bar matched as-is",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// ---------------------------------------------------------------------------
// HttpRouter Integration Tests
// ---------------------------------------------------------------------------

// Test 25: router dispatches param route and handler receives extracted params
void TestRouterPatternParam() {
    try {
        HttpRouter router;
        std::string captured_id;

        router.Get("/users/:id", [&](const HttpRequest& req, HttpResponse& res) {
            captured_id = req.params.count("id") ? req.params.at("id") : "";
            res.Status(200).Text("ok");
        });

        HttpRequest req;
        req.method = "GET";
        req.path = "/users/42";
        HttpResponse res;

        bool found = router.Dispatch(req, res);
        bool pass = found &&
                    (res.GetStatusCode() == 200) &&
                    (captured_id == "42");
        TestFramework::RecordTest(
            "HttpRouter: pattern param /users/:id dispatch",
            pass, pass ? "" : "handler not called or param wrong (id='" + captured_id + "')",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: pattern param /users/:id dispatch",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 26: two path parameters both extracted
void TestRouterPatternMultiParam() {
    try {
        HttpRouter router;
        std::string got_id, got_oid;

        router.Get("/users/:id/orders/:oid", [&](const HttpRequest& req, HttpResponse& res) {
            got_id  = req.params.count("id")  ? req.params.at("id")  : "";
            got_oid = req.params.count("oid") ? req.params.at("oid") : "";
            res.Status(200).Text("ok");
        });

        HttpRequest req;
        req.method = "GET";
        req.path = "/users/5/orders/99";
        HttpResponse res;

        bool found = router.Dispatch(req, res);
        bool pass = found && (got_id == "5") && (got_oid == "99");
        TestFramework::RecordTest(
            "HttpRouter: two params /users/:id/orders/:oid",
            pass, pass ? "" : "id='" + got_id + "' oid='" + got_oid + "'",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: two params /users/:id/orders/:oid",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 27: catch-all route captures tail
void TestRouterPatternCatchAll() {
    try {
        HttpRouter router;
        std::string captured_filepath;

        router.Get("/static/*filepath", [&](const HttpRequest& req, HttpResponse& res) {
            captured_filepath = req.params.count("filepath") ?
                req.params.at("filepath") : "";
            res.Status(200).Text("ok");
        });

        HttpRequest req;
        req.method = "GET";
        req.path = "/static/css/main.css";
        HttpResponse res;

        bool found = router.Dispatch(req, res);
        bool pass = found && (captured_filepath == "css/main.css");
        TestFramework::RecordTest(
            "HttpRouter: catch-all /static/*filepath captures tail",
            pass, pass ? "" :
                "filepath='" + captured_filepath + "' (expected 'css/main.css')",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: catch-all /static/*filepath captures tail",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 28: constrained param accepts digit, rejects alpha
void TestRouterPatternConstraint() {
    try {
        HttpRouter router;
        bool digit_handler_called = false;

        router.Get("/users/:id(\\d+)", [&](const HttpRequest& req, HttpResponse& res) {
            digit_handler_called = true;
            res.Status(200).Text("digit");
        });

        bool pass = true;
        std::string err;

        // Should match digit segment
        {
            HttpRequest req; req.method = "GET"; req.path = "/users/123";
            HttpResponse res;
            bool found = router.Dispatch(req, res);
            if (!found || !digit_handler_called) {
                pass = false; err += "digit segment not matched; ";
            }
        }

        // Should NOT match alpha segment (returns false — 404)
        {
            digit_handler_called = false;
            HttpRequest req; req.method = "GET"; req.path = "/users/abc";
            HttpResponse res;
            bool found = router.Dispatch(req, res);
            if (found && digit_handler_called) {
                pass = false; err += "alpha segment should not match digit constraint; ";
            }
        }

        TestFramework::RecordTest(
            "HttpRouter: constrained param :id(\\d+) accepts digits, rejects alpha",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: constrained param :id(\\d+) accepts digits, rejects alpha",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 29: static /users/admin beats param /users/:id in router
void TestRouterPatternPriorityStaticParam() {
    try {
        HttpRouter router;
        int which = 0;

        router.Get("/users/admin", [&](const HttpRequest&, HttpResponse& res) {
            which = 1;
            res.Status(200).Text("admin");
        });
        router.Get("/users/:id", [&](const HttpRequest&, HttpResponse& res) {
            which = 2;
            res.Status(200).Text("user");
        });

        HttpRequest req; req.method = "GET"; req.path = "/users/admin";
        HttpResponse res;
        router.Dispatch(req, res);

        bool pass = (which == 1);
        TestFramework::RecordTest(
            "HttpRouter: static /users/admin beats param /users/:id",
            pass, pass ? "" : "wrong handler called (which=" + std::to_string(which) + ")",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: static /users/admin beats param /users/:id",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 30: param beats catch-all for single segment; catch-all wins on deeper path
void TestRouterPatternPriorityParamCatchAll() {
    try {
        HttpRouter router;
        int which = 0;

        router.Get("/api/:version", [&](const HttpRequest&, HttpResponse& res) {
            which = 1;
            res.Status(200).Text("version");
        });
        router.Get("/api/*rest", [&](const HttpRequest&, HttpResponse& res) {
            which = 2;
            res.Status(200).Text("rest");
        });

        bool pass = true;
        std::string err;

        // Single segment — param should win
        {
            which = 0;
            HttpRequest req; req.method = "GET"; req.path = "/api/v2";
            HttpResponse res;
            router.Dispatch(req, res);
            if (which != 1) { pass = false; err += "/api/v2 should hit param (1), got " + std::to_string(which) + "; "; }
        }

        // Deeper path — catch-all should win
        {
            which = 0;
            HttpRequest req; req.method = "GET"; req.path = "/api/v2/users";
            HttpResponse res;
            router.Dispatch(req, res);
            if (which != 2) { pass = false; err += "/api/v2/users should hit catch-all (2), got " + std::to_string(which) + "; "; }
        }

        TestFramework::RecordTest(
            "HttpRouter: param beats catch-all; catch-all on deeper path",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: param beats catch-all; catch-all on deeper path",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 31: pattern route with wrong method returns 405 with Allow header
void TestRouterPattern405() {
    try {
        HttpRouter router;
        router.Get("/users/:id", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        HttpRequest req;
        req.method = "DELETE";
        req.path = "/users/42";
        HttpResponse res;

        bool found = router.Dispatch(req, res);

        // Find Allow header in response headers (vector of pairs, case-sensitive key)
        std::string allow_value;
        for (const auto& hdr : res.GetHeaders()) {
            if (hdr.first == "Allow") {
                allow_value = hdr.second;
                break;
            }
        }

        bool pass = found &&
                    (res.GetStatusCode() == 405) &&
                    (!allow_value.empty());
        TestFramework::RecordTest(
            "HttpRouter: pattern route wrong method returns 405 + Allow header",
            pass, pass ? "" :
                "found=" + std::string(found ? "true" : "false") +
                " status=" + std::to_string(res.GetStatusCode()) +
                " Allow='" + allow_value + "'",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: pattern route wrong method returns 405 + Allow header",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 32: HEAD on pattern route falls back to GET handler
void TestRouterPatternHEADFallback() {
    try {
        HttpRouter router;
        bool get_handler_called = false;

        router.Get("/users/:id", [&](const HttpRequest& req, HttpResponse& res) {
            // HEAD fallback clones request with method="GET"
            get_handler_called = (req.method == "GET");
            res.Status(200).Text("body");
        });

        HttpRequest req;
        req.method = "HEAD";
        req.path = "/users/7";
        HttpResponse res;

        bool found = router.Dispatch(req, res);

        bool pass = found && get_handler_called && (res.GetStatusCode() == 200);
        TestFramework::RecordTest(
            "HttpRouter: HEAD fallback to GET on pattern route",
            pass, pass ? "" : "HEAD fallback failed",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: HEAD fallback to GET on pattern route",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 33: middleware runs before pattern route handler
void TestRouterPatternMiddleware() {
    try {
        HttpRouter router;
        bool mw_ran = false;
        bool handler_ran = false;

        router.Use([&](const HttpRequest&, HttpResponse&) {
            mw_ran = true;
            return true;
        });

        router.Get("/users/:id", [&](const HttpRequest&, HttpResponse& res) {
            handler_ran = true;
            res.Status(200).Text("ok");
        });

        HttpRequest req;
        req.method = "GET";
        req.path = "/users/1";
        HttpResponse res;

        router.Dispatch(req, res);

        bool pass = mw_ran && handler_ran;
        TestFramework::RecordTest(
            "HttpRouter: middleware runs before pattern route handler",
            pass, pass ? "" : "mw_ran=" + std::string(mw_ran ? "true" : "false") +
                " handler_ran=" + std::string(handler_ran ? "true" : "false"),
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: middleware runs before pattern route handler",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 34: exact (non-pattern) routes still work alongside pattern routes
void TestRouterPatternExactStillWorks() {
    try {
        HttpRouter router;
        bool exact_called = false;

        router.Get("/health", [&](const HttpRequest&, HttpResponse& res) {
            exact_called = true;
            res.Status(200).Text("ok");
        });
        router.Get("/users/:id", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("user");
        });

        HttpRequest req;
        req.method = "GET";
        req.path = "/health";
        HttpResponse res;

        bool found = router.Dispatch(req, res);
        bool pass = found && exact_called && (res.GetStatusCode() == 200);
        TestFramework::RecordTest(
            "HttpRouter: exact routes work alongside pattern routes",
            pass, pass ? "" : "exact route not matched",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: exact routes work alongside pattern routes",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Test 35: params are cleared between dispatches (HttpRequest::Reset)
void TestRouterPatternParamsCleared() {
    try {
        HttpRouter router;

        router.Get("/users/:id", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Text(req.params.count("id") ? req.params.at("id") : "");
        });

        bool pass = true;
        std::string err;

        for (int i = 1; i <= 3; i++) {
            HttpRequest req;
            req.method = "GET";
            req.path = "/users/" + std::to_string(i);
            // Simulate a stale params map from a previous request
            req.params["id"] = "stale";
            req.params["extra"] = "garbage";
            HttpResponse res;

            router.Dispatch(req, res);

            // After dispatch, params should hold only this request's params
            if (req.params.count("id") == 0 ||
                req.params.at("id") != std::to_string(i)) {
                pass = false;
                err += "req " + std::to_string(i) + ": id='" +
                       (req.params.count("id") ? req.params.at("id") : "(missing)") + "'; ";
            }
            if (req.params.count("extra") != 0) {
                pass = false; err += "stale key 'extra' still present on req " + std::to_string(i) + "; ";
            }
        }

        TestFramework::RecordTest(
            "HttpRouter: params cleared/replaced between dispatches",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpRouter: params cleared/replaced between dispatches",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// ---------------------------------------------------------------------------
// Additional edge case tests
// ---------------------------------------------------------------------------

// Root catch-all: /*rest should match "/" with rest=""
void TestTrieRootCatchAll() {
    try {
        IntTrie trie;
        trie.Insert("/*rest", 99);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/", params);
        bool pass_root = (result.handler != nullptr) && (*result.handler == 99) &&
                         (params["rest"] == "");

        params.clear();
        auto result2 = trie.Search("/anything/here", params);
        bool pass_deep = (result2.handler != nullptr) && (*result2.handler == 99) &&
                         (params["rest"] == "anything/here");

        bool pass = pass_root && pass_deep;
        std::string err;
        if (!pass_root) err = "/*rest did not match /";
        else if (!pass_deep) err = "/*rest did not match /anything/here";
        TestFramework::RecordTest(
            "RouteTrie: root catch-all /*rest matches / and /anything/here",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: root catch-all /*rest matches / and /anything/here",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Catch-all without trailing slash: /static/*filepath should NOT match /static
void TestTrieCatchAllNoTrailingSlash() {
    try {
        IntTrie trie;
        trie.Insert("/static/*filepath", 1);

        std::unordered_map<std::string, std::string> params;
        auto result = trie.Search("/static", params);
        bool pass = (result.handler == nullptr);
        TestFramework::RecordTest(
            "RouteTrie: catch-all /static/*filepath does not match /static (no slash)",
            pass, pass ? "" : "/static matched when it should not",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: catch-all /static/*filepath does not match /static (no slash)",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// WebSocket pattern route: params extracted and available via GetWebSocketHandler
void TestRouterWsPatternRoute() {
    try {
        HttpRouter router;
        router.WebSocket("/ws/:room", [](WebSocketConnection& ws) {
            // Handler body — in real usage, ws.GetParams()["room"] is available
        });

        // Test HasWebSocketRoute with pattern
        bool has_route = router.HasWebSocketRoute("/ws/lobby");
        bool no_route = !router.HasWebSocketRoute("/ws/");  // empty param — no match

        // Test GetWebSocketHandler with param extraction
        HttpRequest req;
        req.path = "/ws/lobby";
        auto ws_handler = router.GetWebSocketHandler(req);
        bool got_handler = (ws_handler != nullptr);
        bool params_set = (req.params.count("room") > 0) && (req.params["room"] == "lobby");

        bool pass = has_route && no_route && got_handler && params_set;
        std::string err;
        if (!has_route) err = "HasWebSocketRoute failed for /ws/lobby";
        else if (!no_route) err = "HasWebSocketRoute matched /ws/ (empty param)";
        else if (!got_handler) err = "GetWebSocketHandler returned null";
        else if (!params_set) err = "params not populated on request";
        TestFramework::RecordTest(
            "HttpRouter: WebSocket pattern route /ws/:room",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "HttpRouter: WebSocket pattern route /ws/:room",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Regression: /foobar and /foo/bar must not collide (slash boundary in split)
void TestTrieSlashBoundarySplit() {
    try {
        IntTrie trie;
        trie.Insert("/foobar", 1);
        trie.Insert("/foo/bar", 2);  // must not throw

        std::unordered_map<std::string, std::string> params;
        auto r1 = trie.Search("/foobar", params);
        auto r2 = trie.Search("/foo/bar", params);
        auto r3 = trie.Search("/foo", params);
        auto r4 = trie.Search("/foob", params);

        bool pass = (r1.handler && *r1.handler == 1) &&
                    (r2.handler && *r2.handler == 2) &&
                    (r3.handler == nullptr) &&
                    (r4.handler == nullptr);
        std::string err;
        if (!r1.handler || *r1.handler != 1) err = "/foobar did not match handler 1";
        else if (!r2.handler || *r2.handler != 2) err = "/foo/bar did not match handler 2";
        else if (r3.handler) err = "/foo should not match";
        else if (r4.handler) err = "/foob should not match";
        TestFramework::RecordTest(
            "RouteTrie: /foobar and /foo/bar coexist (slash boundary in split)",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: /foobar and /foo/bar coexist (slash boundary in split)",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Regression: /baz must NOT match route /b/a/z (collapsed path)
void TestTrieNoCollapsedPathMatch() {
    try {
        IntTrie trie;
        trie.Insert("/b/a/z", 1);

        std::unordered_map<std::string, std::string> params;
        auto r1 = trie.Search("/b/a/z", params);
        auto r2 = trie.Search("/baz", params);

        bool pass = (r1.handler && *r1.handler == 1) &&
                    (r2.handler == nullptr);
        std::string err;
        if (!r1.handler) err = "/b/a/z did not match";
        else if (r2.handler) err = "/baz incorrectly matched /b/a/z route";
        TestFramework::RecordTest(
            "RouteTrie: /baz does NOT match route /b/a/z (no collapsed path)",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: /baz does NOT match route /b/a/z (no collapsed path)",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Regression: /users/:id/ must NOT match /users/42 (param trailing-slash)
void TestTrieParamTrailingSlashDistinct() {
    try {
        IntTrie trie;
        trie.Insert("/users/:id/", 1);
        trie.Insert("/users/:id", 2);

        std::unordered_map<std::string, std::string> params;
        auto r1 = trie.Search("/users/42/", params);
        bool r1_ok = (r1.handler && *r1.handler == 1 && params["id"] == "42");

        params.clear();
        auto r2 = trie.Search("/users/42", params);
        bool r2_ok = (r2.handler && *r2.handler == 2 && params["id"] == "42");

        bool pass = r1_ok && r2_ok;
        std::string err;
        if (!r1_ok) err = "/users/42/ did not match trailing-slash route";
        else if (!r2_ok) err = "/users/42 did not match non-trailing-slash route";
        TestFramework::RecordTest(
            "RouteTrie: /users/:id/ and /users/:id are distinct routes",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: /users/:id/ and /users/:id are distinct routes",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Regression: regex character class with parentheses
void TestTrieRegexCharacterClass() {
    try {
        IntTrie trie;
        // [0-9] is a character class — parens inside [] should not confuse parser
        trie.Insert("/items/:id([0-9]+)", 1);

        std::unordered_map<std::string, std::string> params;
        auto r1 = trie.Search("/items/42", params);
        bool pass = (r1.handler && *r1.handler == 1);
        TestFramework::RecordTest(
            "RouteTrie: regex with character class [0-9] parses correctly",
            pass, pass ? "" : "constraint with [] failed",
            TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: regex with character class [0-9] parses correctly",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Regression: stale params cleared on dispatch miss
void TestRouterParamsClearedOnMiss() {
    try {
        HttpRouter router;
        router.Get("/users/:id", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200);
        });

        HttpRequest req;
        HttpResponse res;

        // First dispatch — match
        req.method = "GET"; req.path = "/users/42";
        router.Dispatch(req, res);
        bool first_ok = (req.params["id"] == "42");

        // Second dispatch — miss (404)
        req.method = "GET"; req.path = "/missing";
        router.Dispatch(req, res);
        bool second_ok = req.params.empty();

        bool pass = first_ok && second_ok;
        std::string err;
        if (!first_ok) err = "first dispatch did not set params";
        else if (!second_ok) err = "params not cleared on 404 miss";
        TestFramework::RecordTest(
            "HttpRouter: params cleared on dispatch miss (no stale state)",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "HttpRouter: params cleared on dispatch miss (no stale state)",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Regression: mid-segment : and * are static text, not dynamic tokens
void TestTrieMidSegmentColonStar() {
    try {
        IntTrie trie;
        trie.Insert("/v:version/docs", 1);   // "v:version" is static text
        trie.Insert("/file*name", 2);          // "file*name" is static text

        std::unordered_map<std::string, std::string> params;
        auto r1 = trie.Search("/v:version/docs", params);
        auto r2 = trie.Search("/file*name", params);
        // These should NOT match as params
        auto r3 = trie.Search("/v1/docs", params);

        bool pass = (r1.handler && *r1.handler == 1) &&
                    (r2.handler && *r2.handler == 2) &&
                    (r3.handler == nullptr);
        std::string err;
        if (!r1.handler) err = "/v:version/docs did not match as static";
        else if (!r2.handler) err = "/file*name did not match as static";
        else if (r3.handler) err = "/v1/docs should not match (: is mid-segment static)";
        TestFramework::RecordTest(
            "RouteTrie: mid-segment : and * treated as static text",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteTrie: mid-segment : and * treated as static text",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// ---------------------------------------------------------------------------
// Proxy-marker regression tests (per-registration scoping)
//
// These tests exercise HttpRouter's proxy precedence markers directly
// to guard against cross-route contamination. The markers track:
//
//   - MarkProxyDefaultHead(pattern, paired_with_get) — installed when a
//     proxy's HEAD comes from default_methods AND whether the SAME
//     registration also installed GET. Used so HEAD follows the same
//     registration's GET owner, not some other proxy that happens to
//     own GET on the same pattern string.
//
//   - MarkProxyCompanion(method, pattern) — installed for a proxy's
//     derived bare-prefix companion, keyed by (method, pattern) so a
//     later unrelated async registration on the same pattern with a
//     different method does NOT inherit the yield-to-sync behavior.
// ---------------------------------------------------------------------------

// P1 regression: proxy A owns async GET on a pattern, then proxy B
// installs a default-HEAD on the same pattern but its GET was filtered
// out by the async-conflict check. HEAD requests must NOT stick on
// proxy B — they must drop B's HEAD and fall through to the async
// HEAD→GET fallback that routes through A's GET.
void TestRouterProxyHeadFollowsRegistrationOwner() {
    std::cout << "\n[TEST] Router: proxy default HEAD follows same-registration GET owner..."
              << std::endl;
    try {
        HttpRouter router;

        // Proxy A: owns GET on /api/*rest. Simulate by registering the
        // async GET route directly. Mark nothing for HEAD — A has no HEAD.
        auto proxy_a_hit = std::make_shared<bool>(false);
        router.RouteAsync("GET", "/api/*rest",
            [proxy_a_hit](const HttpRequest&,
                          HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                          HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                          HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                          HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *proxy_a_hit = true;
            });

        // Proxy B: registers HEAD on the same pattern as a DEFAULT method,
        // but its GET was filtered out (proxy A already owns it). In the
        // real proxy registration loop, the per-method conflict check
        // would skip B's GET and keep B's HEAD, then mark
        // proxy_default_head_patterns_[/api/*rest] = false (paired=false)
        // because proxy_has_get (for B) is false post-filter.
        auto proxy_b_head_hit = std::make_shared<bool>(false);
        router.RouteAsync("HEAD", "/api/*rest",
            [proxy_b_head_hit](const HttpRequest&,
                               HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                               HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                               HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                               HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *proxy_b_head_hit = true;
            });
        // paired_with_get = false — B did NOT register GET on this pattern.
        router.MarkProxyDefaultHead("/api/*rest", /*paired_with_get=*/false);

        HttpRequest req;
        req.method = "HEAD";
        req.path = "/api/foo";
        bool head_fallback = false;
        auto handler = router.GetAsyncHandler(req, &head_fallback);

        // Expected: handler is A's GET handler (via HEAD→GET fallback),
        // NOT B's HEAD handler.
        bool got_handler = (handler != nullptr);
        bool fallback_flag = head_fallback;
        if (got_handler) {
            handler(req,
                    [](int, const std::vector<std::pair<std::string,std::string>>&) {},
                    [](const std::string&, const std::string&, const std::string&,
                       const std::string&, const HttpResponse&) -> int32_t { return -1; },
                    HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender{},
                    [](HttpResponse) {});
        }

        bool pass = got_handler && fallback_flag &&
                    *proxy_a_hit && !*proxy_b_head_hit;
        std::string err;
        if (!got_handler) err = "HEAD returned no handler";
        else if (!fallback_flag) err = "HEAD→GET fallback flag was false";
        else if (!*proxy_a_hit) err = "proxy A's GET was not invoked";
        else if (*proxy_b_head_hit) err = "proxy B's default HEAD hijacked the request";
        TestFramework::RecordTest(
            "Router: proxy default HEAD follows same-registration GET owner",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Router: proxy default HEAD follows same-registration GET owner",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// P1 companion case: same registration DID own both GET and HEAD on
// the same pattern — HEAD must stay on the proxy.
void TestRouterProxyHeadKeptWhenSameRegistrationPair() {
    std::cout << "\n[TEST] Router: proxy default HEAD stays when same registration owns GET..."
              << std::endl;
    try {
        HttpRouter router;

        // Single proxy registers both GET and HEAD on /items/*rest.
        auto get_hit = std::make_shared<bool>(false);
        auto head_hit = std::make_shared<bool>(false);
        router.RouteAsync("GET", "/items/*rest",
            [get_hit](const HttpRequest&,
                      HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                      HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                      HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                      HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *get_hit = true;
            });
        router.RouteAsync("HEAD", "/items/*rest",
            [head_hit](const HttpRequest&,
                       HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                       HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                       HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                       HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *head_hit = true;
            });
        // paired_with_get = true — same registration owns both.
        router.MarkProxyDefaultHead("/items/*rest", /*paired_with_get=*/true);

        HttpRequest req;
        req.method = "HEAD";
        req.path = "/items/foo";
        bool head_fallback = false;
        auto handler = router.GetAsyncHandler(req, &head_fallback);

        if (handler) handler(req,
                             [](int, const std::vector<std::pair<std::string,std::string>>&) {},
                             [](const std::string&, const std::string&, const std::string&,
                                const std::string&, const HttpResponse&) -> int32_t { return -1; },
                             HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender{},
                             [](HttpResponse) {});

        // HEAD stays on the proxy's HEAD handler (not via HEAD→GET fallback).
        bool pass = (handler != nullptr) && !head_fallback &&
                    *head_hit && !*get_hit;
        std::string err;
        if (!handler) err = "HEAD returned no handler";
        else if (head_fallback) err = "unexpected HEAD→GET fallback";
        else if (!*head_hit) err = "proxy's HEAD handler was not invoked";
        else if (*get_hit) err = "GET handler was unexpectedly invoked";
        TestFramework::RecordTest(
            "Router: proxy default HEAD stays when same registration owns GET",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Router: proxy default HEAD stays when same registration owns GET",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// P2 regression: proxy companion marked for GET on /api. Later, an
// unrelated async POST /api is registered. A POST request to /api
// must NOT yield to a matching sync POST /api — it was never a
// companion for the POST method.
void TestRouterProxyCompanionScopedByMethod() {
    std::cout << "\n[TEST] Router: proxy companion yield is scoped to marked methods..."
              << std::endl;
    try {
        HttpRouter router;

        // Sync POST /api — user's first-class handler.
        auto sync_post_hit = std::make_shared<bool>(false);
        router.Route("POST", "/api",
            [sync_post_hit](const HttpRequest&, HttpResponse& resp) {
                *sync_post_hit = true;
                resp.Status(200).Text("sync-post");
            });

        // Proxy-like GET companion registration: /api is the derived
        // bare-prefix companion for a /api/*rest proxy with methods=[GET].
        auto async_get_hit = std::make_shared<bool>(false);
        router.RouteAsync("GET", "/api",
            [async_get_hit](const HttpRequest&,
                            HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                            HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                            HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *async_get_hit = true;
            });
        // Mark ONLY (GET, /api) as a companion — this is what the per-method
        // proxy registration loop produces.
        router.MarkProxyCompanion("GET", "/api");

        // Later: an UNRELATED first-class async POST /api. NOT a companion.
        auto async_post_hit = std::make_shared<bool>(false);
        router.RouteAsync("POST", "/api",
            [async_post_hit](const HttpRequest&,
                             HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                             HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                             HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                             HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *async_post_hit = true;
            });

        // POST /api → should reach the async POST handler and NOT yield
        // to the sync POST handler (the async registration is first-class,
        // not a companion).
        HttpRequest req;
        req.method = "POST";
        req.path = "/api";
        auto handler = router.GetAsyncHandler(req, nullptr);
        if (handler) handler(req,
                             [](int, const std::vector<std::pair<std::string,std::string>>&) {},
                             [](const std::string&, const std::string&, const std::string&,
                                const std::string&, const HttpResponse&) -> int32_t { return -1; },
                             HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender{},
                             [](HttpResponse) {});

        bool pass = (handler != nullptr) &&
                    *async_post_hit && !*sync_post_hit;
        std::string err;
        if (!handler) err = "POST returned no async handler (unexpected yield)";
        else if (!*async_post_hit) err = "async POST handler not invoked";
        else if (*sync_post_hit) err = "sync POST handler was incorrectly invoked via yield";
        TestFramework::RecordTest(
            "Router: proxy companion yield is scoped to marked methods",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Router: proxy companion yield is scoped to marked methods",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// P2 companion case: GET /api is a companion and sync GET /api exists
// → companion must still yield for GET requests (this is the existing
// behavior the earlier fix added; keep it working after the method-
// scoping refactor).
void TestRouterProxyCompanionYieldsForMarkedMethod() {
    std::cout << "\n[TEST] Router: proxy companion still yields for the marked method..."
              << std::endl;
    try {
        HttpRouter router;

        auto sync_get_hit = std::make_shared<bool>(false);
        router.Route("GET", "/api",
            [sync_get_hit](const HttpRequest&, HttpResponse& resp) {
                *sync_get_hit = true;
                resp.Status(200).Text("sync-get");
            });

        auto async_get_hit = std::make_shared<bool>(false);
        router.RouteAsync("GET", "/api",
            [async_get_hit](const HttpRequest&,
                            HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                            HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                            HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *async_get_hit = true;
            });
        router.MarkProxyCompanion("GET", "/api");

        HttpRequest req;
        req.method = "GET";
        req.path = "/api";
        auto handler = router.GetAsyncHandler(req, nullptr);

        // Expected: GetAsyncHandler yields (returns null) and sync GET
        // serves via Dispatch. Verify the yield; the sync invocation is
        // verified via Dispatch below.
        bool yielded = (handler == nullptr);

        HttpResponse resp;
        bool dispatched = router.Dispatch(req, resp);
        bool pass = yielded && dispatched && *sync_get_hit && !*async_get_hit;
        std::string err;
        if (!yielded) err = "async companion did not yield to sync GET";
        else if (!dispatched) err = "sync Dispatch did not handle the request";
        else if (!*sync_get_hit) err = "sync GET handler was not invoked";
        else if (*async_get_hit) err = "async GET companion was unexpectedly invoked";
        TestFramework::RecordTest(
            "Router: proxy companion still yields for the marked method",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Router: proxy companion still yields for the marked method",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// Per-pattern paired_with_get. When a proxy
// registers both a companion pattern and a catch-all pattern, the
// per-(method,pattern) async-conflict filter may drop GET on ONE
// pattern while keeping it on the OTHER. MarkProxyDefaultHead must
// be called with a PER-PATTERN paired flag — marking both patterns
// as paired=true just because the proxy owns GET on SOME pattern
// overall would incorrectly keep HEAD on the proxy for the pattern
// where GET was actually filtered out.
//
// Scenario (mirrors the production bug):
//   - Existing async GET /api (user's own handler — not a proxy)
//   - Proxy on /api/*rest with default methods. Its companion /api
//     and catch-all /api/*rest both survive except for GET /api,
//     which collides with the user's async GET.
//   - MarkProxyDefaultHead should be called with paired=FALSE for
//     /api (proxy's GET skipped) and paired=TRUE for /api/*rest.
//   - HEAD /api must fall through to HEAD→GET fallback and reach
//     the user's async GET /api.
//   - HEAD /api/foo must stay on the proxy's HEAD /api/*rest
//     (same-registration pair, paired=true).
void TestRouterProxyDefaultHeadPairingPerPattern() {
    std::cout << "\n[TEST] Router: proxy default HEAD paired_with_get is per-pattern..."
              << std::endl;
    try {
        HttpRouter router;

        // User's first-class async GET /api (the real GET owner).
        auto user_get_hit = std::make_shared<bool>(false);
        router.RouteAsync("GET", "/api",
            [user_get_hit](const HttpRequest&,
                           HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                           HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                           HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                           HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *user_get_hit = true;
            });

        // Proxy's surviving async HEAD /api (the collision filtered
        // out proxy's GET /api, so the proxy's companion only has
        // HEAD). In the real http_server.cc loop, this is what we
        // would see after the per-method conflict filter runs.
        auto proxy_head_api_hit = std::make_shared<bool>(false);
        router.RouteAsync("HEAD", "/api",
            [proxy_head_api_hit](const HttpRequest&,
                                 HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                                 HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                                 HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                                 HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *proxy_head_api_hit = true;
            });
        // paired=false: proxy did NOT register GET /api (filtered out).
        router.MarkProxyDefaultHead("/api", /*paired_with_get=*/false);

        // Proxy's catch-all pattern — GET /api/*rest and HEAD
        // /api/*rest both survived, so pairing is TRUE here.
        auto proxy_get_catchall_hit = std::make_shared<bool>(false);
        auto proxy_head_catchall_hit = std::make_shared<bool>(false);
        router.RouteAsync("GET", "/api/*rest",
            [proxy_get_catchall_hit](const HttpRequest&,
                                      HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                                      HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                                      HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                                      HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *proxy_get_catchall_hit = true;
            });
        router.RouteAsync("HEAD", "/api/*rest",
            [proxy_head_catchall_hit](const HttpRequest&,
                                       HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                                       HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                                       HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                                       HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *proxy_head_catchall_hit = true;
            });
        router.MarkProxyDefaultHead("/api/*rest", /*paired_with_get=*/true);

        // HEAD /api must route through the user's async GET /api
        // via the HEAD→GET fallback (proxy HEAD /api dropped because
        // paired=false for that pattern).
        {
            HttpRequest req;
            req.method = "HEAD";
            req.path = "/api";
            bool head_fallback = false;
            auto handler = router.GetAsyncHandler(req, &head_fallback);
            if (handler) handler(req,
                                 [](int, const std::vector<std::pair<std::string,std::string>>&) {},
                                 [](const std::string&, const std::string&, const std::string&,
                                    const std::string&, const HttpResponse&) -> int32_t { return -1; },
                                 HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender{},
                                 [](HttpResponse) {});

            bool api_ok = (handler != nullptr) && head_fallback &&
                          *user_get_hit && !*proxy_head_api_hit;
            std::string err1;
            if (!handler) err1 = "HEAD /api returned no handler";
            else if (!head_fallback) err1 = "HEAD /api did not use HEAD→GET fallback";
            else if (!*user_get_hit) err1 = "user's async GET /api was not invoked";
            else if (*proxy_head_api_hit) err1 = "proxy HEAD /api incorrectly hijacked";
            if (!api_ok) {
                TestFramework::RecordTest(
                    "Router: proxy default HEAD paired_with_get is per-pattern",
                    false, err1, TestFramework::TestCategory::ROUTE);
                return;
            }
        }

        // HEAD /api/foo must stay on the proxy's HEAD /api/*rest
        // (paired=true, same-registration pairing honored). Proxy
        // GET /api/*rest must NOT be invoked — the catch-all's HEAD
        // handler is.
        {
            HttpRequest req;
            req.method = "HEAD";
            req.path = "/api/foo";
            bool head_fallback = false;
            auto handler = router.GetAsyncHandler(req, &head_fallback);
            if (handler) handler(req,
                                 [](int, const std::vector<std::pair<std::string,std::string>>&) {},
                                 [](const std::string&, const std::string&, const std::string&,
                                    const std::string&, const HttpResponse&) -> int32_t { return -1; },
                                 HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender{},
                                 [](HttpResponse) {});

            bool catchall_ok = (handler != nullptr) && !head_fallback &&
                               *proxy_head_catchall_hit &&
                               !*proxy_get_catchall_hit;
            std::string err2;
            if (!handler) err2 = "HEAD /api/foo returned no handler";
            else if (head_fallback) err2 = "HEAD /api/foo unexpectedly used HEAD→GET fallback";
            else if (!*proxy_head_catchall_hit) err2 = "proxy HEAD /api/*rest not invoked";
            else if (*proxy_get_catchall_hit) err2 = "proxy GET /api/*rest unexpectedly invoked";
            TestFramework::RecordTest(
                "Router: proxy default HEAD paired_with_get is per-pattern",
                catchall_ok, err2, TestFramework::TestCategory::ROUTE);
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Router: proxy default HEAD paired_with_get is per-pattern",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// P2 disjoint-regex companion case: sync /users/:id([0-9]+) +
// async companion /users/:slug([a-z]+). Alphabetic bare-prefix
// requests should still reach the async companion (no sync match).
void TestRouterProxyCompanionDisjointRegex() {
    std::cout << "\n[TEST] Router: proxy companion serves disjoint-regex paths..."
              << std::endl;
    try {
        HttpRouter router;

        // Sync numeric-only route.
        router.Route("GET", "/users/:id([0-9]+)",
            [](const HttpRequest&, HttpResponse& resp) {
                resp.Status(200).Text("sync-num");
            });

        // Async alphabetic-only companion.
        auto async_hit = std::make_shared<bool>(false);
        router.RouteAsync("GET", "/users/:slug([a-z]+)",
            [async_hit](const HttpRequest&,
                        HTTP_CALLBACKS_NAMESPACE::InterimResponseSender,
                        HTTP_CALLBACKS_NAMESPACE::ResourcePusher,
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                        HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback) {
                *async_hit = true;
            });
        router.MarkProxyCompanion("GET", "/users/:slug([a-z]+)");

        // Request /users/abc — sync regex rejects, async companion
        // should NOT yield (sync GET HasMatch returns false for /users/abc
        // because [0-9]+ doesn't match "abc").
        HttpRequest req;
        req.method = "GET";
        req.path = "/users/abc";
        auto handler = router.GetAsyncHandler(req, nullptr);
        if (handler) handler(req,
                             [](int, const std::vector<std::pair<std::string,std::string>>&) {},
                             [](const std::string&, const std::string&, const std::string&,
                                const std::string&, const HttpResponse&) -> int32_t { return -1; },
                             HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender{},
                             [](HttpResponse) {});

        bool pass = (handler != nullptr) && *async_hit;
        std::string err;
        if (!handler) err = "async companion incorrectly yielded for disjoint-regex path";
        else if (!*async_hit) err = "async companion handler was not invoked";
        TestFramework::RecordTest(
            "Router: proxy companion serves disjoint-regex paths",
            pass, err, TestFramework::TestCategory::ROUTE);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Router: proxy companion serves disjoint-regex paths",
            false, e.what(), TestFramework::TestCategory::ROUTE);
    }
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------
void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "ROUTE TRIE & HTTP ROUTER - UNIT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // RouteTrie unit tests (direct API, no server)
    TestTrieExactMatch();
    TestTrieParameterMatch();
    TestTrieMultipleParameters();
    TestTrieParameterNoMatch();
    TestTrieConstrainedParameter();
    TestTrieConstrainedParameterFail();
    TestTrieCatchAll();
    TestTrieCatchAllEmpty();
    TestTrieCatchAllUnnamed();
    TestTriePriorityStaticOverParam();
    TestTriePriorityParamOverCatchAll();
    TestTrieConflictDuplicateRoute();
    TestTrieConflictConstraintClash();
    TestTrieConflictDuplicateCatchAll();
    TestTrieParamNameSharesNode();
    TestTrieNonOriginForm();
    TestTrieInvalidPatternEmptyParam();
    TestTrieInvalidPatternCatchAllNotLast();
    TestTrieInvalidRegex();
    TestTrieNoMatch404();
    TestTrieTrailingSlash();
    TestTrieRootRoute();
    TestTrieSplitStaticSameSegment();
    TestTrieRawPercentEncoded();

    // HttpRouter integration tests
    TestRouterPatternParam();
    TestRouterPatternMultiParam();
    TestRouterPatternCatchAll();
    TestRouterPatternConstraint();
    TestRouterPatternPriorityStaticParam();
    TestRouterPatternPriorityParamCatchAll();
    TestRouterPattern405();
    TestRouterPatternHEADFallback();
    TestRouterPatternMiddleware();
    TestRouterPatternExactStillWorks();
    TestRouterPatternParamsCleared();

    // Additional edge case tests
    TestTrieRootCatchAll();
    TestTrieCatchAllNoTrailingSlash();
    TestRouterWsPatternRoute();
    TestTrieSlashBoundarySplit();
    TestTrieNoCollapsedPathMatch();
    TestTrieParamTrailingSlashDistinct();
    TestTrieRegexCharacterClass();
    TestRouterParamsClearedOnMiss();
    TestTrieMidSegmentColonStar();

    // Proxy-marker per-registration scoping
    TestRouterProxyHeadFollowsRegistrationOwner();
    TestRouterProxyHeadKeptWhenSameRegistrationPair();
    TestRouterProxyCompanionScopedByMethod();
    TestRouterProxyCompanionYieldsForMarkedMethod();
    TestRouterProxyCompanionDisjointRegex();
    TestRouterProxyDefaultHeadPairingPerPattern();
}

}  // namespace RouteTests
