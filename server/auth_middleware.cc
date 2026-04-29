#include "auth/auth_middleware.h"
#include "log/logger.h"

namespace AUTH_NAMESPACE {

HttpRouter::Middleware MakeMiddleware(AuthManager* mgr) {
    if (!mgr) {
        // No manager installed — ensure we don't install a broken
        // middleware that silently drops all traffic.
        logging::Get()->debug(
            "AuthMiddleware factory called with null AuthManager — "
            "returning pass-through");
        return [](const HttpRequest&, HttpResponse&) -> bool { return true; };
    }
    // Capture by pointer: AuthManager is owned by HttpServer and outlives
    // every registered middleware (middleware is cleared before the
    // manager is destroyed in ~HttpServer). Non-owning is correct —
    // capturing a shared_ptr here would create a cycle between the
    // manager and the router.
    return [mgr](const HttpRequest& req, HttpResponse& resp) -> bool {
        return mgr->InvokeMiddleware(req, resp);
    };
}

HttpRouter::AsyncMiddleware MakeAsyncMiddleware(AuthManager* mgr) {
    if (!mgr) {
        // No manager — every request passes through synchronously.
        return [](const HttpRequest&, HttpResponse&,
                  std::shared_ptr<HttpRouter::AsyncPendingState> state) {
            state->SetSyncResult(HttpRouter::AsyncMiddlewareResult::PASS);
            state->MarkCompletedSync();
        };
    }
    return [mgr](const HttpRequest& req, HttpResponse& resp,
                  std::shared_ptr<HttpRouter::AsyncPendingState> state) {
        mgr->InvokeAsyncMiddleware(req, resp, std::move(state));
    };
}

}  // namespace AUTH_NAMESPACE
