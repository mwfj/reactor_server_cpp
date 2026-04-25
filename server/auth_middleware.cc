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

HttpRouter::AsyncMiddleware MakeAsyncMiddleware(AuthManager* /*mgr*/) {
    // No-op pass-through: always completes synchronously with PASS. The
    // shared_ptr<AsyncPendingState> argument is constructed in
    // HttpRouter::RunAsyncMiddleware before the call, so it is never
    // null on entry. Setting sync_result=PASS + MarkCompletedSync makes
    // the callsite's uniform fast-path read fall through to
    // DispatchHandler unchanged.
    return [](const HttpRequest&, HttpResponse&,
              std::shared_ptr<HttpRouter::AsyncPendingState> state) {
        state->SetSyncResult(HttpRouter::AsyncMiddlewareResult::PASS);
        state->MarkCompletedSync();
    };
}

}  // namespace AUTH_NAMESPACE
