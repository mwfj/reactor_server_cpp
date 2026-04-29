#pragma once

#include "http/http_router.h"
#include "auth/auth_manager.h"

namespace AUTH_NAMESPACE {

// Construct a middleware closure bound to `mgr` that AuthManager consumes
// via InvokeMiddleware. The closure captures `mgr` by pointer (non-owning
// — AuthManager outlives the router) and forwards to InvokeMiddleware.
// Safe to install via HttpRouter::PrependMiddleware.
//
// Returns an empty (no-op / always-pass) middleware when `mgr` is null.
HttpRouter::Middleware MakeMiddleware(AuthManager* mgr);

// Construct an async middleware closure bound to `mgr` for installation
// via HttpRouter::PrependAsyncMiddleware. The body completes
// synchronously with PASS until introspection-mode dispatch is wired,
// adding only the cost of one shared_ptr allocation per request inside
// RunAsyncMiddleware. Safe to install at server startup unconditionally.
HttpRouter::AsyncMiddleware MakeAsyncMiddleware(AuthManager* mgr);

}  // namespace AUTH_NAMESPACE
