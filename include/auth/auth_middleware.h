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

}  // namespace AUTH_NAMESPACE
