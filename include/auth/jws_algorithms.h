#pragma once

#include "common.h"
// <string> via common.h

namespace AUTH_NAMESPACE {

// JWT signature algorithms accepted in v1. Asymmetric-only per design spec
// §5.3 — HS* requires symmetric-secret provisioning (deferred §15),
// `none` is NEVER admitted, PS* / `auto` are deferred. Shared by
// ConfigLoader (startup + hot-reload) and Issuer (apply-path) so every
// validation gate checks the same set.
inline bool IsSupportedJwsAlg(const std::string& alg) {
    return alg == "RS256" || alg == "RS384" || alg == "RS512"
        || alg == "ES256" || alg == "ES384";
}

}  // namespace AUTH_NAMESPACE
