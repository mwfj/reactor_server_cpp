#pragma once

#include "common.h"
#include "auth/auth_config.h"
// <vector>, <string> via common.h

namespace auth {

// AppliedPolicy is a (path_prefix, policy) pair. One policy may have many
// applied entries (one per prefix in its applies_to list). AppliedPolicyList
// is an immutable snapshot — atomically swapped inside AuthManager on Reload.
struct AppliedPolicy {
    std::string prefix;
    AuthPolicy policy;
};

using AppliedPolicyList = std::vector<AppliedPolicy>;

// Longest-prefix match over an AppliedPolicyList.
//
// Semantics:
// - Returns a pointer to the entry whose `prefix` is the LONGEST string that
//   is a prefix of `path`. Returns nullptr if nothing matches.
// - Ties between equal-length prefixes are NOT resolved here — the config
//   loader rejects exact-prefix collisions at load time (see §3.2 of the
//   design spec). If a tie does somehow reach runtime (e.g. programmatic
//   RegisterPolicy bypassing validation) the first in the vector wins.
// - An empty prefix ("") is valid and matches every path; operators may use
//   it as a catch-all "require auth on everything" policy. It will lose to
//   any longer matching prefix (longest-prefix wins).
// - Matching is case-sensitive. HTTP path components are case-sensitive per
//   RFC 3986 §6.2.2.1 (schemes and hosts are the case-insensitive parts).
const AppliedPolicy* FindPolicyForPath(const AppliedPolicyList& policies,
                                       const std::string& path);

// Validate that an AppliedPolicyList has no exact-prefix collisions. Returns
// true when the list is clean. On collision, returns false and stores an
// offender description in `err_out` (format: "prefix `/api/v1` declared by
// both policy A and policy B").
//
// Called by ConfigLoader::Validate at load time and by AuthManager::Reload
// before swapping in a new snapshot.
bool ValidatePolicyList(const AppliedPolicyList& policies,
                        std::string& err_out);

}  // namespace auth
