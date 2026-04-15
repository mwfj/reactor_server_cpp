#include "auth/auth_policy_matcher.h"

#include <unordered_map>

namespace auth {

const AppliedPolicy* FindPolicyForPath(const AppliedPolicyList& policies,
                                       const std::string& path) {
    const AppliedPolicy* best = nullptr;
    size_t best_len = 0;

    for (const auto& entry : policies) {
        const auto& pref = entry.prefix;
        // An empty prefix matches anything (catch-all).
        if (pref.empty()) {
            if (!best) {
                best = &entry;
                best_len = 0;
            }
            continue;
        }
        if (path.size() < pref.size()) continue;
        if (path.compare(0, pref.size(), pref) != 0) continue;
        if (pref.size() > best_len) {
            best = &entry;
            best_len = pref.size();
        }
    }
    return best;
}

bool ValidatePolicyList(const AppliedPolicyList& policies,
                        std::string& err_out) {
    std::unordered_map<std::string, std::string> seen;  // prefix -> owner name
    for (const auto& entry : policies) {
        const std::string& pref = entry.prefix;
        const std::string& owner =
            entry.policy.name.empty() ? std::string("<unnamed>")
                                      : entry.policy.name;
        auto [it, inserted] = seen.try_emplace(pref, owner);
        if (!inserted) {
            err_out = "auth policy prefix `" + pref +
                      "` declared by both `" + it->second + "` and `" +
                      owner + "` — exact-prefix collisions must be resolved "
                      "at config time (see design spec §3.2)";
            return false;
        }
    }
    return true;
}

}  // namespace auth
