# OAuth 2.0 Token Validation

The gateway ships with built-in OAuth 2.0 bearer-token validation. Point it at one or more identity providers, mark the routes you want protected, and the gateway checks every request before it reaches the upstream — rejecting anything without a valid token and forwarding a sanitized identity payload on success.

This is a **resource-server** validator. The gateway does not run the authorization-code dance, issue tokens, or host a login page. It expects clients (or an upstream BFF) to present an already-minted bearer token in `Authorization: Bearer <jwt>`.

Full design and security rationale live in [`.claude/documents/design/OAUTH2_TOKEN_VALIDATION_DESIGN.md`](../.claude/documents/design/OAUTH2_TOKEN_VALIDATION_DESIGN.md). This document is the operator's guide.

---

## What's in the box

- **JWT validation** against JWKS keys. Signature, issuer, audience, expiry, optional `nbf`, leeway, and per-route scope / required-claim checks — all done on the dispatcher thread in the request hot path.
- **OIDC discovery** (`.well-known/openid-configuration`) or a static `jwks_uri` override. JWKS is cached, coalesced, and served stale-on-error.
- **Multi-issuer routing**. A single gateway can accept tokens from Google and your private IdP on the same listener; policies pick which issuers each route trusts.
- **Per-route policies**. Either attached inline to a proxy (`proxy.auth`), or declared top-level (`auth.policies[]`) for programmatic routes.
- **401 / 403 / 503 taxonomy** with RFC 6750 `WWW-Authenticate` headers, `Retry-After` on 503, and an `on_undetermined: deny|allow` switch for degraded-IdP scenarios.
- **Outbound identity injection**. On ALLOW the gateway strips any inbound copies of identity headers and emits the ones you configure (`X-Auth-Subject`, scopes, whitelisted claims, optionally the raw JWT).
- **Hot reload**. Issuer cache TTLs, algorithms, audiences, required scopes, and the forward-header overlay are all live-reloadable; topology (adding a new issuer) still needs a restart.
- **Introspection mode (RFC 7662)** is scaffolded in the config schema but the enforcement path is **Phase 3 deferred** — the validator rejects `mode: "introspection"` at startup for now.

What it does **not** do: authorization-code flow, token revocation, refresh, session cookies, CSRF — those belong to a BFF service behind the gateway.

---

## Minimal configuration

Here's the smallest working setup: one IdP (Google), one protected route, and identity forwarding.

```json
{
  "upstreams": [
    {
      "name": "api-backend",
      "host": "10.0.1.5",
      "port": 8080,
      "proxy": {
        "route_prefix": "/api/",
        "auth": {
          "enabled": true,
          "issuers": ["google"],
          "required_scopes": ["api.read"]
        }
      }
    },
    {
      "name": "google-idp",
      "host": "www.googleapis.com",
      "port": 443,
      "tls": { "enabled": true, "verify_peer": true, "sni_hostname": "www.googleapis.com" },
      "pool": { "max_connections": 4 }
    }
  ],
  "auth": {
    "enabled": true,
    "issuers": {
      "google": {
        "issuer_url": "https://accounts.google.com",
        "discovery": true,
        "upstream": "google-idp",
        "audiences": ["https://api.example.com"],
        "algorithms": ["RS256"]
      }
    },
    "forward": {
      "subject_header": "X-Auth-Subject",
      "issuer_header": "X-Auth-Issuer",
      "scopes_header": "X-Auth-Scopes",
      "strip_inbound_identity_headers": true
    }
  }
}
```

What happens on a request to `/api/orders`:

1. Middleware matches the inline policy (derived from `proxy.route_prefix`).
2. Gateway extracts the bearer token from `Authorization`.
3. It peeks the unverified `iss` claim, picks the matching issuer from the policy's allowlist, loads the JWKS key by `kid`, and verifies signature + claims (including `aud`, `exp`, algorithm).
4. It checks `scope` / `scp` contains `api.read`.
5. On success, the client's copy of `X-Auth-Subject` etc. is **stripped** and the verified values are injected for the upstream.
6. The request is proxied to `api-backend`.

Failure modes are covered below. See [`config/server.example.json`](../config/server.example.json) for an annotated reference config.

---

## JWT mode vs introspection mode

Each issuer has a `mode` field.

| Mode | Status | What it does |
|---|---|---|
| `jwt` (default) | Available | Verify the JWT signature locally using JWKS keys. No per-request network call to the IdP (beyond the cached JWKS fetch). |
| `introspection` | Deferred to Phase 3 | POST to the IdP's `/introspect` endpoint per token. Rejected at config load for now. |

If your IdP issues opaque tokens (e.g. some Keycloak deployments), you'll want introspection mode. For now, stick to JWT — the scaffolding is in place so a future release can turn it on without a config migration.

---

## Supported algorithms

The validator admits only asymmetric signature algorithms by default:

- RSA: `RS256`, `RS384`, `RS512`
- ECDSA: `ES256`, `ES384`

`HS256` and friends are rejected — shared-secret signing would require distributing the IdP's private key to every gateway, which is not a security model this server endorses.

`alg: none` is explicitly rejected per RFC 8725 §3.1 — tokens signed with `none` are never accepted, regardless of the algorithms allowlist.

Per-issuer algorithm allowlist lives at `auth.issuers.<name>.algorithms`. Keep it narrow. Accepting `RS512` when your IdP only issues `RS256` is a downgrade-substitution risk.

---

## Failure modes

Every failed request maps to one of three HTTP statuses:

| Status | When | `WWW-Authenticate` | `Retry-After` |
|---|---|---|---|
| `401 Unauthorized` | No/malformed header, bad signature, wrong issuer, expired, wrong audience | Yes (`error="invalid_request"` or `error="invalid_token"`) | No |
| `403 Forbidden` | Signature valid but required scopes are missing | Yes (`error="insufficient_scope"`, `scope="..."`) | No |
| `503 Service Unavailable` | IdP unreachable, JWKS kid miss without fallback, transient verifier build error — i.e. we **don't know** if the token is good | No (RFC 7235 §3.1 — do not emit a challenge when the verifier is broken) | Yes (1–300 s, clamped) |

### `on_undetermined: allow`

For advisory / observability deployments (e.g. you want to see which routes would deny, without actually denying), set a policy's `on_undetermined` to `"allow"`. A request that would have returned 503 will instead proceed with `X-Auth-Undetermined: true` injected into the outbound headers and a warn log. The upstream can decide what to do with it.

The default is `"deny"`. Don't flip this globally in production unless you know what you're signing up for.

### Why 503, not 401, when the IdP is down

A 401 tells the client "your token is bad, get a new one." If the gateway can't reach the IdP to verify, the token might still be fine — and forcing the client to re-auth would stampede the IdP right when it's already struggling. A 503 with `Retry-After` says "not now, come back in N seconds" and clients back off. See design spec §8.2.

---

## Outbound header injection

Once a token is validated, the gateway rewrites the outbound headers for the upstream hop. All of this is governed by `auth.forward`:

```json
"forward": {
  "subject_header": "X-Auth-Subject",
  "issuer_header":  "X-Auth-Issuer",
  "scopes_header":  "X-Auth-Scopes",
  "raw_jwt_header": "",
  "claims_to_headers": {
    "email":       "X-Auth-Email",
    "tenant_id":   "X-Tenant"
  },
  "strip_inbound_identity_headers": true,
  "preserve_authorization": true
}
```

### Identity headers

`subject_header`, `issuer_header`, and `scopes_header` populate from the verified `sub`, `iss`, and extracted scope list. Leaving any of them empty omits that header.

### `claims_to_headers`

Maps a claim name in the verified JWT payload to an outbound header name. Useful for passing tenant IDs, email addresses, group memberships, etc. without exposing the raw JWT.

- The gateway only forwards claims that are **simple strings or numbers**. Arrays and objects are ignored (with a debug log) — header values don't have a wire format for them.
- Both the claim name and the output header name are validated — header names must match RFC 7230 §3.2.6 `tchar`, and reserved names (see below) are rejected at config load.

### `strip_inbound_identity_headers`

When `true` (the default and the recommended setting), the gateway deletes any client-provided copies of the headers it plans to inject. Without this, a caller could forge `X-Auth-Subject: admin@example.com` and bypass auth at the upstream. Always keep this on.

### `preserve_authorization`

Default `true`. When `true`, the gateway forwards the original `Authorization` header to the upstream — useful when the upstream wants to do its own token inspection. When `false`, the `Authorization` header is stripped.

If you're terminating auth at the gateway, set this to `false`. If your upstream re-verifies for defense-in-depth, leave it on.

### `raw_jwt_header`

Opt-in. When set to a non-empty header name (e.g. `X-Auth-Raw-JWT`), the gateway forwards the original compact JWT string under that header.

**Don't turn this on unless your upstream specifically needs it.** You're shipping a credential across your own network; combined with log scraping or a header-logging sidecar, it's a token-leak vector. `X-Auth-Subject` + `X-Auth-Scopes` + the whitelisted claims usually give the upstream everything it needs.

### Reserved names

The following header names are **rejected at config load** if they appear as an output header in `subject_header` / `issuer_header` / `scopes_header` / `raw_jwt_header` or any `claims_to_headers` value:

- HTTP/2 pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`, `:status`)
- Hop-by-hop headers (RFC 7230 §6.1: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, plus legacy `Proxy-Connection`)
- Framing-critical headers (`Host`, `Content-Length`, `Content-Type`, `Content-Encoding`)
- `Authorization` (conflicts with `preserve_authorization`)
- HeaderRewriter-owned: `Via`, `X-Forwarded-For`, `X-Forwarded-Proto`

Picking one of these would either crash the upstream's HTTP parser or silently mangle the identity / proxy-chain signal.

---

## Operations

### JWKS caching

Every issuer has its own JWKS cache.

- **TTL**: `jwks_cache_sec` (default 300). When the TTL expires, the next request triggers a background refresh; the old keys stay live until the refresh completes.
- **Refresh triggers**: TTL expiry OR a live request presents a `kid` that isn't in the cache (key rotation path).
- **Coalescing**: only one refresh is in flight per issuer at any time, enforced by an atomic CAS.
- **Stale on error**: if the refresh fails (IdP unreachable, 5xx, timeout), the cache keeps serving the old keys and increments a `jwks_stale_served` counter. You can see this counter in `/stats`. A rate-limited warn log tells you about it.
- **Hard cap**: 64 keys per issuer. Most IdPs publish 2–5. Anything beyond is trimmed with a warn — a JWKS with thousands of keys is either a misconfiguration or a DoS.

### OIDC discovery

When `discovery: true`, the gateway fetches `<issuer_url>/.well-known/openid-configuration` at startup (and on SIGHUP). The response populates `jwks_uri` and (for Phase 3) `introspection_endpoint`.

If discovery fails, the issuer schedules a retry after `discovery_retry_sec` seconds (default 30). Requests targeting this issuer's policies return 503 / `UNDETERMINED` until discovery succeeds.

If you want to skip discovery (e.g. talk to an IdP that doesn't publish the metadata document), set `discovery: false` and provide `jwks_uri` explicitly.

### Hot reload semantics

Send `SIGHUP` (or `server_runner reload`) to reload. These fields are **live-reloadable**:

- `auth.enabled` (master switch)
- Per-issuer: `audiences`, `algorithms`, `leeway_sec`, `required_claims`, `jwks_cache_sec`, `jwks_refresh_timeout_sec`, `discovery_retry_sec`
- Per-policy: `enabled`, `required_scopes`, `required_audience`, `on_undetermined`, `realm`
- All `auth.forward.*` fields

These fields are **restart-required**:

- Adding or removing issuers
- Changing an issuer's `issuer_url`, `discovery`, `jwks_uri`, `upstream`, or `mode`
- Changing the `applies_to` / inline `route_prefix` topology of policies (i.e. which routes are protected)

A reload that only touches live-reloadable fields applies immediately to the next request. A reload that requests a topology change logs a warn ("restart required") and the live topology stays as-is — nothing silently diverges from what operators typed. Already-running requests continue with the snapshot they started against.

### Observability

Every `/stats` snapshot includes a per-issuer block:

```
"auth": {
  "issuers": {
    "google": {
      "ready": true,
      "jwks_refresh_ok": 142,
      "jwks_refresh_fail": 2,
      "jwks_stale_served": 17,
      "jwks_key_count": 4,
      "last_jwks_refresh": "2026-04-18T12:03:22Z"
    }
  },
  "totals": { "allowed": 98234, "denied": 71, "undetermined": 3 }
}
```

Operator log lines follow a predictable pattern:

- `auth: ALLOW sub=<redacted> iss=google policy=admin-only scopes=...`
- `auth: DENY_401 reason=signature_invalid policy=api-read iss=<peeked>`
- `auth: DENY_403 reason=insufficient_scope policy=billing-read required=billing.read have=...`
- `auth: UNDETERMINED reason=jwks_fetch_timeout policy=api-read (on_undetermined=deny → 503)`

Raw tokens are **never** logged; operators get the issuer / kid / short reason labels.

---

## Security recommendations

1. **Always use TLS between the gateway and the IdP.** `jwks_uri` and `introspection.endpoint` are rejected at config load if they start with `http://` — not negotiable.
2. **Keep the algorithm allowlist tight.** If your IdP only signs with `RS256`, list just `RS256`. Admitting extra algorithms is a substitution risk.
3. **Strip inbound identity headers.** `strip_inbound_identity_headers: true` is the default for a reason. Forged `X-Auth-Subject` headers are a classic auth bypass.
4. **Never inline `client_secret`.** Use `client_secret_env` and load from a secret-manager-populated environment variable. The validator rejects inline secrets at load.
5. **Tune `leeway_sec` for clock skew, not for convenience.** 30 seconds is normal. Values above 300 start accepting tokens that are genuinely expired.
6. **Pin `audiences`.** An empty audience list accepts any audience — including tokens minted for a different application.
7. **Don't enable `raw_jwt_header` unless you need it.** Every header you inject is a potential log leak.
8. **Keep `on_undetermined: deny`** in production. Only flip to `allow` when you're rolling out and explicitly want advisory mode.

---

## Troubleshooting

### `401 invalid_token` on every request

- **Wrong `audiences`**: the token's `aud` claim doesn't match any configured audience. Decode the token at jwt.io (dev only!) and inspect `aud`.
- **Wrong algorithm**: the token was signed with an algorithm not in your `algorithms` list.
- **Clock skew**: increase `leeway_sec` to 60s and see if the issue disappears (it usually won't with well-synced servers).
- **Key rotation mid-refresh**: the IdP rotated keys but the cache is stale. Check `jwks_refresh_fail` and `jwks_stale_served` in `/stats`.

### `503 Service Unavailable` with `Retry-After`

The gateway can't verify — usually an IdP connectivity issue:

- Is the `upstream` entry pointing at the right host/port?
- Is TLS to the IdP working? Look for `auth: UNDETERMINED reason=jwks_fetch_timeout` or `tls_handshake_failed` in the log.
- Is the circuit breaker open against the IdP upstream? Check `/stats`.
- If the issuer was never ready, discovery never succeeded. Check for `oidc: discovery failed` warnings.

### `403 insufficient_scope`

The token was valid, but the required scopes aren't present. The `WWW-Authenticate` header tells you what the gateway expected — compare with what the IdP actually embeds in the token's `scope` / `scp` / `scopes` claim.

### "Reload logged 'restart required'"

You changed a topology field (new issuer, new `applies_to`). The running server keeps the old topology. Restart to pick up the new layout, or if you only wanted to edit reloadable fields, undo the topology change and SIGHUP again.

### Clock skew across instances

The gateway uses its own clock for `exp` / `nbf` / `iat`. If your fleet has drifted clocks, you'll see sporadic `exp_invalid` denials. Set `leeway_sec` to cover expected drift (30s is usually plenty); run NTP if it's not.

### Programmatic routes

Routes registered in code (via `HttpRouter::Handle(...)`) are not covered by inline `proxy.auth`. Use top-level `auth.policies[]` with explicit `applies_to` prefixes for those. Example:

```json
"policies": [{
  "name": "admin-api",
  "enabled": true,
  "applies_to": ["/admin/"],
  "issuers": ["ours"],
  "required_scopes": ["admin"]
}]
```

Top-level policies always require a `name` (so `/stats` and logs stay stable across config edits) and support literal-byte `applies_to` prefixes.

---

## Known risks and open issues

These are tracked in §16 of the design spec:

- **HS256 / symmetric keys not supported.** If you need them, the validator needs extending — scope decision for a future release.
- **Introspection mode deferred.** Opaque-token IdPs aren't usable yet.
- **`alg: none` explicitly rejected** regardless of allowlist.
- **No token revocation hook.** A compromised token is valid until `exp`. Keep `leeway_sec` small and TTLs short.
- **`on_undetermined: allow` is a knowingly-lax degraded mode.** It exists for rollout / observability; don't run it long-term.
- **JWKS cache is per-issuer, process-local.** Multiple gateway instances each fetch independently; if that's a problem for your IdP's rate limits, front it with a shared cache.

---

## See also

- [`docs/configuration.md`](configuration.md) — full `auth.*` field reference and validation rules.
- [`docs/architecture.md`](architecture.md) — where the auth middleware fits in the layered design.
- [`.claude/documents/design/OAUTH2_TOKEN_VALIDATION_DESIGN.md`](../.claude/documents/design/OAUTH2_TOKEN_VALIDATION_DESIGN.md) — design rationale, data flow, threat model.
- [`.claude/documents/features/OAUTH_TOKEN_VALIDATION.md`](../.claude/documents/features/OAUTH_TOKEN_VALIDATION.md) — internal component reference.
