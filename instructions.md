# Zoolanding API Proxy Contract

## Request Contract

`POST /api-proxy/read`

```json
{
  "domain": "music.lynxpardelle.com",
  "pageId": "default",
  "sourceId": "pokemon-list",
  "input": {
    "limit": 8
  }
}
```

`POST /api-proxy/action`

```json
{
  "domain": "music.lynxpardelle.com",
  "pageId": "default",
  "actionId": "newsletter-subscribe",
  "input": {
    "email": "listener@example.test",
    "language": "en"
  }
}
```

`GET /auth/runtime-config?domain=music.lynxpardelle.com&authProfileId=staff`

or:

```json
{
  "domain": "music.lynxpardelle.com",
  "authProfileId": "staff"
}
```

Active profiles return the same public `runtime.auth` shape that the Angular app validates:

```json
{
  "ok": true,
  "domain": "music.lynxpardelle.com",
  "auth": {
    "enabled": true,
    "authProfileId": "staff",
    "provider": "cognito",
    "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
    "hostedUiDomain": "https://auth.example.test",
    "clientId": "public-client-id",
    "scopes": ["openid", "email", "profile"],
    "redirectPath": "/auth/callback",
    "logoutPath": "/logout",
    "loginPath": "/login",
    "groupsClaim": "cognito:groups",
    "allowedGroups": ["Editors"]
  }
}
```

Inactive profiles return the same public shape with `enabled: false`; profile status and provisioning details stay server-only. Runtime-config rejects browser-supplied secret or policy fields; only `domain` and `authProfileId` are accepted in this public request. Browser requests are origin-bound: a public draft origin can request only its own domain, or a canonical domain when the origin is a managed alias proven by server-only registry metadata. `test.zoolandingpage.com.mx` and local QA origins can preview other domains.

`POST /auth/provisioning-plan`

```json
{
  "domain": "music.lynxpardelle.com",
  "authProfileId": "staff"
}
```

`/auth/provisioning-plan` is server-only. It is denied unless the API Gateway/Lambda request context contains a signed IAM role ARN whose role name or ARN is allowlisted by environment configuration.

Provisioning-plan requests accept only `domain` and `authProfileId`. The response is versioned and deterministic so a future executor can resume safely without inventing new identifiers: it includes `planVersion`, `planKey`, lifecycle state, runtime public-client config, hosted UI details, expected post-activation outputs, normalized social IdP references, and per-operation `operationKey` plus `idempotencyKey` values. `planned` and `provisioning` return resumable operations toward `active`; `active` returns an explicit noop plan; `suspended` and `failed` return explicit manual-review plans. Social IdPs stay reference-only; no secret values are resolved or echoed.

`POST /auth/provisioning-executor`

```json
{
  "domain": "music.lynxpardelle.com",
  "authProfileId": "staff",
  "mode": "dry-run",
  "planKey": "optional-current-plan-key",
  "idempotencyKey": "optional-64-character-hex-key"
}
```

`/auth/provisioning-executor` is server-only and must stay IAM-authorized. Requests accept only `domain`, `authProfileId`, `mode`, optional `planKey`, and optional `idempotencyKey`. `dry-run` regenerates and validates the current plan, returns sanitized operation previews and a deterministic audit event, and does not perform AWS writes, call Cognito, or create/update/delete resources; it may read the server-only registry from the configured local or deployed sources. `apply` is explicit but fails closed with manual review required; it is not implemented and must not create Cognito resources until a future approved deploy/provisioning pass.

## Server-Only Policy

Published drafts can include `server/integrations.json` in the config payload bucket. Runtime-read must not expose this file to the browser.

```json
{
  "version": 1,
  "sources": [
    {
      "id": "pokemon-list",
      "method": "GET",
      "url": "https://pokeapi.co/api/v2/pokemon",
      "allowedInputFields": ["limit", "offset"],
      "response": {
        "allowedFields": ["count", "results"],
        "maxBytes": 524288
      }
    },
    {
      "id": "pokemon-detail",
      "method": "GET",
      "urlTemplate": "https://pokeapi.co/api/v2/pokemon/{pokemonName}",
      "allowedInputFields": ["pokemonName"],
      "response": {
        "singleItem": true,
        "allowedFields": ["id", "name", "sprites.other.official-artwork.front_default", "types.type.name"]
      }
    },
    {
      "id": "member-posts",
      "method": "GET",
      "url": "https://cms.example.test/member-posts",
      "access": {
        "required": true,
        "authProfileId": "staff",
        "allowedGroups": ["Editors"]
      },
      "allowedInputFields": ["section"],
      "response": {
        "allowedFields": ["items.title", "items.href"]
      }
    }
  ],
  "actions": [
    {
      "id": "newsletter-subscribe",
      "method": "POST",
      "url": "https://mailing.example.test/subscribe",
      "credentialRef": "zoolanding/api/music/newsletter",
      "auth": {
        "type": "bearer",
        "secretField": "accessToken"
      },
      "allowedInputFields": ["email", "language"],
      "response": {
        "allowedFields": ["status", "subscriberId"]
      }
    }
  ]
}
```

Access options:

- Omit `access` or set `access.required: false` for public integrations.
- Set `access.required: true` for protected sources/actions. Protected integrations require a browser `Authorization: Bearer <jwt>` header.
- `access.authProfileId` selects the server-only auth profile used to verify issuer, audience/client ID, tenant, and profile groups.
- `access.allowedGroups` can further narrow access for a specific source/action beyond the profile's own group policy.
- The user JWT is never forwarded upstream. Upstream credentials still use `credentialRef` plus the existing `auth` block.

Auth options:

- `bearer`: reads `auth.secretField` from the Secrets Manager JSON object and sends `Authorization: Bearer <value>`.
- `api-key-header`: reads `auth.secretField` and sends it in the policy-controlled `auth.headerName`.
- `oauth2-client-credentials`: reads `auth.clientIdField` and `auth.clientSecretField` from the Secrets Manager JSON object, exchanges them at `auth.tokenUrl` with `grant_type=client_credentials`, and sends the returned bearer token upstream. The default field names are `clientId` and `clientSecret`.

Static request headers may be configured with `headers` when an upstream API requires non-secret metadata such as `Accept`. Do not put credentials there; `authorization`, `cookie`, `set-cookie`, and `x-api-key` are rejected.

Parameterized upstream URLs use `urlTemplate` instead of `url`. A template can include placeholders such as `{pokemonName}` for detail pages, blog articles, product records, or similar route/query-driven resources. Every placeholder must be listed in `allowedInputFields`; missing, object, array, empty, or overlong values are rejected. Accepted values are trimmed and percent-encoded before the upstream request. Fields consumed by the URL template are not forwarded again as query/body input, while other allowlisted fields continue to be forwarded normally.

## Creating Credential Placeholders

Use `secret-placeholders/credential-placeholders.json` as the repeatable inventory of API proxy credential placeholders. It stores only safe metadata: Secrets Manager name, expected JSON field names, description, and tags.

```powershell
python .\tools\ensure_secret_placeholders.py --dry-run
python .\tools\ensure_secret_placeholders.py --region us-east-1
```

The script is idempotent: existing secrets are left untouched so real values entered in the AWS console are not replaced. New secrets are created with placeholder JSON values such as:

```json
{
  "clientId": "__SET_IN_AWS_CONSOLE__",
  "clientSecret": "__SET_IN_AWS_CONSOLE__"
}
```

## Auth Profile Registry

Published drafts can include `server/auth-profile-registry.json` in the same private payload prefix as `server/integrations.json`. Runtime-read must not expose this file to the browser.

```json
{
  "version": 1,
  "profiles": [
    {
      "authProfileId": "staff",
      "status": "active",
      "tenantId": "tenant-a",
      "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
      "hostedUiDomain": "https://auth.example.test",
      "clientId": "public-client-id",
      "audiences": ["public-client-id"],
      "loginPath": "/login",
      "logoutPath": "/logout",
      "callbackUrls": ["https://music.lynxpardelle.com/auth/callback"],
      "logoutUrls": ["https://music.lynxpardelle.com/logout"],
      "scopes": ["openid", "email", "profile"],
      "tenantClaim": "custom:tenant_id",
      "groupClaim": "cognito:groups",
      "allowedGroups": ["Editors"],
      "socialIdpSecretRefs": {
        "google": "/zoolanding/auth/tenant-a/staff/google",
        "facebook": "/zoolanding/auth/tenant-a/staff/facebook"
      }
    }
  ]
}
```

Raw secrets, tokens, client secrets, private keys, passwords, credentials, and API keys are rejected in the registry. Social IdP setup uses secret refs only, and those refs must look like SSM/Secrets Manager references such as `/zoolanding/auth/tenant-a/staff/google` or AWS SSM/Secrets Manager ARNs. Active profiles must include `tenantId`, use absolute HTTPS `issuer` and `hostedUiDomain` values, same-origin auth paths that start with `/`, and HTTPS callback/logout URLs.

Structured social IdPs may also use a server-only `socialIdentityProviders` list. Each entry may declare `providerId`, `providerType` (`google`, `facebook`, `oidc`, or another executor-known type), optional public OIDC metadata such as `issuer`, `discoveryUrl`, `authorizeUrl`, `tokenUrl`, `userInfoUrl`, and `jwksUrl`, plus secret references such as `clientIdRef`, `clientSecretRef`, `providerSecretRef`, or nested `secretRefs`. Secret-looking raw values are still rejected.

The JWT authorizer is exposed as `auth_service.jwt_authorizer_handler` for future protected APIs. It verifies RS256 tokens through JWKS, keeps the full Cognito issuer path when building `/.well-known/jwks.json`, accepts either `aud` or Cognito access-token `client_id`, and enforces tenant/group policy from the server-only profile.

## Acceptance Criteria

- A single draft/site can configure multiple read sources and multiple actions.
- A single draft/site can optionally configure one or more auth profiles.
- Public auth runtime config exposes only safe public metadata and never exposes client secrets or social IdP secret refs.
- Public auth runtime config rejects browser origins that do not belong to the requested domain or a proven managed alias for that domain.
- Server-only provisioning plans are denied by default, remain plan-only until a future explicit deployment/provisioning decision, and expose stable operation/idempotency keys for a future executor.
- Server-only provisioning executor dry-run returns sanitized previews and audit keys without secret refs; apply remains closed/no-op until explicitly approved and implemented.
- The reusable JWT authorizer can protect future blogs, dashboards, uploads, and mutable actions using the same server-only registry policy.
- The browser cannot choose arbitrary upstream URLs.
- The browser cannot send undeclared input fields.
- Parameterized detail sources can resolve server-owned upstream URLs from allowlisted scalar input without exposing arbitrary URL control to the browser.
- The Lambda only resolves credentials by `credentialRef`.
- Secret values are never returned to the browser.
- Upstream errors are returned as generic public errors.
- The Lambda can represent `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.
- Real destructive actions require an authorization design before production enablement.

## Non-Goals

- This repo creates only placeholder Secrets Manager entries; it does not store, generate, or rotate real upstream credential values.
- This repo does not deploy itself automatically.
- This repo does not expose `server/integrations.json` through runtime-read.
- This repo does not create Cognito user pools, app clients, domains, Google/Facebook IdPs, API Gateway authorizers, or IAM roles unless a future deploy/provisioning step is explicitly run.
- This repo does not execute Cognito provisioning through the scaffolded executor; the apply mode currently returns a safe not-implemented response.
