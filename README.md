# Zoolanding API Proxy

Server-side API proxy for Zoolanding runtime drafts.

The Angular app calls:

- `POST /api-proxy/read` for configured read data sources.
- `POST /api-proxy/action` for configured mutable API actions.
- `GET` or `POST /auth/runtime-config` for public, config-driven auth metadata.
- `POST /auth/provisioning-plan` for server-only, plan-only Cognito provisioning output.

The browser sends only `domain`, optional `pageId`, `sourceId` or `actionId`, and allowlisted input values. It never sends upstream URLs or credentials. The Lambda resolves the published server-only policy from `server/integrations.json`, loads credentials by `credentialRef` from SSM SecureString, calls the upstream API, filters the response, and returns safe JSON.

Auth profiles are resolved from the published server-only file `server/auth-profile-registry.json`. The runtime auth endpoint accepts only `domain` and `authProfileId`, enforces that the browser `Origin` belongs to the requested domain or to a managed alias for that domain, then returns the same public `runtime.auth` shape validated by the Angular app. Active profiles return `enabled: true`; planned, provisioning, suspended, and failed profiles return the same secret-free public metadata with `enabled: false`. The provisioning endpoint is denied by default and returns only plan-only output when the caller's signed IAM role is explicitly allowlisted by `AUTH_PROVISIONING_ALLOWED_ROLE_NAMES` or `AUTH_PROVISIONING_ALLOWED_ROLE_ARNS`.

Parameterized read sources can use server-owned `urlTemplate` values, for example `https://pokeapi.co/api/v2/pokemon/{pokemonName}`. Template placeholders must also appear in `allowedInputFields`; the Lambda trims and percent-encodes those values, uses them only to resolve the upstream URL, and keeps all undeclared fields blocked.

Server-only `server/integrations.json` entries can protect individual sources/actions with an `access` block. `access` verifies the browser JWT against the server-only auth profile registry before the proxy calls upstream. Existing integration `auth` blocks remain reserved for upstream API credentials.

## AWS Dependencies

- DynamoDB table: `zoolanding-config-registry`
- S3 bucket: `zoolanding-config-payloads`
- SSM Parameter Store SecureString for `credentialRef` values
- API Gateway: `POST /api-proxy/read`, `POST /api-proxy/action`, `GET|POST /auth/runtime-config`, and `POST /auth/provisioning-plan`
- PyJWT with crypto support for reusable JWT authorizer verification against JWKS

## Local Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

The tests stub policy loading, upstream calls, and secrets. They do not call AWS and do not require real credentials.

## Local Harness

```powershell
$env:DRY_RUN = "1"
python .\local_test.py
```

For local browser QA of remote auth, run the HTTP harness with an explicit server-only registry source. `LOCAL_AUTH_REGISTRY_DIR` points at a folder containing `{domain}\server\auth-profile-registry.json`; `LOCAL_AUTH_REGISTRY_FILE` may point at a single registry file instead.

```powershell
$env:DRY_RUN = "1"
$env:LOCAL_AUTH_REGISTRY_DIR = "C:\path\to\zoolandingpage\drafts"
$env:ZLP_LOCAL_AUTH_PROXY_PORT = "5055"
python .\local_auth_server.py
```

Then point the Angular dev server proxy at `http://127.0.0.1:5055`. The local auth harness dispatches through the same Lambda handler shape, including stage-prefixed paths such as `/Prod/auth/runtime-config`, and does not use `/auth/provisioning-plan` for browser QA.

## Deploy

Do not deploy or create secrets until the frontend and policy contract are reviewed.

```bash
sam deploy
```

The checked-in `samconfig.toml` targets `us-east-1`, stack `zoolanding-api-proxy`, and the platform production/testing browser origins. Localhost and 127.0.0.1 origins are accepted by the Lambda for local QA only. Published draft domains are accepted dynamically from the config registry, so adding a new draft domain does not require editing the API Gateway/Lambda CORS parameter.

## Credential Placeholder Workflow

Credential values are not stored in this repository. New credentials should use SSM SecureString parameters under `/${credentialRef}`. To add a new API credential, add only the credential reference, required JSON field names, and non-sensitive tags to `secret-placeholders/credential-placeholders.json`, then create missing placeholders:

```powershell
python .\tools\ensure_secret_placeholders.py --dry-run
python .\tools\ensure_secret_placeholders.py --region us-east-1
```

The legacy script creates only missing Secrets Manager entries under `zoolanding/api/` and does not overwrite existing secrets. Prefer creating a matching SSM SecureString parameter such as `/zoolanding/api/music/tidal`; after creation, replace `__SET_IN_AWS_CONSOLE__` placeholders through AWS-managed secret tooling, not in repo files.

## Security Model

- Credentials are stored in SSM SecureString and referenced by `credentialRef`.
- Draft/browser payloads must not contain tokens, client secrets, private keys, or upstream URLs with embedded credentials.
- Auth profile registries must not contain raw secrets, tokens, client secrets, private keys, passwords, credentials, or API keys. Social IdP credentials are represented by SSM/Secrets Manager secret refs only.
- Public auth runtime config never includes social IdP secret refs or raw credentials.
- Provisioning plans are server-only and plan-only; this repo does not create Cognito, Google, Facebook, DynamoDB, S3, API Gateway, or IAM resources unless a future deploy is explicitly run.
- JWT authorization verifies RS256 tokens through JWKS, validates issuer, accepts either `aud` or Cognito access-token `client_id`, and then enforces tenant/group policy from the server-only profile.
- Protected integrations use server-only `access.required`, `access.authProfileId`, and optional `access.allowedGroups`; invalid or missing user JWTs return a generic `Unauthorized` response before any upstream call.
- Server-only integrations may configure safe static request headers through `headers`. Static `authorization`, `cookie`, `set-cookie`, and `x-api-key` headers are rejected so credentials keep flowing through `auth` and managed credential storage.
- Supported auth types are `bearer`, `api-key-header`, and `oauth2-client-credentials`. The OAuth2 client-credentials flow reads `clientId` and `clientSecret` fields from the configured secret by default, exchanges them at the policy-controlled `auth.tokenUrl`, and sends only the resulting bearer token upstream.
- The proxy rejects unknown `sourceId` or `actionId` values.
- The proxy rejects input fields not declared in server-only policy.
- `urlTemplate` placeholders must be declared in `allowedInputFields`, must receive scalar non-empty values, and are percent-encoded before the upstream request.
- The proxy rejects HTTP methods outside `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.
- Responses are filtered by `response.allowedFields`.
- Upstream failures return a generic public error.
- A public draft origin may request only its own draft domain. Managed aliases are accepted only when the private registry proves the alias belongs to the requested domain through canonical site metadata (`aliases`, `domains`, or `environmentAliases`) or `ALIAS#<alias>, sk=SITE`. `test.zoolandingpage.com.mx` and local QA origins may preview other domains.

See `instructions.md` for the complete contract.
