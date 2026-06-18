# Zoolanding API Proxy

Server-side API proxy for Zoolanding runtime drafts.

The Angular app calls:

- `POST /api-proxy/read` for configured read data sources.
- `POST /api-proxy/action` for configured mutable API actions.
- `GET` or `POST /auth/runtime-config` for public, config-driven auth metadata.
- `POST /auth/signin`, `/auth/signup`, `/auth/confirm-signup`, `/auth/resend-confirmation`, `/auth/forgot-password`, and `/auth/confirm-forgot-password` for optional custom generic auth forms.
- `POST /auth/provisioning-plan` for server-only, plan-only Cognito provisioning output.
- `POST /auth/provisioning-executor` for server-only Cognito executor dry-run and guarded apply.

The browser sends only `domain`, optional `pageId`, `sourceId` or `actionId`, and allowlisted input values. It never sends upstream URLs or credentials. The Lambda resolves the published server-only policy from `server/integrations.json`, loads credentials by `credentialRef` from SSM SecureString, calls the upstream API, filters the response, and returns safe JSON.

Auth profiles are resolved from the published server-only file `server/auth-profile-registry.json`. The runtime auth endpoint accepts only `domain` and `authProfileId`, enforces that the browser `Origin` belongs to the requested domain or to a managed alias for that domain, then returns the same public `runtime.auth` shape validated by the Angular app. Requests from the shared testing host or a configured environment alias resolve `publishedEnvironments.test` instead of production `published`, so testing can exercise draft auth changes without changing production auth policy. Active profiles return `enabled: true`; planned, provisioning, suspended, and failed profiles return the same secret-free public metadata with `enabled: false`. The provisioning endpoint is denied by default, accepts only `domain` and `authProfileId`, and returns only a server-only, plan-only contract when the caller's signed IAM role is explicitly allowlisted by `AUTH_PROVISIONING_ALLOWED_ROLE_NAMES` or `AUTH_PROVISIONING_ALLOWED_ROLE_ARNS`.

Public runtime auth session metadata may include same-origin BFF paths such as sign-in, account, logout, MFA challenge, voluntary MFA enrollment, and voluntary MFA disablement paths. These fields are only routing metadata for Angular; Cognito tokens, tenant/group policy, TOTP setup secrets, and auth-admin state remain server-only.

Custom auth form endpoints are optional per auth profile. They require the server-only profile to be active and to enable the matching `customAuth` policy before calling Cognito. Browser requests may send only public form inputs such as email, password, confirmation code, language, `domain`, and `authProfileId`; tenant claims, default groups, user pool IDs, billing boundaries, and runtime environment are resolved from the server-only profile and Lambda stack. The signup endpoint can set the configured tenant claim, optionally set the configured environment claim such as `custom:zoolanding_env`, and add only server-approved default groups from `allowedGroups`. Signin uses Cognito `USER_PASSWORD_AUTH` and returns only sanitized public session metadata after JWT issuer/audience/tenant/environment/group validation; it does not return ID, access, or refresh tokens. Responses return sanitized statuses and code-delivery metadata only.

Provisioning plans are deterministic and versioned. The response includes a stable `planVersion`, `planKey`, sanitized `configHash`, lifecycle status, runtime public-client shape, hosted UI data, expected post-activation outputs, normalized social IdP references, optional Cognito MFA policy, and per-operation `operationKey` plus `idempotencyKey` values for the executor. `planKey` and operation idempotency are bound to the sanitized desired config, so callback URLs, logout URLs, groups, hosted UI config, scopes, MFA policy, and social provider reference changes produce a new plan. `planned` and `provisioning` return resumable operations; `active` returns either an explicit noop plan or repair operations for declared drift-sensitive policy such as MFA configuration; `suspended` and `failed` return explicit manual-review plans. No raw social credentials, secret values, tokens, or browser-supplied policy fields are accepted or returned.

The executor endpoint is server-only and deployed on a separate Lambda boundary from the public proxy/runtime handler. It accepts only `domain`, `authProfileId`, `mode`, optional `planKey`, and optional `idempotencyKey`. `mode: "dry-run"` regenerates the current plan, validates the optional plan key, and returns a sanitized deterministic preview plus audit event without social secret refs or tenant secret material. `mode: "apply"` is implemented but disabled by default through `AUTH_PROVISIONING_APPLY_ENABLED=false`; when enabled it requires an exact caller ARN allowlist, explicit `planKey`, explicit `idempotencyKey`, optional domain/tenant allowlists, scoped social IdP secret refs, callback/logout URL ownership, and the DynamoDB state table. Apply reconciles Cognito user pools by deterministic name plus Zoolanding ownership tags, public app clients by deterministic name inside that pool, and optional TOTP MFA configuration before creating resources. It uses non-destructive create/update Cognito operations and persists effective runtime state; it does not delete Cognito resources.

Parameterized read sources can use server-owned `urlTemplate` values, for example `https://pokeapi.co/api/v2/pokemon/{pokemonName}`. Template placeholders must also appear in `allowedInputFields`; the Lambda trims and percent-encodes those values, uses them only to resolve the upstream URL, and keeps all undeclared fields blocked.

Server-only `server/integrations.json` entries can protect individual sources/actions with an `access` block. `access` verifies the browser JWT against the server-only auth profile registry before the proxy calls upstream. Existing integration `auth` blocks remain reserved for upstream API credentials.

The SAM stack also publishes `DraftJwtRequestAuthorizer`, a reusable API Gateway Lambda authorizer for future protected endpoints. It is intentionally configured as a `REQUEST` authorizer so API Gateway sends `Authorization`, `x-zoolanding-domain`, and `x-zoolanding-auth-profile-id` together. Its cache TTL is `0` to avoid cross-domain, cross-profile, or cross-environment authorization reuse until a tenant-safe cache key is designed. Existing public endpoints do not use it by default.

## AWS Dependencies

- DynamoDB table: `zoolanding-config-registry`
- DynamoDB table: `zoolanding-auth-provisioning-state` for provisioning operation state and effective runtime activation state
- S3 bucket: `zoolanding-config-payloads`
- SSM Parameter Store SecureString for `credentialRef` values
- API Gateway: `POST /api-proxy/read`, `POST /api-proxy/action`, `GET|POST /auth/runtime-config`, `POST /auth/provisioning-plan`, `POST /auth/provisioning-executor`, and the reusable `DraftJwtRequestAuthorizer`. The executor route must remain IAM-authorized.
- Cognito public app-client APIs for optional custom auth forms: InitiateAuth, SignUp, ConfirmSignUp, ResendConfirmationCode, ForgotPassword, ConfirmForgotPassword, plus AdminAddUserToGroup for server-approved signup default groups.
- Cognito provisioning executor API for optional TOTP MFA reconciliation: SetUserPoolMfaConfig.
- Cognito custom user attribute `custom:zoolanding_env` or a profile-specific equivalent when a draft shares one user pool across testing and production users.
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

The auth provisioning rollout, post-deploy smoke plan, and future real Cognito apply design are documented in [docs/auth-provisioning-rollout-and-apply-plan.md](docs/auth-provisioning-rollout-and-apply-plan.md). That document is planning-only unless a future task explicitly approves deploy/AWS/Cognito execution.

```bash
sam build --no-cached
sam deploy
```

Deploy the non-production Lambda stack with the `test` SAM environment. It uses the same config registry and provisioning state table, but runs as its own stack/API ID with `AuthRuntimeEnvironment=test` and CORS restricted to `https://test.zoolandingpage.com.mx`. The API Gateway stage path remains `/Prod` in both stacks because SAM-generated logical IDs for the live production stack depend on the literal `Prod` stage name:

```bash
sam build --no-cached
sam deploy --config-env test
```

The checked-in `samconfig.toml` targets `us-east-1`, stack `zoolanding-api-proxy` for production and `zoolanding-api-proxy-test` for testing. Both expose a `/Prod` API Gateway stage, but they remain isolated by stack name, API ID, Lambda environment variables, CORS, and `AUTH_RUNTIME_ENVIRONMENT`. Localhost and 127.0.0.1 origins are accepted by the Lambda for local QA only. Published draft domains are accepted dynamically from the config registry, so adding a new draft domain does not require editing the API Gateway/Lambda CORS parameter.

## Credential Placeholder Workflow

Credential values are not stored in this repository. New credentials should use SSM SecureString parameters under `/${credentialRef}`. To add a new API credential, add only the credential reference, required JSON field names, and non-sensitive tags to `secret-placeholders/credential-placeholders.json`, then create missing placeholders:

```powershell
python .\tools\ensure_secret_placeholders.py --dry-run
python .\tools\ensure_secret_placeholders.py --region us-east-1
```

The legacy script creates only missing Secrets Manager entries under `zoolanding/api/` and does not overwrite existing secrets. Prefer creating a matching SSM SecureString parameter such as `/zoolanding/api/music/tidal`; after creation, replace `__SET_IN_AWS_CONSOLE__` placeholders through AWS-managed secret tooling, not in repo files.

Zoosite social auth credentials use server-only Secrets Manager refs under `/zoolanding/auth/zoosite/staff/{provider}`. The loader reads values from environment variables or hidden prompts and writes only sanitized status output:

```powershell
# Optional check: reports existence/shape only, never values.
python .\tools\auth_idp_secret_loader.py --mode check --provider all

# Non-interactive load. Set these only in the local shell, never in files or PR text.
$env:GOOGLE_CLIENT_ID = "<google OAuth client id>"
$env:GOOGLE_CLIENT_SECRET = "<google OAuth client secret>"
$env:FACEBOOK_CLIENT_ID = "<facebook app id>"
$env:FACEBOOK_CLIENT_SECRET = "<facebook app secret>"

python .\tools\auth_idp_secret_loader.py --mode upsert --provider all --dry-run --no-prompt
python .\tools\auth_idp_secret_loader.py --mode upsert --provider all --no-prompt
python .\tools\auth_idp_secret_loader.py --mode check --provider all

Remove-Item Env:\GOOGLE_CLIENT_ID, Env:\GOOGLE_CLIENT_SECRET, Env:\FACEBOOK_CLIENT_ID, Env:\FACEBOOK_CLIENT_SECRET
```

The expected refs are `/zoolanding/auth/zoosite/staff/google` and `/zoolanding/auth/zoosite/staff/facebook`, each stored as JSON with `clientId` and `clientSecret`. The loader uses a temporary `file://` secret payload so the secret values are not passed as command-line arguments.

For the Zoosite Cognito pilot, configure Google and Facebook OAuth apps with this external IdP redirect URI before loading credentials:

```text
https://zoosite-staff-planned.auth.us-east-1.amazoncognito.com/oauth2/idpresponse
```

The planned public app client callback URLs are `https://zoositioweb.com.mx/auth/callback` and `https://zoositioweb.com/auth/callback`; logout URLs are `https://zoositioweb.com.mx/acceso` and `https://zoositioweb.com/acceso`.

## Security Model

- Credentials are stored in SSM SecureString and referenced by `credentialRef`.
- Draft/browser payloads must not contain tokens, client secrets, private keys, or upstream URLs with embedded credentials.
- Auth profile registries must not contain raw secrets, tokens, client secrets, private keys, passwords, credentials, or API keys. Social IdP credentials are represented by SSM/Secrets Manager secret refs only.
- Public auth runtime config never includes social IdP secret refs or raw credentials.
- Public auth runtime config may expose `session.mfaDisablePath` only as a same-origin path. It must not expose whether a specific user has MFA enabled or any token/setup material.
- Custom auth form endpoints reject unsupported browser fields instead of accepting tenant/group/user-pool policy from the client.
- Custom signup may set tenant attributes, environment attributes, and default groups only from the server-only profile `customAuth.signup` policy plus the Lambda stack environment; password recovery uses only the profile public app client.
- When a profile declares `environmentClaim`, signin, protected integrations, and the reusable JWT authorizer require the verified JWT claim to match the deployed `AUTH_RUNTIME_ENVIRONMENT`. This allows one Cognito user pool to hold testing and production users for a draft while preventing cross-environment access.
- Provisioning plan requests accept only `domain` and `authProfileId`; secret-looking or policy-style browser/server payload fields are rejected instead of ignored.
- Provisioning plans are server-only and plan-only; dry-run does not create Cognito, Google, Facebook, DynamoDB, S3, API Gateway, or IAM resources.
- Provisioning executor requests accept only `domain`, `authProfileId`, `mode`, `planKey`, and `idempotencyKey`; `dry-run` is preview-only and `apply` remains disabled unless `AUTH_PROVISIONING_APPLY_ENABLED=true` is deployed with exact ARN, domain, and tenant guardrails.
- Apply resolves social IdP credentials only from scoped `/zoolanding/auth/{tenantId}/...` SSM/Secrets Manager references, rejects placeholders, performs preflight before mutation, and never returns raw secret refs or secret values.
- JWT authorization verifies RS256 tokens through JWKS, validates issuer, accepts either `aud` or Cognito access-token `client_id`, and then enforces tenant/group policy from the server-only profile. API Gateway wiring must use the declared `REQUEST` authorizer shape, not `TOKEN`, because the authorizer requires domain and auth profile headers.
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
