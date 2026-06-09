# Codex Agent Memory

## 2026-05-29 CT - TIDAL Credential Migrated To SSM

- Runtime credential refs now use SSM SecureString parameters named `/{credentialRef}`. For `zoolanding/api/music/tidal`, the SSM parameter is `/zoolanding/api/music/tidal`.
- Existing TIDAL SecretString was copied to SSM without printing it. Old Secrets Manager secret `zoolanding/api/music/tidal` was scheduled for deletion with a 7-day recovery window.
- Deployed SAM stack `zoolanding-api-proxy` after tests and validation. The Lambda role now has app inline permissions for DynamoDB `GetItem`, S3 `GetObject`, and `ssm:GetParameter` on `parameter/zoolanding/api/*`; the deployed inline policy no longer grants Secrets Manager reads.
- Live smoke for `music.lynxpardelle.com` + `music-releases` returned `{"ok":false,"error":"Integration not found"}`, so the music/TIDAL integration is currently disabled/no-op rather than live.
- Keep browser payloads secret-free: `credentialRef` is allowed in server-only policy only; client bundles must not contain tokens, client secrets, or upstream credentials.

## 2026-06-08 CT - Auth Service Offline Scaffold

- `zoolanding-api-proxy` is the chosen home for the first real serverless Auth service scaffold because it already owns the runtime server-side API boundary, DynamoDB/S3 private policy loading, SSM credential-ref posture, CORS handling for managed draft origins, and "browser sends no secrets" contract.
- Auth profiles are loaded from published private payload path `server/auth-profile-registry.json`; runtime config is public metadata only, while provisioning plans are server-only, plan-only, and denied unless the signed IAM role name/ARN is explicitly allowlisted.
- JWT authorizer code is reusable for future protected blogs, dashboards, uploads, and actions. It verifies RS256 JWTs through JWKS, accepts either `aud` or Cognito access-token `client_id`, and enforces tenant/group policy from the server-only profile.
- No AWS, Cognito, Google, Facebook, API Gateway, IAM, or deployment command was run for this scaffold. The SAM template changes are declarative/offline until a future explicit deploy decision.

## 2026-06-09 CT - Auth Runtime Contract Hardening

- Public `/auth/runtime-config` output must stay compatible with the Angular `runtime.auth` contract: `authProfileId`, `provider`, `issuer`, `hostedUiDomain`, `clientId`, `scopes`, `redirectPath`, `logoutPath`, optional `loginPath`, `groupsClaim`, and `allowedGroups`.
- Public runtime-config accepts only `domain` and `authProfileId`; browser-supplied secret, policy, callback URL, JWKS, or tenant fields are rejected instead of ignored.
- Active auth profiles must include `tenantId`. Social IdP secret refs must be actual SSM/Secrets Manager-style references, not raw-looking strings.
- API proxy integrations can now protect individual sources/actions with server-only `access.required`, `access.authProfileId`, and optional `access.allowedGroups`; this is separate from the existing upstream credential `auth` block.
- Protected integrations verify the browser Bearer JWT before any upstream call and never forward that user JWT upstream. Upstream credentials still come only from `credentialRef` plus integration `auth`.
- Auth handlers must accept API Gateway stage-prefixed paths such as `/Prod/auth/runtime-config`, while dispatching internally to canonical `/auth/...` paths. The provisioning-plan POST method must stay protected by SAM `Authorizer: AWS_IAM` plus the Lambda role-name/ARN allowlist.

## 2026-06-09 00:43 CT - Local Auth Runtime QA Harness

- Local browser QA for optional remote auth can run through `local_auth_server.py` with `DRY_RUN=1` plus `LOCAL_AUTH_REGISTRY_DIR` or `LOCAL_AUTH_REGISTRY_FILE`; no registry path is hardcoded in runtime code.
- The local registry resolver reads server-only `auth-profile-registry.json` from the configured local source and bypasses DynamoDB/S3 only when the explicit dry-run env vars are present.
- `/auth/runtime-config` returns Angular-compatible, secret-free public auth metadata for both active and non-active profiles. Non-active profiles keep `enabled: false`; provisioning status and social IdP refs remain server-only.

## 2026-06-09 02:49 CT - Auth Runtime Origin Isolation

- Public `/auth/runtime-config` now checks browser `Origin` before loading a site's auth registry. Allowed origins are: missing origin for non-browser/public metadata reads, local QA origins, `test.zoolandingpage.com.mx`, the exact requested domain, or a managed alias proven by server-only registry metadata.
- Managed alias proof can come from canonical site metadata listing the alias in `aliases`, `domains`, or `environmentAliases`, or from the DynamoDB alias lookup shape `ALIAS#<alias>, sk=SITE` pointing back to the requested canonical domain.
- CORS managed-origin reflection also recognizes `ALIAS#<alias>, sk=SITE`, so a valid alias is not blocked by browser CORS after passing the Auth runtime guard.
- This remained an offline hardening pass only: no AWS calls, no Cognito changes, no deploy, and no secrets or tokens added.
