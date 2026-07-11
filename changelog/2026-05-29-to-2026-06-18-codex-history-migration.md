# Codex History Migration — 2026-05-29 through 2026-06-18 CT

This file preserves useful chronology that existed only in `Codex.md` at repository commit `2f3e530880cabdd5a2b7c0b836d96b4f6090582a`. Events that already had a dedicated changelog file are not repeated here.

These records are historical evidence, not current runtime truth. Use `README.md`, `instructions.md`, code, and tests for the current contract.

## 2026-05-29 CT — TIDAL credential migrated to SSM

- Runtime credential references moved to SSM SecureString parameters under `/{credentialRef}`; the TIDAL reference became `/zoolanding/api/music/tidal`.
- The previous Secrets Manager value was copied without printing it, then scheduled for deletion with a seven-day recovery window.
- The deployed Lambda role moved from Secrets Manager reads to scoped `ssm:GetParameter` access for `parameter/zoolanding/api/*`.
- Live music integration smoke returned `Integration not found`, so the integration remained disabled rather than silently using credentials.
- Browser payloads remained secret-free; `credentialRef` stayed server-only.

## 2026-06-08 CT — Auth service offline scaffold

- This repository became the initial server-side home for draft auth because it already owned private policy loading, credential references, managed-origin CORS, and the browser-no-secrets boundary.
- Auth profiles used the private published path `server/auth-profile-registry.json`; public runtime config exposed metadata only.
- Reusable RS256/JWKS JWT verification and tenant/group policy were scaffolded for future protected routes.
- This pass was offline only: it did not call AWS/Cognito, create resources, or deploy.

## 2026-06-09 CT — Auth runtime contract hardening

- Public runtime config was aligned with Angular's `runtime.auth` shape and restricted to `domain` plus `authProfileId` input.
- Active profiles required a tenant, while social providers remained reference-only through server-side secret refs.
- Integration-level `access` policy was separated from upstream credential `auth`; browser JWTs were verified but never forwarded upstream.
- Stage-prefixed API Gateway paths were normalized to canonical internal auth paths.
- Provisioning-plan POST remained IAM-protected and role-allowlisted.

## 2026-06-09 00:43 CT — Local auth runtime QA harness

- `local_auth_server.py` gained dry-run registry loading through explicit `LOCAL_AUTH_REGISTRY_DIR` or `LOCAL_AUTH_REGISTRY_FILE` configuration.
- Local registry resolution bypassed deployed DynamoDB/S3 only when the dry-run variables were present.
- Planned/non-active profiles returned secret-free public metadata with `enabled:false`; provisioning details and IdP refs stayed server-only.

## 2026-06-09 02:49 CT — Runtime origin isolation

- Runtime-config began checking browser `Origin` before loading a site's auth registry.
- Exact domains, local QA origins, the shared testing host, and aliases proven through private metadata or `ALIAS#<alias>, sk=SITE` were allowed.
- CORS reflection used the same managed-alias proof.
- This hardening pass was offline only and made no AWS changes.

## 2026-06-09 03:30 CT — Auth runtime production deploy

- The origin-isolation and missing-S3-payload fixes were merged and deployed to the production SAM stack.
- A stale `.aws-sam` build initially omitted new API routes; rebuilding with `sam build --no-cached` and deploying the fresh template corrected the stack.
- API Gateway and the custom API domain received the auth runtime routes with caching disabled for `/auth/*`.
- CORS and origin-isolation smoke passed. A later Zoosite check superseded the initial missing-registry result and returned a controlled disabled auth profile.
- Test-origin registry resolution was later directed to `publishedEnvironments.test`; production origins continued to use `published`.

## 2026-06-09 18:06 CT — Provisioning-plan contract hardening

- Provisioning requests were restricted to `domain` and `authProfileId`.
- Plans gained deterministic version, plan, operation, and idempotency keys plus explicit lifecycle behavior for planned, provisioning, active, suspended, and failed profiles.
- Responses carried sanitized desired configuration and social-provider references without resolving secret values.
- No deploy or mutation occurred in this contract pass.

## 2026-06-10 01:59 CT — Cognito apply permission correction

- The first real apply attempt failed before user-pool creation because `CreateUserPool` with tags also required `cognito-idp:TagResource`.
- The executor's user-pool-scoped IAM permissions were updated to include that action.
- The live plan at that time had no social IdP operations because the draft's Google/Facebook refs had been removed.

## 2026-06-10 02:08 CT — Zoosite Cognito-native auth activation

- After the tagging permission fix, guarded apply reported five successful Cognito-native operations: user pool, hosted UI domain, public app client, groups, and runtime activation.
- Verification recorded a public client without a client secret, Cognito-only identity provider support, authorization-code flow, and approved callback/logout URLs.
- Apply was disabled again after activation; subsequent apply requests failed closed with `apply-disabled`.
- Runtime and browser QA recorded enabled Zoosite auth plus expected unauthenticated redirects and Hosted UI rendering.
- The original note also contained a contradictory later claim that a filtered user-pool query returned no matching resources and that no resources were created. That contradiction is preserved as unresolved historical evidence; do not use this entry as current AWS-state proof.
- The same work recorded that credential export output had been exposed visibly and recommended rotating the affected local IAM access key. No credential value is preserved here.

## 2026-06-16 11:49 CT — Optional custom auth form endpoints

- Added optional public Cognito self-service endpoints for sign-in, sign-up, confirmation, resend, and password recovery.
- Each endpoint remained disabled unless the private active auth profile enabled its matching `customAuth` policy.
- Tenant claims, environment claims, default groups, pool policy, and billing boundaries remained server-owned; browser payloads carried only public form input.
- The public proxy received only the Cognito actions needed for these flows. This implementation pass did not deploy or mutate AWS.

## 2026-06-17 04:48 CT — Auth admin runtime metadata

- Runtime config gained public-safe same-origin session/admin route metadata for Angular while admin groups, tenant mutation policy, credentials, JWTs, and Cognito state remained private.
- Auth-admin authorization stayed in the dedicated BFF through HttpOnly session cookies, CSRF, and draft/profile context.
- Optional environment claims were enforced across sign-in, protected integrations, and the reusable request authorizer.
- Active profiles could produce repair-only plans for the Cognito custom environment attribute without re-running full provisioning.
- A separate testing stack was created with apply disabled; later stage-path evidence is recorded below.

## 2026-06-17 CT — Auth registry token-policy metadata

- The private-registry secret scanner explicitly allowed the policy key `allowedTokenUses` while continuing to reject raw token, secret, password, credential, and client-secret material.

## 2026-06-17 16:55 CT — Testing API proxy stage correction

- The testing stack retained its own API ID, testing environment, and CORS policy, but its deployed API Gateway stage path was corrected to `/Prod`, not `/Test`.
- The literal `Prod` SAM stage remained necessary because parameterizing it changed generated logical IDs and could conflict with the live production stage.

## 2026-06-17 23:17 CT — Provisioning-state PITR

- The shared server-only provisioning-state table was designated for DynamoDB point-in-time recovery.
- Production remained the CloudFormation owner; the test stack referenced the table as existing.

## 2026-06-18 01:20 CT — Voluntary MFA runtime metadata

- Runtime config gained safe same-origin paths and a CSRF cookie name for voluntary MFA enrollment.
- Cognito tokens, setup secrets, tenant/group policy, and BFF state remained server-only.

## 2026-06-18 03:42 CT — MFA disable runtime metadata

- Runtime config gained a same-origin MFA-disable path as routing metadata only.
- Actual disablement remained an auth-admin BFF operation requiring an active session, CSRF, current password, and current TOTP code.

## 2026-06-18 16:44 CT — Admin MFA reset runtime metadata

- Runtime config gained an admin MFA-reset path template as public-safe same-origin routing metadata.
- Authorization remained in the auth-admin BFF through HttpOnly sessions, admin-group checks, CSRF, and self-reset prevention.
- Cognito tokens, TOTP material, admin policy, tenant policy, and secrets remained private.
