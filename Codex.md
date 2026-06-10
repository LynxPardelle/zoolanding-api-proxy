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

## 2026-06-09 03:30 CT - Auth Runtime Production Deploy

- PR #2 (`feat: isolate auth runtime origins`) and PR #3 (`fix: treat missing S3 payloads as not found`) were merged to `main` and deployed to the `zoolanding-api-proxy` SAM stack in `us-east-1`.
- Always run `sam build --no-cached` before deploy or deploy the fresh `.aws-sam/build/template.yaml` explicitly. A first deploy from stale `.aws-sam` artifacts updated only Lambda code and did not add the Auth API Gateway routes.
- Final CloudFormation status was `UPDATE_COMPLETE`. API Gateway `yxp97qlog2` now has `GET`, `POST`, and `OPTIONS` for `/auth/runtime-config`; stack output `AuthRuntimeConfigEndpoint` is `https://yxp97qlog2.execute-api.us-east-1.amazonaws.com/Prod/auth/runtime-config`.
- CloudFront distribution `E28Y8KTE8ZVWY9` for `api.zoolandingpage.com.mx` now has `/auth/*` routed to `zoolanding-api-proxy-prod`, copied from `/api-proxy/*`, with managed caching disabled and origin request policy `Managed-AllViewerExceptHostHeader`.
- Live smoke through both raw execute-api and `https://api.zoolandingpage.com.mx` verified: `OPTIONS /auth/runtime-config` returns `200` with matching CORS; cross-domain configured origin returns `400` with `Origin is not allowed for requested domain`; exact Zoosite domain and `zoositioweb.com` alias reach Lambda and return controlled `404 Auth profile registry not found`.
- The earlier `404 Auth profile registry not found` evidence for Zoosite is now superseded by later live verification from the Zoosite subagent: `POST https://zoositioweb.com.mx/auth/runtime-config` with `{"domain":"zoositioweb.com.mx","authProfileId":"staff"}` returned `200`, `ok:true`, `auth.enabled:false`, `authProfileId:"staff"`. Cognito activation is still pending because the live profile remains non-active (`planned` / `enabled:false`), not because the registry is missing.

## 2026-06-09 18:06 CT - Auth Provisioning Plan Contract Hardening

- `/auth/provisioning-plan` remains server-only, plan-only, IAM-allowlisted, and non-mutating. No deploy, Cognito provisioning, Secrets Manager/SSM value reads, or AWS write calls are part of this contract.
- Provisioning plan requests now accept only `domain` and `authProfileId`; extra policy/secret-style request fields are rejected instead of ignored.
- Plan responses are now deterministic and versioned with `planVersion`, `planKey`, stable per-operation `operationKey`, and stable hashed `idempotencyKey` values so a future executor can resume safely without deriving its own keys.
- Plans now distinguish `planned`, `provisioning`, `active`, `suspended`, and `failed` explicitly. `planned` and `provisioning` return resumable operations toward `active`; `active` returns an explicit noop contract; `suspended` and `failed` return explicit manual-review contracts with runtime auth still disabled.
- The plan payload now carries domain, tenant, `authProfileId`, runtime public-client config, hosted UI details, expected post-activation outputs, group policy, and normalized social IdP metadata by reference only. Supported social provider normalization covers legacy `socialIdpSecretRefs` plus structured `socialIdentityProviders` entries for Google, Facebook, and OIDC-style providers without copying secret values.

## 2026-06-09 17:38 CT - Auth Cognito Executor Scaffold

- `/auth/provisioning-executor` is now scaffolded as a server-only IAM route in the SAM template, sharing the same signed-role allowlist posture as `/auth/provisioning-plan`.
- Executor requests accept only `domain`, `authProfileId`, `mode`, optional `planKey`, and optional 64-hex `idempotencyKey`; browser/server-supplied secret or override fields are rejected before registry loading.
- `mode: dry-run` regenerates the current Cognito plan, validates optional `planKey`, and returns sanitized operation previews plus deterministic audit/idempotency keys without secret refs or raw credential material.
- `mode: apply` intentionally fails closed with `501`, `manual-review-required`, and no operations. Real Cognito creation/update/delete remains pending explicit approval, implementation, validation, and future deploy.
- This pass stayed local-only: no deploy, no AWS/Cognito/API Gateway/IAM/DynamoDB/S3/SSM/Secrets Manager calls, no secrets/tokens added, and no push/PR.

## 2026-06-09 18:49 CT - Auth Provisioning Rollout And Apply Plan Docs

- `origin/main` was verified at `768fbb7afe2721f51a274935edd5ec4dbe4ec31e`, with PR #4 and PR #5 present in merge history.
- Steps 3, 4, and 5 are now documented in `docs/auth-provisioning-rollout-and-apply-plan.md`: API proxy deploy plan, post-deploy smoke plan, and future real Cognito apply design.
- This documentation pass did not deploy, call AWS, call Cognito, create real resources, read or write secrets, or add tokens.

## 2026-06-09 19:30 CT - Auth Provisioning Production Deploy

- After explicit deploy approval, `origin/main` at `409f8576f59b456aa58b15b826d21de7e41a3726` was deployed to the `zoolanding-api-proxy` SAM stack in `us-east-1` from the fresh `.aws-sam/build/template.yaml`.
- Preflight passed before deploy: `python -m unittest discover -s tests -p "test_*.py"` returned `Ran 65 tests ... OK`; `sam validate --lint` reported a valid template; `pip-audit -r requirements.txt` reported `No known vulnerabilities found`; `sam build --no-cached` succeeded.
- The first deploy command attempt did not create a changeset because SAM rejected an empty `AuthProvisioningAllowedRoleNames=` parameter. The successful deploy omitted that empty parameter and set `AuthProvisioningAllowedRoleArns` to the exact current IAM caller ARN for the deploy/smoke principal.
- CloudFormation completed with `UPDATE_COMPLETE`. The changeset added the `/auth/provisioning-executor` POST/OPTIONS Lambda permissions and a new API Gateway deployment, modified the API Gateway RestApi/Stage and both Lambda functions, and deleted the previous API Gateway deployment.
- Stack outputs now include `AuthProvisioningExecutorEndpoint=https://yxp97qlog2.execute-api.us-east-1.amazonaws.com/Prod/auth/provisioning-executor` in addition to the existing `ApiUrl`, runtime-config, provisioning-plan, and function-name outputs.
- Live raw execute-api smoke verified: Zoosite `GET` and `POST /auth/runtime-config` return `200`, `ok:true`, `auth.authProfileId:"staff"`, and `auth.enabled:false`; bad origin returns `400` with `Origin is not allowed for requested domain`; unsigned `POST /auth/provisioning-plan` and `/auth/provisioning-executor` return `403 Missing Authentication Token`; OPTIONS for provisioning-plan and provisioning-executor return `200`.
- Live signed IAM smoke verified with an exact allowlisted caller: `POST /auth/provisioning-plan` returns `200`, `mode:"plan-only"`, `status:"planned"`, and six operations; executor `mode:"dry-run"` returns `200`, `executionStatus:"preview-only"`, six operations, and no `secretRefs`; executor `mode:"apply"` returns `501`, `manual-review-required`, and zero operations.
- Live custom-domain smoke through `https://api.zoolandingpage.com.mx` verified: Zoosite runtime-config returns `200` with `auth.enabled:false`, `OPTIONS /auth/provisioning-executor` returns `200`, and unsigned `POST /auth/provisioning-executor` returns `403 Missing Authentication Token`.
- No Cognito user pools, app clients, Hosted UI domains, Google/Facebook IdPs, users, groups, or other Cognito resources were created. The deployed executor still keeps real apply closed with `501/manual-review-required`.

## 2026-06-09 20:00 CT - Auth Apply Readiness Boundary

- The next real Cognito apply step is not ready to mutate Cognito until the executor can bind idempotency to the full desired config, persist state/audit, and run behind a separate Lambda/role from the public proxy/runtime handler.
- Provisioning plans now use contract version `2026-06-10.v1` and include a sanitized `configHash`. `planKey` and per-operation idempotency are bound to that hash, so callback/logout URLs, groups, Hosted UI config, scopes, and social IdP reference changes create a new plan.
- Planned/provisioning profiles can now be planned before the real Cognito app client ID exists. Active profiles still require a real audience/clientId.
- The SAM template now separates `/auth/provisioning-executor` onto `AuthProvisioningExecutorFunction` and adds `AuthProvisioningStateTable` for future provisioning state/audit records. No Cognito write permissions are granted in this readiness step.
- Real Cognito resources should still not be created until a future apply implementation passes Cognito-specific tests and the social IdP secret preflight is ready.
- Verification at 2026-06-09 20:05 CT: `python -m unittest discover -s tests -p "test_*.py"` ran 69 tests OK; `sam validate --lint` reported the template is valid; `sam build --no-cached` succeeded; `pip-audit -r requirements.txt` reported no known vulnerabilities; the high-signal diff secret scan reported `NO_HIGH_CONFIDENCE_SECRET_MATCHES`.

## 2026-06-09 20:18 CT - Auth Apply Readiness Deploy

- Deployed `main` merge commit `9229f010c14a095c91e31afd33ef296265d4a4d8` to stack `zoolanding-api-proxy` in `us-east-1` with `AuthProvisioningApplyEnabled=false` and `AuthProvisioningAllowedRoleArns=arn:aws:iam::765932874577:user/ADMIN-AIM-CLI`.
- CloudFormation completed with `UPDATE_COMPLETE`. The changeset created `AuthProvisioningStateTable`, `AuthProvisioningExecutorFunction`, the executor IAM role, executor Lambda permissions, and a new API Gateway deployment; it removed the previous executor permissions from `ApiProxyFunction`.
- Stack outputs include `AuthProvisioningExecutorFunctionName=zoolanding-api-proxy-AuthProvisioningExecutorFunct-D4RqgVhOtoJt` and `AuthProvisioningStateTableName=zoolanding-auth-provisioning-state`.
- Live runtime-config smoke returned `200`, `ok:true`, `auth.authProfileId:"staff"`, and `auth.enabled:false` through both execute-api and `https://api.zoolandingpage.com.mx`. Bad origin `https://evil.example` returned `400` with `Origin is not allowed for requested domain`.
- Unsigned `POST /auth/provisioning-plan` and `POST /auth/provisioning-executor` returned `403 Missing Authentication Token`; OPTIONS for both provisioning endpoints returned `200`.
- Signed provisioning plan returned `200`, `planVersion:"2026-06-10.v1"`, `configHash:"a047d17beea7650d5a003919aceaa09e0ebc9dbd0ab2b502ce03e892e05a64cd"`, six operations, and social provider IDs `facebook` and `google`. The plan includes server-only `secretRefs` metadata, but the high-signal secret pattern check returned false.
- Signed executor `dry-run` returned `200`, `executionStatus:"preview-only"`, the same `configHash`, six operations, `mutationAttempted:false`, no `secretRefs`, and no high-signal secret matches. Signed executor `apply` returned `501`, `error:"Cognito executor apply is not implemented"`, `blockedReason:"apply-not-implemented"`, zero operations, and `mutationAttempted:false`.
- Read-only AWS verification returned `DEPLOYED_TEMPLATE_NO_COGNITO_IDP_ACTIONS`; `aws cognito-idp list-user-pools --max-results 60 --region us-east-1 --query "UserPools[?contains(Name, 'zoosite') || contains(Name, 'zoolanding')]"` returned `[]`. No real Zoosite/Zoolanding Cognito user pool was created in this step.

## 2026-06-09 21:04 CT - Guarded Cognito Apply Implementation

- Implemented real Cognito apply code behind `AUTH_PROVISIONING_APPLY_ENABLED=false` by default. Apply is still server-only and requires exact caller ARN allowlist, explicit current `planKey`, explicit current executor `idempotencyKey`, optional domain/tenant allowlists, scoped social IdP secret refs, and callback/logout URL ownership before mutation.
- The executor now preflights social IdP credentials before any Cognito mutation, rejects placeholder or cross-tenant secret refs, writes per-operation DynamoDB state, resumes already-succeeded operations, and writes effective runtime activation state only after all operations succeed.
- Runtime auth and JWT authorizer can read effective active state from `AuthProvisioningStateTable`, so a registry can remain `planned` while a completed apply provides active runtime values for the matching `configHash`.
- SAM grants Cognito and auth provisioning SSM/Secrets permissions only to `AuthProvisioningExecutorFunction`; `ApiProxyFunction` keeps its existing SSM read for upstream API credentials and also gets state-table `dynamodb:GetItem` for effective auth state.
- Subagent security review returned NO-GO for creating real Cognito yet. The remaining live blockers are real Zoosite social IdP secret refs in AWS, final apply domain/tenant allowlists, and an explicitly approved deploy with `AUTH_PROVISIONING_APPLY_ENABLED=true`.
- Verification at 2026-06-09 21:04 CT: `python -m unittest tests.test_auth_service` ran 47 tests OK; `python -m unittest discover -s tests -p "test_*.py"` ran 79 tests OK; `sam validate --lint` reported the template is valid; `sam build --no-cached` succeeded; `pip-audit -r requirements.txt` reported no known vulnerabilities; high-signal diff secret scan reported `NO_HIGH_CONFIDENCE_SECRET_MATCHES`.

## 2026-06-09 22:32 CT - Cognito Apply Reconciliation

- Closed the apply idempotency blocker found in review: the executor now lists Cognito user pools by deterministic name, verifies Zoolanding ownership tags, and only creates when no owned match exists.
- Public app clients are now listed by deterministic name inside the reconciled user pool before creation; matched clients are described, verified public, and updated instead of duplicated.
- Same-name user pools without matching `managedBy`, `domain`, `tenantId`, and `authProfileId` tags fail closed instead of being adopted.
- Operation state writes now allow retry from `failed` for the same idempotency path, while `succeeded` remains terminal. Local tests cover user pool and public app client retries after DynamoDB `succeeded` write failures.
- No deploy, no AWS calls, no real Cognito resources, no social IdP secrets, and no tokens were created in this reconciliation step.

## 2026-06-09 23:15 CT - Guarded Apply Production Readiness Deploy

- PR #10 was merged to `main` as `2be60d0`, then deployed to stack `zoolanding-api-proxy` in `us-east-1`.
- First deploy preserved `AuthProvisioningApplyEnabled=false` and the exact allowed caller ARN. A later corrected deploy set live apply allowlists to `AuthProvisioningApplyAllowedDomains=zoositioweb.com.mx` and `AuthProvisioningApplyAllowedTenants=zoosite`, matching the live plan tenant ID, still with apply disabled.
- CloudFormation completed `UPDATE_COMPLETE`. Stack outputs still include `ApiUrl=https://yxp97qlog2.execute-api.us-east-1.amazonaws.com/Prod`, `AuthProvisioningExecutorFunctionName=zoolanding-api-proxy-AuthProvisioningExecutorFunct-D4RqgVhOtoJt`, and `AuthProvisioningStateTableName=zoolanding-auth-provisioning-state`.
- Live runtime smoke returned `200`, `ok:true`, `auth.authProfileId:"staff"`, and `auth.enabled:false` through both execute-api and `https://api.zoolandingpage.com.mx`; bad origin `https://evil.example` returned `400`, `Origin is not allowed for requested domain`.
- Unsigned provisioning-plan and provisioning-executor POSTs returned `403`, `Missing Authentication Token`; OPTIONS for both endpoints returned `200`.
- Signed provisioning-plan returned `200`, `mode:"plan-only"`, `status:"planned"`, six operations, and config hash `a047d17beea7650d5a003919aceaa09e0ebc9dbd0ab2b502ce03e892e05a64cd`. Signed executor dry-run returned `200`, `executionStatus:"preview-only"`, six operations, `mutationAttempted:false`, no `secretRefs`, no `clientSecret`, and no auth ref prefix in the response.

## 2026-06-10 01:59 CT - Cognito apply permission fix

- Zoosite social IdP refs were removed in the draft, so the live provisioning plan for `zoositioweb.com.mx` / `staff` now has five Cognito-native operations, `socialIdentityProviderCount:0`, and no Google/Facebook/secret-ref material.
- First real apply attempt failed before creating the user pool: executor response reported `ensure-user-pool` failed with `AccessDeniedException`; CloudTrail for `CreateUserPool` reported missing `cognito-idp:TagResource` on `arn:aws:cognito-idp:us-east-1:765932874577:userpool/*`.
- `template.yaml` now includes `cognito-idp:TagResource` in the executor user-pool-scoped Cognito permissions because `CreateUserPool` with `UserPoolTags` requires that tagging permission.

## 2026-06-10 02:08 CT - Zoosite Cognito-native auth activated

- Deployed the `TagResource` IAM fix after `sam build`; the executor role update completed without replacement. Then signed executor `mode:"apply"` for `zoositioweb.com.mx` / `staff` returned `200`, `ok:true`, `executionStatus:"applied"`, and five succeeded operations: `ensure-user-pool`, `ensure-hosted-ui-domain`, `ensure-public-client`, `ensure-user-groups`, and `finalize-runtime-activation`.
- Real Cognito resources now exist in `us-east-1`: user pool `us-east-1_Pq5OCadbK`, public app client `16jb6ml9q5jdh6blj7f668fajp`, Hosted UI `https://zoosite-staff-planned.auth.us-east-1.amazoncognito.com`, and groups `zoosite-admin` / `zoosite-client`.
- Verified app client has no `ClientSecret`, supports only `COGNITO`, OAuth code flow, scopes `email`, `openid`, `profile`, and callback/logout URLs for `zoositioweb.com.mx` plus `zoositioweb.com`.
- After apply, redeployed `AuthProvisioningApplyEnabled=false`; stack parameter now reports `false`, and a signed apply attempt returns `501` with `blockedReason:"apply-disabled"` and zero operations.
- Runtime `POST https://api.zoolandingpage.com.mx/auth/runtime-config` from origin `https://zoositioweb.com.mx` returns `auth.enabled:true`, issuer `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Pq5OCadbK`, clientId `16jb6ml9q5jdh6blj7f668fajp`, no Google/Facebook refs, and no secret material.
- Production QA: `/acceso` and `/auth/callback` render `<main>`; `/mi-cuenta` redirects unauthenticated users to `/acceso`; Hosted UI login returns `200` with password fields and no Google/Facebook text in desktop/mobile Edge headless.
- Signed executor apply with apply disabled returned `501`, `error:"Cognito executor apply is disabled"`, `blockedReason:"apply-disabled"`, zero operations, `mutationAttempted:false`, and no secret refs or client secret.
- Read-only Cognito verification returned `[]` for user pools containing `zoosite` or `zoolanding`; no real Cognito resources were created.
- Current blocker for real apply: the live plan has Google and Facebook provider refs, but both provider credential refs are missing in AWS. Real apply must stay disabled until those real IdP credentials exist and pass non-placeholder preflight.
- Operational note: avoid `aws configure export-credentials --format env` in visible tool output; capture `--format process` output in memory instead. The earlier visible export output should be treated as a credential exposure and the local IAM access key should be rotated.

## 2026-06-10 00:00 CT - Zoosite Social IdP Secret Loader

- Added `tools/auth_idp_secret_loader.py` to check or upsert Zoosite Google/Facebook social IdP credentials into Secrets Manager refs `/zoolanding/auth/zoosite/staff/google` and `/zoolanding/auth/zoosite/staff/facebook`.
- The loader accepts credentials from local environment variables or hidden prompts, writes JSON with `clientId` and `clientSecret`, uses a temporary `file://` payload instead of putting secret values in AWS CLI arguments, and prints only sanitized provider/ref/action status.
- Live check mode confirmed both refs are still missing in AWS; no secret values were created, changed, or printed in this step.
- Zoosite external IdP redirect URI for Google/Facebook setup is `https://zoosite-staff-planned.auth.us-east-1.amazoncognito.com/oauth2/idpresponse`. Planned public callback URLs are `https://zoositioweb.com.mx/auth/callback` and `https://zoositioweb.com/auth/callback`; logout URLs are `https://zoositioweb.com.mx/acceso` and `https://zoositioweb.com/acceso`.
