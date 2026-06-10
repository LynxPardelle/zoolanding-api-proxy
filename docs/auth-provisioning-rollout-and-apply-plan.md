# Auth Provisioning Rollout And Apply Plan

This document materializes steps 3, 4, and 5 for the auth provisioning work after PR #4 and PR #5 merged to `main`.

Current base evidence at authoring time:

- `origin/main`: `768fbb7afe2721f51a274935edd5ec4dbe4ec31e`
- Merge history includes PR #4: `841d83e Merge pull request #4 from LynxPardelle/codex/auth-cognito-provisioning-dry-run`
- Merge history includes PR #5: `768fbb7 Merge pull request #5 from LynxPardelle/codex/auth-cognito-executor-scaffold`
- Scope here is documentation only. No deploy, AWS CLI, CloudFormation, Cognito, SSM, Secrets Manager, or real secret/token work is approved by this document.

Update at 2026-06-09 21:04 CT:

- Code now includes a guarded Cognito apply implementation behind `AUTH_PROVISIONING_APPLY_ENABLED=false` by default.
- Apply requires exact caller ARN allowlist, explicit `planKey`, explicit `idempotencyKey`, optional domain/tenant allowlists, scoped social IdP secret refs, callback/logout URL ownership, per-operation DynamoDB state, and effective runtime activation state.
- This is still NO-GO for real Zoosite Cognito creation until the real Zoosite auth secret refs exist in AWS, the apply allowlists are final, and a separate approved deploy enables `AUTH_PROVISIONING_APPLY_ENABLED=true`.

Update at 2026-06-09 22:32 CT:

- Apply now reconciles Cognito user pools by deterministic pool name plus Zoolanding ownership tags before creation.
- Apply now reconciles public Cognito app clients by deterministic client name inside the reconciled user pool before creation.
- Same-name user pools without matching `managedBy`, `domain`, `tenantId`, and `authProfileId` tags fail closed instead of being adopted.
- Retry tests now cover DynamoDB `succeeded` state write failures after Cognito creates a user pool or app client; retry reuses the existing Cognito resource and does not duplicate it.
- This remains NO-GO for real Zoosite Cognito creation until the final live secret refs, apply allowlists, approved deploy, and post-deploy smoke evidence exist.

## Step 3: API Proxy Deploy Plan

Status: planned only, not executed.

The SAM stack is `zoolanding-api-proxy` in `us-east-1`. The checked-in `samconfig.toml` already targets that stack and region. The template exports these auth-relevant outputs:

- `ApiUrl`
- `AuthRuntimeConfigEndpoint`
- `AuthProvisioningPlanEndpoint`
- `AuthProvisioningExecutorEndpoint`
- `FunctionName`
- `AuthJwtAuthorizerFunctionName`

Recommended preflight before any future approved deploy:

```powershell
git status --short
git fetch origin
git log -1 --oneline origin/main
gh pr checks 4
gh pr checks 5
python -m unittest discover -s tests -p "test_*.py"
sam validate --lint
sam build --no-cached
```

Deploy command shape, for planning only:

```powershell
# NO EJECUTAR SIN APROBACION EXPLICITA.
sam deploy `
  --stack-name zoolanding-api-proxy `
  --region us-east-1 `
  --capabilities CAPABILITY_IAM `
  --parameter-overrides `
    ConfigTableName=<config-table-name> `
    ConfigPayloadsBucketName=<config-payloads-bucket-name> `
    AllowedCorsOrigins=<comma-separated-approved-origins> `
    SecretNamePrefix=<ssm-parameter-prefix> `
    AuthRegistryFileName=<auth-registry-file-name> `
    AuthProvisioningAllowedRoleNames=<comma-separated-approved-role-names> `
    AuthProvisioningAllowedRoleArns=<comma-separated-approved-role-arns> `
    LogLevel=<INFO-or-approved-level>
```

Required approvals and missing values before execution:

- Explicit deploy/AWS approval for this stack and region.
- Current post-merge `ApiUrl` or CloudFormation outputs from an approved deploy.
- Exact allowed IAM role names or ARNs for provisioning-plan and provisioning-executor access.
- Final approved values for all deploy parameters, especially CORS origins and auth registry file name.

Stop immediately if any of these occur:

- Validation or build fails.
- CloudFormation does not finish in `UPDATE_COMPLETE`.
- Unsigned provisioning access succeeds.
- Executor `apply` returns anything other than fail-closed `501` / `manual-review-required`.
- Executor `apply` is enabled without exact ARN, domain, tenant, current plan key, and current idempotency key controls.
- Runtime responses leak secrets, raw secret refs, tokens, or client secrets.
- Zoosite runtime auth returns `enabled: true` before activation is explicitly approved.
- CORS reflects an attacker or unapproved origin.

## Step 4: Post-Deploy Smoke Plan

Status: planned only, not executed. These checks require an approved deploy and a current API URL.

Minimum HTTP smoke coverage:

- `GET /auth/runtime-config`
- `POST /auth/runtime-config`
- `OPTIONS /auth/runtime-config`
- `POST /auth/provisioning-plan`
- `OPTIONS /auth/provisioning-plan`
- `POST /auth/provisioning-executor`
- `OPTIONS /auth/provisioning-executor`
- Unsigned provisioning request is denied.
- Signed IAM provisioning-plan request returns `200` with plan-only output.
- Signed IAM executor `dry-run` returns `200` with preview-only output.
- Signed IAM executor `apply` returns `501` while `AUTH_PROVISIONING_APPLY_ENABLED=false`.
- CORS allows only approved origins and does not reflect an attacker origin.
- Zoosite planned runtime remains `enabled: false`.
- Runtime and provisioning responses contain no `clientSecret`, no social IdP secret values, and no browser-exposed secret references.

Evidence to capture, with Central Time timestamps:

- Git SHA under test.
- Unit test and SAM validation/build output.
- SAM deploy and CloudFormation output only if deploy was explicitly approved.
- CloudFormation stack outputs including `ApiUrl` and auth endpoints.
- HTTP status codes, selected headers, and sanitized response bodies.
- Negative unsigned IAM provisioning evidence.
- Executor apply fail-closed evidence.
- Zoosite `enabled:false` evidence.
- CORS origin-isolation evidence.

Do not run these smoke tests in this task because no deploy/AWS approval was granted.

## Step 5: Real Cognito Apply Design

Status: partially implemented behind a disabled feature flag. Do not deploy with `AUTH_PROVISIONING_APPLY_ENABLED=true` or create real Cognito resources without a separate approved task that provides final allowlists and real server-side secret refs.

### Execution Boundary

Real apply uses a separate executor Lambda and IAM role. It must not run inside the public proxy Lambda that serves browser/runtime reads.

The apply role should have only the permissions required to:

- Read private config from S3 and DynamoDB.
- Write provisioning state and audit events to DynamoDB.
- Optionally write sanitized JSONL audit records to S3.
- Resolve scoped SSM/Secrets Manager/KMS secrets only during apply.
- Create, describe, list, update, and tag the required Cognito resources.

The apply role must not grant `Delete*`, `AdminCreateUser`, IAM, CloudFormation, Route53, or ACM permissions.

### Cognito Resource Model

Create a User Pool per draft/client/auth profile when strong isolation is required. The app client should be public with `GenerateSecret=false`, Authorization Code flow, and PKCE. Start with a Cognito prefix domain; custom domain work belongs in a later design because it introduces DNS and certificate ownership.

Provision these resource families idempotently:

- User Pool: list by deterministic name, verify Zoolanding ownership tags, fail closed on foreign same-name resources, create only when no owned match exists.
- Public App Client: list by deterministic name within the reconciled pool, verify it is public, update settings, create only when no match exists.
- User Pool Domain: describe by domain prefix before create and reject ownership conflicts.
- Groups: list existing groups before creating missing groups.
- Google, Facebook, and OIDC identity providers: describe provider before create/update.
- App Client supported provider updates after IdPs exist.

### State, Idempotency, And Runtime Status

Keep desired config in the registry and effective state in a new `AuthProvisioningState` DynamoDB model. Supported lifecycle statuses remain:

- `planned`
- `provisioning`
- `active`
- `suspended`
- `failed`

Runtime config must remain disabled except when effective state is `active`.

Use an operation ledger keyed by `operationKey` and idempotency key. The executor key includes a hash of `planVersion`, `planKey`, `mode`, and the sanitized config hash. Apply reads, compares, creates, updates, and resumes partial operations without duplicating resources. Failed operation records for the same idempotency key are retryable; succeeded operation records are terminal.

### Secrets

Resolve social IdP secret refs only in apply mode. Preflight all secret references before the first mutation. Reject placeholders. Never expose secret values, raw tokens, raw secret refs, or provider credentials in plan, dry-run, audit, logs, browser responses, or PR text.

`SecretNamePrefix` currently points at `zoolanding/api/`; real apply must reconcile that with `/zoolanding/auth/...` style auth refs before execution.

### Guardrails

Initial real apply should require all of these gates:

- `AUTH_PROVISIONING_APPLY_ENABLED=false` by default.
- Explicit allowlists for IAM role ARNs, domains, and tenants.
- Required `planKey`.
- Required executor `idempotencyKey`.
- Required prior dry-run audit event for the same sanitized config hash before enabling apply in production.
- Social IdP apply flag remains false until mappings and secret handling are verified.
- Callback and logout URL allowlists validated before mutation.
- Concurrency lock per domain/profile.

### Rollback

Version 1 should not delete Cognito resources. Rollback is logical:

- Mark status `suspended` or `failed`.
- Keep runtime disabled.
- Persist partial resource IDs.
- Resume or repair idempotently in a later approved operation.

### Tests Required Before Apply

Before enabling apply, keep or add tests for:

- Botocore Stubber coverage for Cognito, SSM/Secrets Manager, KMS, DynamoDB, and S3 interactions.
- Duplicate retry produces no duplicate resources. Covered locally with fake clients for user pool and public app client creation after DynamoDB `succeeded` state write failures.
- State/config mismatches block mutation.
- Partial operation resume.
- Secret preflight failure performs no mutation.
- No secret leaks in plan, dry-run, audit, logs, or runtime config.
- IAM templates have no wildcard write/admin/delete permissions.
- Callback and logout allowlists.
- Social provider details and attribute mappings.
- Concurrency locks.
- Non-destructive removal semantics.

### Known Gaps To Resolve First

- Hosted UI domain schema needs prefix/custom distinction.
- ProviderDetails and AttributeMapping schema needs durable validation.
- Botocore Stubber coverage should be added for the real boto3 request/response contracts beyond the fake-client unit tests.
- Live DynamoDB lock and retry behavior should be smoke-tested after an approved deploy with `AUTH_PROVISIONING_APPLY_ENABLED=false` first, then separately before enabling apply.
- Real Zoosite social IdP secret refs must exist in AWS under the approved tenant/profile scope before real apply.
- Final apply domain, tenant, and exact caller ARN allowlists must be approved before real apply.
- Removals must remain explicitly non-destructive in v1.
