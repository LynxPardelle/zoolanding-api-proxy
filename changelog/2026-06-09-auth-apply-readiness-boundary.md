# 2026-06-09 CT - Auth Apply Readiness Boundary

- Added sanitized `configHash` to Cognito provisioning plans.
- Bound `planKey`, executor idempotency, and operation idempotency to the sanitized desired config.
- Allowed planned/provisioning profiles to be planned before a real Cognito app client ID exists, while keeping active profiles strict.
- Split `/auth/provisioning-executor` onto a separate Lambda boundary in SAM.
- Added `AuthProvisioningStateTable` for future state/audit records.
- Kept real Cognito apply closed; this change does not grant Cognito write permissions or create Cognito resources.

## Deploy Evidence

- Deployed merge commit `9229f010c14a095c91e31afd33ef296265d4a4d8` to `zoolanding-api-proxy` in `us-east-1` at 2026-06-09 20:10 CT with `AuthProvisioningApplyEnabled=false`.
- CloudFormation finished `UPDATE_COMPLETE` and created `AuthProvisioningExecutorFunction` plus `AuthProvisioningStateTable`.
- Live signed executor `dry-run` returned `200`, `executionStatus:"preview-only"`, `mutationAttempted:false`, six operations, no `secretRefs`, and no high-signal secret matches.
- Live signed executor `apply` returned `501`, `error:"Cognito executor apply is not implemented"`, `blockedReason:"apply-not-implemented"`, zero operations, and `mutationAttempted:false`.
- Deployed template check returned `DEPLOYED_TEMPLATE_NO_COGNITO_IDP_ACTIONS`; filtered read-only Cognito user pool query for `zoosite` or `zoolanding` returned `[]`.
