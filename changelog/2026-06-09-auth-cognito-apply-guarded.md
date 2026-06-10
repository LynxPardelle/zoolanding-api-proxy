# 2026-06-09 CT - Guarded Cognito Apply

- Implemented guarded Cognito apply behind `AUTH_PROVISIONING_APPLY_ENABLED=false` by default.
- Added exact caller ARN, plan key, executor idempotency key, domain, tenant, callback/logout ownership, and scoped social IdP secret ref checks before mutation.
- Added non-destructive Cognito create/update operations for user pool, hosted UI domain, public app client, user groups, and social identity providers.
- Added DynamoDB per-operation state, resume of already-succeeded operations, and effective runtime activation state.
- Updated runtime config and JWT authorizer to read effective active auth state for the matching config hash.
- Updated SAM so only `AuthProvisioningExecutorFunction` receives Cognito and auth provisioning SSM/Secrets permissions; `ApiProxyFunction` keeps existing SSM read access for upstream API credentials and also receives state-table read access.
- Added fake-client tests for apply disabled, strict apply request validation, exact ARN enforcement, sanitized success, missing secret refs, missing secret values, cross-tenant secret refs, resume behavior, and effective runtime activation.
- No deploy, no AWS calls, no real Cognito resources, no real Google/Facebook IdPs, and no secrets were created in this implementation step.
