# 2026-06-09 CT - Auth Apply Readiness Boundary

- Added sanitized `configHash` to Cognito provisioning plans.
- Bound `planKey`, executor idempotency, and operation idempotency to the sanitized desired config.
- Allowed planned/provisioning profiles to be planned before a real Cognito app client ID exists, while keeping active profiles strict.
- Split `/auth/provisioning-executor` onto a separate Lambda boundary in SAM.
- Added `AuthProvisioningStateTable` for future state/audit records.
- Kept real Cognito apply closed; this change does not grant Cognito write permissions or create Cognito resources.
