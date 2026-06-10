# 2026-06-09 CT - Cognito Apply Reconciliation

- Added pre-create reconciliation for Cognito user pools using deterministic pool name plus Zoolanding ownership tags.
- Added pre-create reconciliation for public Cognito app clients using deterministic client name inside the reconciled user pool.
- Added fail-closed handling for same-name user pools that do not have matching `managedBy`, `domain`, `tenantId`, and `authProfileId` tags.
- Added retry coverage for DynamoDB `succeeded` operation-state write failures after Cognito user pool and public app client creation, proving retries reuse existing resources instead of duplicating them.
- Added `cognito-idp:ListUserPools`, `cognito-idp:ListUserPoolClients`, and `cognito-idp:ListTagsForResource` only to `AuthProvisioningExecutorFunction`.
- No deploy, no AWS calls, no real Cognito resources, no real social IdPs, and no secrets were created in this step.
