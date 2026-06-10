# 2026-06-09 CT - Auth Cognito Executor Scaffold

- Added a server-only `/auth/provisioning-executor` scaffold route for future Cognito provisioning execution.
- The route is declared with SAM `AWS_IAM` auth and uses the existing signed IAM role-name/ARN allowlist checks.
- `dry-run` regenerates the current `/auth/provisioning-plan` contract, validates optional `planKey`, and returns sanitized operation previews plus deterministic audit/idempotency keys.
- `apply` is explicit but fails closed with `501` and `manual-review-required`; no Cognito resources are created, updated, or deleted.
- Request allowlist is limited to `domain`, `authProfileId`, `mode`, `planKey`, and `idempotencyKey`; secret-looking or override fields are rejected before registry loading.
- This change is local-only. No deploy, AWS calls, real Cognito calls, secrets/tokens, push, or PR were performed.
