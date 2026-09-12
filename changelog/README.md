# Changelog

This directory contains historical implementation, deployment, QA, and security evidence. It is intentionally outside the default agent read path. Use [../README.md](../README.md), [../instructions.md](../instructions.md), code, and tests for current behavior.

Keep new entries chronological, scoped to one change or operational pass, and timestamped in Central Time when a time is recorded. Do not store credentials, tokens, private keys, signed URLs, or customer data.

## Migrated history

- [Codex history migration, 2026-05-29 through 2026-06-18 CT](2026-05-29-to-2026-06-18-codex-history-migration.md) — events that had no dedicated changelog file; it also marks one contradictory historical AWS-state record as unresolved.

## Dedicated entries

- [2026-09-12 — Retained THN TEST runtime route controller](2026-09-12-thn-retained-runtime-routes.md)
- [2026-09-12 — Explicit AWS-observed TEST code recovery](2026-09-12-aws-observed-recovery.md)
- [2026-09-04 — TEST delivery and immutable rollback hardening](2026-09-04-test-delivery-hardening.md)
- [2026-09-07 — Isolated THN TEST selection and preflight](2026-09-07-thn-test-selection.md)
- [2026-09-04 — THN auth runtime v2 build boundary](2026-09-04-thn-auth-runtime-v2.md)
- [2026-08-31 — THN registry v2 live revision contract](2026-08-31-thn-registry-v2-live-revision.md)
- [2026-06-09 — Auth provisioning rollout and apply plan](2026-06-09-auth-provisioning-rollout-apply-plan.md)
- [2026-06-09 — Auth Cognito executor scaffold](2026-06-09-auth-cognito-executor-scaffold.md)
- [2026-06-09 — Auth provisioning production deploy](2026-06-09-auth-provisioning-production-deploy.md)
- [2026-06-09 — Auth apply readiness boundary and deploy](2026-06-09-auth-apply-readiness-boundary.md)
- [2026-06-09 — Guarded Cognito apply](2026-06-09-auth-cognito-apply-guarded.md)
- [2026-06-09 — Cognito apply reconciliation](2026-06-09-auth-cognito-apply-reconciliation.md)
- [2026-06-09 — Auth Cognito readiness deploy](2026-06-09-auth-cognito-readiness-deploy.md)
- [2026-06-10 — Auth IdP secret loader](2026-06-10-auth-idp-secret-loader.md)
- [2026-06-17 — JWT request authorizer](2026-06-17-jwt-request-authorizer.md)
- [2026-06-17 — Auth testing environment split](2026-06-17-auth-testing-environment-split.md) — the initial `/Test` endpoint evidence is superseded by the later `/Prod` stage correction in the migrated history.
- [2026-06-18 — Auth Cognito MFA provisioning](2026-06-18-auth-cognito-mfa-provisioning.md)
