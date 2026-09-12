# 2026-08-31 — THN registry v2 live revision contract

## Scope

- Removed the artifact-supplied expected registry revision from the dormant THN
  v2 registry consumer and its TEST-only API Proxy adapter.
- Kept the code-owned table/key, immutable descriptor coordinates, full closed
  record validation, exact AWS resource scope, and strongly consistent read.
- The live row's `registryRevision` must still be a positive integer, but a
  valid N to N+1 transition no longer requires a new consumer artifact.
- Every call performs a fresh `GetItem`; no local registry cache or copy was
  added. Existing v1 routes and dispatch remain unchanged.

## Verification

- Focused v2 consumer suite: 15 tests passed.
- Full offline suite: 131 tests passed.
- Regression coverage accepts sequential revisions 7 and 8 from the same
  artifact and rejects malformed, zero, negative, and boolean row revisions.

No push, deployment, AWS mutation, Cognito change, or v1 route change was
performed.
