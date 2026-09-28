# 2026-09-04 — TEST delivery and immutable rollback hardening

- Added an exact `main`-to-`test` promotion workflow with unprivileged validation/build, commit-pinned actions, a full-SHA and full-inventory artifact manifest, and OIDC only in the protected `test` environment job.
- Kept THN runtime v2 disabled in ordinary deployment parameters and reviewed the exact CloudFormation change set before execution; every remove or replacement action fails closed.
- Added stack/Lambda readiness smoke checks and recorded the immutable source run, artifact ID, SHA, and manifest digest.
- Added manual rollback that accepts only a successful recorded TEST deployment and verifies its exact artifact before creating another reviewed nonreplacement change set.
- Verification passed with 157 tests and 112 subtests, Actionlint, Python and Bash syntax checks, SAM lint, dependency audit, and diff validation. No workflow was dispatched and no AWS, production, draft, or Zoosite state changed.
