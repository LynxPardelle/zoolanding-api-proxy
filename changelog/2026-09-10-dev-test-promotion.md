# 2026-09-10 - Reviewed dev-to-TEST promotion

- Corrected only the three source-ref comparisons in the ordinary TEST workflow
  from `main` to `dev`, matching the approved service promotion path.
- Preserved forced-push rejection, exact first and second parents, exactly two
  parents, complete tree equality, immutable artifacts, OIDC, deployment identity,
  change-set review and existing rollback/state-retention boundaries.
- Added real Bash/Git regression fixtures with local-only remotes and no inherited
  cloud credentials. They accept the exact dev merge and reject main, stale or
  substituted dev, altered trees, wrong parents, octopus/single-parent commits,
  wrong branch/SHA, and forced pushes. Temporary repositories are removed.
- Both the valid-dev acceptance and main-rejection tests failed before the fix;
  the complete relevant suites passed after it. GitHub supplies the separate
  Linux execution checks; local Windows skips are not counted as passes.
- No production workflow, runtime code, IAM, AWS resource, feature flag, other
  draft payload or private client data changed.
