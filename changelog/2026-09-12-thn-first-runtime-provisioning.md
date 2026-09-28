# 2026-09-12 — Isolated first THN TEST provisioning

Local implementation, not deployed activation:

- Added exact source-only dev/tree/TEST-base classification. Selected ordinary
  TEST runs have no deployable artifact or AWS deployment job; absence preserves
  the prior path.
- Added a private-plan, no-execution-role native first-provisioning controller
  and manual verify/execute workflow. Actual pinned SAM translation contributes
  only the THN function/role/version/alias/two permissions plus a retained API
  deployment; old resources and shared function artifacts remain exact.
- Added source/native/change-set/SDK/private-read/CLI regression checks. Test
  dependencies are separate from production requirements.
- No production, account, registry/writer activation, DNS, or live recovery
  claim is made by this source change. Those need separate accepted operations.

Current procedure: [first provisioning](../docs/thn-first-runtime-provisioning.md).

## Manual workflow registration follow-up

- Added a no-credential registration job on the existing delivery branch for
  recovery, first provisioning, and retained route operations. Every operational
  job now explicitly requires `workflow_dispatch`; its prior steps, permissions,
  inputs, concurrency, environment and immutable-source checks remain unchanged.
- Added regression checks for the exact registration branch, closed harmless
  registration job, and manual-only operational jobs. This reuses the existing
  Auth/Content Hub registration pattern without changing the default branch.
- Local verification: 265 tests, including two unchanged Windows skips;
  Actionlint, SAM lint, and a fresh SAM build passed. No AWS operation, TEST
  promotion, or runtime activation is implied by this registration change.
