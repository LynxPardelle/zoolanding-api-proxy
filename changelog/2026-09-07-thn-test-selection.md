# Isolated THN TEST selection — 2026-09-07 (Central Time)

Local implementation only; not deployed or activated.

- Added a complete, optional six-parameter THN selection to the existing TEST
  release preparation tool. Omission retains the original parameter map.
- Rejected shared/unknown fields, non-TEST envelopes, duplicate keys, invalid
  identifiers, oversized input, and incomplete runtime activation.
- Added an account/region/dependency preflight using bounded, read-only AWS CLI
  queries with sanitized errors. It creates no files or cloud resources.
- Both immutable TEST deploy and rollback paths run that preflight after
  credentials and before change-set creation. Existing promotion, artifact,
  IAM, removal/replacement, and smoke controls are preserved.
- Runtime handlers, templates, default SAM configuration, other drafts and
  browser behavior remain unchanged. Owner enrollment and working blog
  creation/editing/publication are not completed by this delivery change.

Regressions were observed failing before implementing selection and preflight.
Exact local checks are retained in the ignored hub evidence. Old recovery
artifacts without the new contract remain ineligible for this selection.
A supplied selection requires a packaged-tool capability check before
credentials; a legacy artifact is rejected instead of silently ignoring it.
Disabling an existing conditional runtime is still blocked by the unchanged
no-removal guard and needs a separately reviewed recovery transition.
