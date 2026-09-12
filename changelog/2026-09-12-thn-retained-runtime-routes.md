# 2026-09-12 — Retained THN TEST runtime route controller

Local implementation only; dates are Central Time. Nothing in this entry
certifies a deployed route, permission, owner account or active blog.

- Added a separate manual, default-verification-only close/reopen path for the
  exact THN runtime GET/POST operations. Existing code recovery is unchanged.
- Preserve original resources and add one retained deployment per transition;
  bind native templates, physical inventory, live alias/version, functions,
  parameters, stage settings and unrelated routes before and after execution.
- Added regression checks for actual nested SAM conditions, alias drift,
  nested change sets, wrong state, unexpected modifications and failed
  postconditions. Exceptions remain sanitized.
- The private capture/version, closure-specific IAM verification, first
  no-broad-role forward release and live HTTP drill remain release gates.

See [the owning guide](../docs/thn-retained-runtime-routes.md).
