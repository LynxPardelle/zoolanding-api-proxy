# AWS-observed TEST code recovery — 2026-09-12 CT

Added an explicit owning `AWS-live-snapshot/v1` driver, a dispatch-only workflow
defaulting to verification, and focused boundary tests. The approved original
shared ZIP is verified through its existing immutable S3 version, exact bytes and
safe per-file hashes; historical Git source attribution remains unknown.

Current trusted tooling is independently pinned. Capture double-reads the
payload and projected live baseline. Recovery preserves current configuration,
parameters, resource identities, protection and role state; its explicit executor
uses exact change-set review, original/processed template comparison, pre-execute
drift checks and post-recovery checksum/readiness checks. Absence of a service role
is preserved rather than replaced with a configured role. No runtime, SAM or IAM
definition was changed, and existing GitHub release workflows stay strict.

The focused regressions were RED before implementation. Further RED/GREEN review
covered role absence, avoiding additional bucket-control requirements, CLI error
redaction, stack settings drift and changing provider response metadata.
Independent review additionally reproduced and fixed no-change success over
out-of-band Lambda code drift and capability acknowledgment changes, with
RED/GREEN tests through the actual CLI and provider-shaped state persistence. Full
owning regression, lint, fresh build and security evidence are local validation,
not a deployed release or recovery-record publication.

No commit, push, workflow dispatch, private snapshot publication, AWS mutation or
THN activation was performed. Operational permission review and separately
approved private publication remain required. Enabled-to-disabled retained-state
recovery remains an explicit, unimplemented separate design boundary.

See the [owning guide](../docs/aws-live-snapshot-recovery.md) for the exact contract.
