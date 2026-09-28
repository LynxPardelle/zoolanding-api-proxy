# 2026-09-19 — THN dedicated runtime preparation

Prepared a separate TEST-only SAM template, manual verify-first release
controller, and exact source/package/change-set guards. The only Lambda package
files are the existing THN runtime handler and registry consumer. This local
implementation has not been promoted, deployed, or connected to the admin
front door. The shared API stack is unchanged.

Local verification: the complete API unit suite, dedicated SAM lint and build,
and focused release/workflow tests passed. Browser QA remains pending because
no route has been changed.
