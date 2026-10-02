# 2026-10-02 — Production API prerequisite MFA fingerprint

The approved private API execution run 37047304179 stopped before applying its CloudFormation change set with `production_baseline_changed`. The change set remained `AVAILABLE` and the dedicated stack remained `REVIEW_IN_PROGRESS` with no resources.

The prerequisite capture hashed the full `GetUserPoolMfaConfig` response, including botocore `ResponseMetadata`. A different request ID changes that hash even when Cognito MFA settings are identical. The release compares this hash in the sealed baseline, so a later execution could not match the review.

The capture now removes only `ResponseMetadata` after checking MFA is enabled. A regression test performs two captures with identical settings and different request IDs; it failed before the correction and passed after it. The full local suite passed: 335 tests, 2 skipped.

The prior review digest cannot be reused after a source change. Promote this fix through the protected code path, create a fresh review, inspect its inventory, and request approval of the new digest before execution.
