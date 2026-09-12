# TEST CloudFormation execution role — 2026-09-07 (Central Time)

DeployTest and RollbackTest pass the environment variable `AWS_CLOUDFORMATION_ROLE_ARN` to the change-set runner. Before packaging, the runner rejects an unexpected role name, AWS account, region, or stack. CloudFormation receives that role explicitly.

Artifacts now use the exact `zoolanding-api-proxy-test/<commit>/<run>/<attempt>` prefix, matching the scoped IAM foundation. Arbitrary artifact prefix overrides are no longer accepted.

The `test` environment has `AWS_ROLE_ARN`, `AWS_CLOUDFORMATION_ROLE_ARN`, `AWS_REGION`, and `SAM_ARTIFACTS_BUCKET` configured. OIDC trust requires this repository, environment `test`, and branch `test`. No static AWS credentials were added.

This is a deployment prerequisite, not a deployment or THN activation. The shell guard is exercised against fake AWS and SAM programs on Linux; the complete existing unit suite runs without network access in GitHub Actions. Actual OIDC exchange, service permissions, deployment smoke checks, and rollback remain to be validated in TEST.

Before the first release using this contract, build and validate a recovery release with the new runner and prefix. Do not use an older rollback artifact blindly: it can omit the execution role or write to the previous prefix. CloudFormation service-role association persists once used; omitting the flag does not undo that association. Preserve the existing branch promotion and change-set review controls.

