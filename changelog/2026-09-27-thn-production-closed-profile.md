# THN production runtime discovery preparation

A closed server-owned logical production profile maps SAM prod explicitly to
production descriptor scope, production host, cookie namespace, registry key and
Content Hub resource identities. TEST remains pinned to its existing profile.
Production refuses TEST registry records and qa-only writers.

Offline projection is restricted to the three-resource dedicated runtime SAM
source; the shared public API cannot enter it. Production gets a separate alias
and server profile. Its stage remains Prod to preserve the existing route shape.
The Lambda package now seals the exact three runtime sources, including the
profile; TEST package guards still compare every file and source byte.

A credential-free exact native merge selector protects main source promotion.
No AWS credentials, package publication or deployment occur in that workflow.

Pending: production Environment/roles, IAM simulation, registry/Cognito proofs,
protected review/execution workflow and approved native creation inventory.

Production release supports retained native previews, exact digest execution, sealed package and prior-byte recovery, and independent general v1 review. Fresh source authority is checked before credentials and immediately before native changes. IAM simulations evaluate actual action/resource context rather than unrelated whole-policy context. Production operator grants remain closed behind exact human principal, MFA and separately reviewed native inventory; no TEST QA data or credentials are copied.

The production projection normalizes the REGIONAL endpoint to the current SAM
object shape required by cfn-lint 1.56.0. The complete native translation is
identical to the prior scalar form; the TEST source remains unchanged.

The protected source promotion now checks the parsed native merge commit
against GITHUB_SHA. This resolves the actual ShellCheck SC2034 unused-variable
failure and explicitly binds the head identity. Actionlint 1.7.12 with the CI
ShellCheck 0.9.0 validates every tracked workflow without suppressing checks.
