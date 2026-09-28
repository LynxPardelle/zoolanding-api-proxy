# Isolated first THN TEST runtime provisioning

This path adds the separate The Hair Narrative runtime to the observed native
TEST API stack without packaging or updating the three shared Lambda functions.
It does not associate a CloudFormation execution role, activate a registry
binding, create an owner, enable a writer, change DNS, or deploy production.

## Source promotion is not deployment

The optional repository variable `API_TEST_PROMOTION_SELECTION_JSON` selects
one source-only promotion with exactly `schemaVersion: 1`,
`mode: "thn-source-only"`, `devSha`, `devTree`, and `testBaseSha`. The three Git
coordinates must be full current hashes. They are checked against the fetched
dev tip/tree and first TEST merge parent after the existing exact two-parent
promotion guard. Duplicates, unknown fields, malformed or stale coordinates
fail before credentials. No selection preserves the ordinary delivery path.

A selected run still validates tests and SAM but produces no ordinary deployable
artifact and skips the AWS deployment job. Keep the selector until a subsequent
promotion/delivery has been reviewed; deleting it to bypass a failed check is
not an activation procedure. Production workflows are unchanged.

## Native extension and private evidence

`tools/thn_first_provisioning.py` uses the pinned SAM translator on reviewed
source, taking only the six generated THN resources and its GET/POST method AST.
The result contains one Lambda, its role, version, alias, two invoke permissions,
and one additional retained API deployment. The existing API body gains only
`/auth-v2/runtime-config`; the existing Prod stage changes only its deployment
pointer. All prior native resources and template content otherwise remain exact.
Six dedicated parameters, their condition, and activation rule are added.
Every new resource has retention policies. The original deployment is retained.

The two-file package must match `build_thn_auth_runtime_v2_artifact.py`'s exact
source inventory. Both it and the plan live in the existing private, versioned
TEST artifact channel. The package uses the owning stack's `thn-runtime/`
prefix and the canonical plan uses `first-provisioning/`. No shared package is
built. `prepare_plan` is read-only and returns **private** data; publication is a
separate authorized operation using clean, published tooling, existing channel
protections, create-only keys, encryption, and exact version/byte readback.
Never print the plan, selectors, templates, or raw SDK observations.

The plan binds the reviewed tooling SHA/workflow hash, account/stack, baseline,
original recovery record, versioned package and its digest, six activation
parameters, and exact composed native template digest. The original recovery
package is independently read and verified. The dedicated Auth TEST stack must
be stable, termination-protected and own both matching pool/client resources.
This identity check reads stack metadata only, not customer data. Other
activation gates remain separate.

## Manual verify, then execute

Use [First THN Runtime Provisioning Test](../.github/workflows/thn-first-provision-test.yml)
on the exact reviewed current two-parent TEST merge. It defaults to `verify`.
Public inputs contain only execution mode, tooling SHA/workflow hash and three
reviewed digests (plan, snapshot and current baseline). TEST secrets
`THN_FIRST_PLAN_REFERENCE_JSON` and `AWS_LIVE_SNAPSHOT_REFERENCE_JSON` each hold
exactly `bucket`, `key`, and non-null `versionId`. Neither is a public artifact.

Before credentials, the workflow validates its own bytes, clean Git source,
dispatch/TEST/owner identity, private-reference shape/channel, region and absence
of a service-role or ordinary parameter override. It then reads the exact private
versions twice and revalidates baseline, recovery bytes, package and Auth resource
identities. Verify does not create a change set or otherwise mutate AWS.

Execute requires the separately approved minimum recovery and runtime policies.
It creates an UPDATE change set **without RoleARN**, preserving the stack's
original capabilities and old parameter values. It accepts only seven Adds and
the exact API-body/stage-pointer modifications, rejects replacement/removal or
shared-code changes, compares both returned native templates, and reobserves
the baseline before execution. Final acceptance checks all old resources and
function configurations, new code/alias, parameters, stack settings, and deployed
API export. A failed check is never reported as successful activation.

## Recovery and remaining acceptance

First provisioning is not its own destructive undo. Retained resources are not
deleted automatically. Capture the resulting enabled runtime privately and use
the separate [retained close/reopen controller](thn-retained-runtime-routes.md)
for reviewed route shutdown/restoration while retaining state. Original shared
code recovery remains a separate [observed-byte operation](aws-live-snapshot-recovery.md).
Any partial failure requires a fresh resource inventory before another attempt.

Config-first delivery, dedicated Auth prerequisites, private-origin checks,
tenant/MFA/session/writer isolation, actual recovery drills, content withdrawal,
QA access closure, resource reconciliation and human owner onboarding must pass
before claiming the blog is active. Source tests or IAM simulation do not prove
that a live deployment has occurred or that effective provider access works.

## Local checks

Install `requirements-test.txt` (the production package requirements are unchanged),
then run the complete unit suite, `sam validate --lint`, and `sam build --no-cached`.
Tests exercise actual pinned SAM translation and synthetic SDK boundaries;
they do not call AWS or skip the native first-provisioning checks.
