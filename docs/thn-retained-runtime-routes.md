# Retained THN TEST runtime routes

This is an explicit close/reopen controller for only `GET` and `POST`
`/auth-v2/runtime-config`. It is separate from
[AWS-observed code recovery](aws-live-snapshot-recovery.md) and ordinary SAM
deployment. Source availability is not proof of deployed permissions, successful
recovery, owner access or an active blog.

## Required state

Use only a stable, independently reviewed TEST stack with THN v2 already
provisioned, `EnableThnAuthRuntimeV2=true`, and no associated CloudFormation
service role. The native API must use the existing `Prod` stage (the verified
SAM stage name inside TEST), the retained `test` Lambda alias/version, and
exactly the supported GET/POST definitions. Missing resources, a different
stage/alias, merge mode, unsupported conditions or an associated role stop the
operation. Do not enable the ordinary runner's broader role to pass this gate.

## Private record and workflow inputs

`tools/thn_runtime_routes.py` exposes `observe`, `capture`, `compose` and
`transition` for the owning operator/tests. `observe` and `capture` return
**private in-memory values**: never print them or put them in a GitHub artifact.
The capture seals the exact original method definitions, native resources,
physical inventory, function configurations, live alias version, stage settings,
parameters and unrelated deployed routes. It reads the baseline twice.

The controller does not publish a capture or create storage. Before dispatch,
independently review and persist the canonical capture in the existing approved
private versioned channel. Configure `THN_RETAINED_ROUTES_REFERENCE_JSON` as a
private TEST secret with exactly `bucket`, `key` and non-null `versionId`.
The bucket must equal `SAM_ARTIFACTS_BUCKET`; the key must match
`zoolanding-api-proxy-test/retained-routes/<safe-name>.json`. Never copy real
selectors or contents into a command example, issue or public run input.

The manual workflow [Retained THN Routes Test](../.github/workflows/thn-retained-routes-test.yml)
defaults to `operation=close`, `execution=verify`. Its remaining inputs are
public digests only: current TEST tooling commit, LF-normalized workflow hash,
canonical private record hash and freshly reviewed current baseline hash.
It verifies exact checkout, clean tree, repository/ref and workflow hash before
AWS credentials. It uses the existing TEST concurrency group; no automatic
trigger enables, closes or reopens routes. The record is read back twice by its
exact immutable version and owner.

## Exact permitted transition

Close removes the two methods and their otherwise empty path entry. Reopen
restores their captured AST, including supported nested SAM conditions. Either
operation adds one deterministic retained API deployment and changes only the
existing stage's deployment pointer. Every old deployment, function, role,
permission, alias, version, parameter and unrelated API property remains intact.
An existing transition identifier or wrong open/closed state is rejected.

Before execution, the native change set must contain exactly two non-replacing
property modifications and one deployment addition. Both returned template
stages must equal the composed native template. Nested changes, removal,
replacement, drift or role adoption stop execution. The inline native template
is limited to 51,200 bytes; larger templates require a separately reviewed
private transport rather than automatic public upload.

Readback verifies both native templates, retained physical resources, unchanged
function/configuration and live alias version, stage settings, and exported
deployed methods. `apiDefinitionVerified=true` proves that readback only; it is
not HTTP smoke, MFA or owner-publication proof. Complete independent HTTP checks
of both THN methods and unchanged v1 routes before claiming a live drill.

## Permissions and release gates

The minimal code-recovery IAM policy does **not** authorize this controller's
separate record or route transitions. Before first use, review exact versioned
record reads, metadata reads and provider-evidenced, CloudFormation-mediated
changes restricted to the existing API/stage and new deployments under that
API. No API deletion/creation, IAM mutation or broader role adoption is allowed.
Denied provider behavior is a stop condition, not permission to widen scope.

First THN provisioning remains a separate forward-release review. In particular,
this controller is not usable on the pre-THN stack and does not correct or
authorize the ordinary runner that supplies the excluded broad role.

Failures/timeouts produce sanitized reasons. They do not delete change sets,
deployments or resources, remove termination protection, retry with more
authority, or silently claim rollback. Reconcile the actual stack before retry;
retain the original record and previous immutable deployments. Reopening routes
does not enable the registry, writer or customer account.

## Local verification

```powershell
python -m unittest discover -s tests -p "test_thn_runtime_routes.py"
python -m unittest discover -s tests -p "test_*.py"
```

The focused suite runs actual controller decisions with synthetic service
transports. It does not call AWS. Source/build validation and synthetic native
SAM translation must remain distinct from a reviewed live change-set drill.
