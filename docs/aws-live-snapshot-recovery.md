# Explicit AWS-observed TEST recovery

`tools/aws_live_snapshot.py` and the manually dispatched
`recover-aws-test.yml` workflow implement the separately selected
`AWS-live-snapshot/v1` contract. This is not a GitHub release or an implicit
fallback. The existing Deploy Test / Rollback Test workflows, artifact
verification, runtime handlers, SAM template, parameters, and IAM remain
unchanged. An expired or missing GitHub artifact still fails the GitHub path.

## Identity and private handling

The approved historical package is identified by its exact ZIP, object selector
and object-version hashes in the owning driver. It is the shared original payload
for `ApiProxyFunction`, `AuthProvisioningExecutorFunction`, and
`AuthJwtAuthorizerFunction`. Its Git source attribution is **not established**.
The record says `sourceAttribution: aws-observed` and forbids a source-SHA field.
`$LATEST` is mutable; it is never described as an immutable Lambda version.

The closed record binds:

- Current capture tooling: full commit SHA and LF-normalized workflow digest.
- Exact account, region, existing TEST stack identity and three logical/physical
  function identities; Lambda code checksums, revisions and configuration hashes.
- Original and Processed template hashes, complete parameter map, resource
  inventory, and projected stack settings, including existing role, protection,
  tags and notifications. Only transport metadata is excluded; unknown nested
  Lambda configuration fields remain part of the configuration digest.
- Original S3 bucket/key/version, ZIP length and digest, safe per-file inventory
  digest and file count. ZIP entries are hashed in memory, never extracted,
  rebuilt, imported or executed.

`capture(session, tooling)` reads the version-specific bytes twice and compares
two live baselines before returning the private record in memory. The public-safe
`summary(record)` contains only declared hashes/counts. The record, templates,
parameters, raw provider responses, resource selectors and environment contents
must never be printed, uploaded as public workflow artifacts, or written to local
evidence or source. Do not log a library plan or record.

Private publication is an independently authorized operation, not a side effect
of capture or verification. This tool does not publish a snapshot. Before a
workflow can consume one, the approved canonical JSON bytes must already exist
in the existing private TEST artifact channel under an exact immutable version.
The private environment secret `AWS_LIVE_SNAPSHOT_REFERENCE_JSON` contains only
the closed `bucket`, `key`, `versionId` reference; the bucket must match the
existing `SAM_ARTIFACTS_BUCKET` setting and the key must stay in this service's
TEST prefix. No private selector belongs in dispatch inputs. Version-specific
reads require the expected bucket owner and verify the selected digest twice.
New bucket-hardening permissions or changes are not prerequisites of this reader.

## Current tooling, never historical helpers

The workflow is dispatch-only and defaults to `verify`. It checks out the current
workflow commit, not the prior package or historical source. Before configuring
AWS credentials, `--check-workflow` requires the TEST ref, exact current Git SHA,
clean checkout, independently reviewed workflow digest, private reference and
closed operation. These checks run again before the operational entrypoint.
Every external action is commit-pinned. No build, packaging, artifact download or
public artifact upload occurs in this recovery workflow.

Dispatch inputs contain only `operation`, `tooling_sha`,
`tooling_workflow_sha256`, `snapshot_sha256`, and
`current_baseline_sha256`. The last digest binds a fresh reviewed **current**
baseline, not the historical baseline recorded before a deployment. Capture
tooling and recovery tooling may differ, but each is independently pinned and
the historical record digest remains exact. A local dirty worktree is not
reviewed published tooling and cannot pass the workflow boundary.

## Code-only recovery

Verification authenticates the record, exact prior bytes and current baseline,
then composes only the three original version-specific code pointers into the
current Original template. All other template fields remain identical. Every
current parameter uses `UsePreviousValue`; there is no parameter override input.
The plan remains in memory. All CLI success and failure outputs are sanitized.

Only explicit `execute` creates a TEST-only UPDATE change set. The driver reuses
the owning identity/parameter/no-removal/no-replacement reviewer and additionally
permits only non-replacing Code-property modifications of the three exact
existing functions. It compares the returned Original and Processed templates to
the exact expected compositions, re-reads the immutable bytes and live baseline,
then executes the exact returned change-set ARN. A failed review or read leaves
execution closed; it does not delete or retry a rejected change set.
A no-change result succeeds only when a fresh observation confirms that all three
ready functions already contain the approved target checksums; unchanged template
pointers cannot conceal out-of-band Lambda code drift.

An existing CloudFormation execution role is preserved exactly. If the baseline
has **no** role, the request omits `RoleARN`; an environment variable is not
authority to associate a role. Existing IAM must permit that unchanged-role
request. Existing CloudFormation capability acknowledgments are also preserved
exactly, including their absence. The driver never assumes another role or changes
IAM. Templates beyond
the CloudFormation inline-size limit fail closed rather than being uploaded to a
new channel. After execution, it verifies exact code checksums, retained settings,
parameters, inventory and all-Lambda readiness using the same readiness contract
as `smoke_test_stack.sh`.

The required existing reads are STS caller identity, CloudFormation
DescribeStacks/ListStackResources/GetTemplate, Lambda GetFunctionConfiguration,
and S3 GetObjectVersion for the exact approved package and private record. Capture
may use a current-object HEAD only to discover the already approved version;
payload reads always supply that exact version. Execute additionally requires
CreateChangeSet/DescribeChangeSet/ExecuteChangeSet on the existing TEST boundary.
Authorization must be verified with the real request context. A simulator result
with missing context alone is not proof of an effective-session denial.

## Explicit unresolved boundary: v2 disable

Code recovery cannot turn an enabled THN runtime off. It preserves
`EnableThnAuthRuntimeV2` and every current resource. The existing enabled-to-disabled
parameter transition removes conditional resources and is still rejected by the
unchanged no-removal guard. No alternative composer, route switch, registry
mutation, auth switch or IAM exception is implemented here.

A separate design would have to distinguish retained provisioning from API-route
exposure, demonstrate removal of only the approved GET/POST exposure while
retaining the Lambda, role, permissions and all shared contracts, and prove the
resulting processed-template/change-set and fail-closed smoke behavior. That is
an unimplemented proposal requiring explicit approval, not a recovery capability.

## Local verification

Run the full owning unit suite and SAM validate/build checks from the repository
README. `tests/test_aws_live_snapshot.py` exercises the real capture, private-reader,
composition, review, executor, workflow-context and CLI boundaries with synthetic
AWS transports. It covers metadata-only response changes, actual business drift,
original-byte identity, unsafe archives, explicit provenance, role absence,
parameter/resource preservation and the deliberate absence of a disable operation.
Offline tests never contact AWS. A source-only validation or in-memory live audit
does not publish a private record, close the operational permission gate, authorize
deployment, or activate THN.
