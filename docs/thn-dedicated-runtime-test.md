# Dedicated THN TEST runtime release

This is the implementation boundary for the approved
[design](thn-dedicated-runtime-test-design.md). It is prepared locally, not
deployed or activated. It creates only the standalone
`zoolanding-thn-auth-runtime-test` stack. The shared API stack, its functions,
and the protected-admin CloudFront distribution are out of scope here.

## Preconditions

- Promote the reviewed source to the API repository's `test` branch without
  selecting an ordinary shared-stack deployment. The dedicated workflow runs
  only by manual dispatch and defaults to `verify`.
- GitHub's default branch for this repository is `main`. Register the same
  workflow file there in a separate, reviewed workflow-only PR before manual
  dispatch; run it with `ref=test`. Do not merge the runtime implementation
  into `main` as a registration shortcut. The existing `main` CI may run on
  that workflow-only merge, but no production deployment workflow is present
  in the locally inspected `main` tree.
- Deploy the separately reviewed TEST identity from the infra repository.
  The GitHub caller must have the exact new-stack CloudFormation permission,
  read-back permission on the THN package prefix, and PassRole permission for
  only the dedicated CloudFormation execution role.
- Confirm the existing artifact bucket supports immutable object versions.
  Publish an exact two-file ZIP under the private THN runtime prefix and record
  its version ID and SHA-256. Do not use an unversioned key or print its body.
- Store one canonical private plan in the TEST Environment secret
  `THN_DEDICATED_RUNTIME_PLAN_JSON`. Its digest, source SHA, and template digest
  are manual-dispatch inputs. Set the role ARN in the TEST Environment variable
  `THN_DEDICATED_RUNTIME_CFN_ROLE_ARN`; the existing
  `SAM_ARTIFACTS_BUCKET` and `AWS_ROLE_ARN` variables are also required.
- Review the plan's descriptor, policy, Cognito public identifiers, package
  coordinates, and digest against the active TEST registry. The plan has a
  closed schema enforced by `tools/thn_dedicated_runtime_test.py`.

## Release sequence

1. Run local unit tests, `sam validate --lint` and the dedicated SAM build.
2. Dispatch `thn-dedicated-runtime-test.yml` with `verify`. The controller
   checks the exact TEST branch and repository, AWS account, private plan,
   source bytes, template hash, versioned package read-back, and absence of
   any existing stack. It performs no AWS write in this mode.
3. After reviewing that evidence, dispatch `create` once. It submits a native
   `CREATE` change set, rejects any non-addition or resource outside the
   dedicated template, then executes and verifies stack protection and the
   exact resource inventory. A failure requires inspection of that change
   set's events before another attempt; no automatic retry is configured.
4. Verify the endpoint and negative request cases. Only then update the
   exact private-admin runtime CloudFront behavior in a separate infra change
   set. Article writing remains disabled until owner-session, MFA,
   authorization, and public Journal checks pass.

The workflow does not upload a package, create a private plan, modify GitHub
settings, switch CloudFront, or enable authoring. Those are separate reviewed
steps. Its `verify` mode deliberately rejects an already-created stack; the
successful `create` run performs the post-create inventory check.
