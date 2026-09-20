# THN dedicated runtime plan reuse (TEST)

The dedicated runtime release now derives its closed selection in memory from
the previously verified, versioned first-provisioning plan. Its reviewed digest
is pinned in the release controller. The package remains the same exact
two-module ZIP; no new artifact or dedicated plan secret is required.

The manual workflow still checks the TEST source SHA, dedicated template hash,
AWS account, package digest and source bytes, Auth Admin Cognito ownership, and
absence of an existing dedicated stack before a `CREATE` change set. It does
not deploy the shared API stack. This is local source preparation only until
the dedicated workflow is reviewed and promoted to TEST.
