# 2026-06-17 - Auth testing environment split

- Added SAM parameters for stage name, runtime auth environment, and optional reuse of an existing provisioning state table.
- Added `samconfig.toml` `test` deploy profile for stack `zoolanding-api-proxy-test` with `ApiStageName=Test`, `AuthRuntimeEnvironment=test`, and CORS scoped to `https://test.zoolandingpage.com.mx`.
- Added optional auth profile `environmentClaim` support for Cognito custom attributes such as `custom:zoolanding_env`.
- Custom signup now derives the environment claim from the deployed Lambda stack instead of accepting browser-supplied environment policy.
- Signin, protected integration access checks, and `DraftJwtRequestAuthorizer` deny verified JWTs whose environment claim does not match the active stack.
- The Cognito executor can add the mutable environment custom attribute to an existing user pool when a plan declares `environmentClaim`.
- Active profiles with `environmentClaim` now produce a repair-only executor plan for `ensure-user-pool` and `ensure-user-environment-attribute`; this lets existing pools be updated without re-running Hosted UI/client/social provisioning.
- Repair-only applies skip social IdP secret preflight and do not rewrite effective runtime auth state unless the plan includes `finalize-runtime-activation`.
- Deployed/updated `zoolanding-api-proxy-test` in `us-east-1`; the stack exposes `https://11zpm6wug2.execute-api.us-east-1.amazonaws.com/Test`, runs with `AuthRuntimeEnvironment=test`, and keeps `AuthProvisioningApplyEnabled=false`.
- Production deploy preflight found that parameterizing `AWS::Serverless::Api.StageName` changes the SAM-generated API Gateway stage logical ID away from the existing `ApiProxyApiProdStage`; the production template keeps `StageName: Prod` literal to avoid replacing the live stage.
