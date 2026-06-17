# 2026-06-17 CT - JWT Request Authorizer

- Declared `DraftJwtRequestAuthorizer` in SAM as a reusable API Gateway Lambda authorizer backed by `auth_service.jwt_authorizer_handler`.
- Required the `REQUEST` authorizer shape with `Authorization`, `x-zoolanding-domain`, and `x-zoolanding-auth-profile-id` identity headers.
- Disabled authorizer caching with `ReauthorizeEvery: 0` to avoid cross-domain or cross-profile authorization reuse.
- Hardened the handler so explicit `TOKEN` authorizer events are denied before auth registry lookup.
- Kept existing public API/auth endpoints public; future protected routes must opt in to this authorizer explicitly.
- Deployed merged PR #14 to the `zoolanding-api-proxy` stack in `us-east-1`; CloudFormation completed `UPDATE_COMPLETE`.
- Verified live API Gateway authorizer `DraftJwtRequestAuthorizer` is `REQUEST`, uses the three expected identity headers, and has TTL `0`.
- Verified Zoosite runtime-config still returns `auth.enabled:true`, unsigned provisioning executor remains `403`, and a fake `TOKEN` authorizer event returns a `Deny` policy without token echo.
