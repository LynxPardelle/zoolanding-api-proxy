# 2026-06-17 CT - JWT Request Authorizer

- Declared `DraftJwtRequestAuthorizer` in SAM as a reusable API Gateway Lambda authorizer backed by `auth_service.jwt_authorizer_handler`.
- Required the `REQUEST` authorizer shape with `Authorization`, `x-zoolanding-domain`, and `x-zoolanding-auth-profile-id` identity headers.
- Disabled authorizer caching with `ReauthorizeEvery: 0` to avoid cross-domain or cross-profile authorization reuse.
- Hardened the handler so explicit `TOKEN` authorizer events are denied before auth registry lookup.
- Kept existing public API/auth endpoints public; future protected routes must opt in to this authorizer explicitly.
