# 2026-06-18 00:21 CT - Auth Cognito MFA Provisioning

- Added server-only auth profile support for Cognito MFA policy with `mfa.mode` and TOTP enablement.
- Added deterministic provisioning planning for `ensure-mfa-config`, including config-hash participation and active-profile repair behavior.
- Added guarded executor support for `cognito-idp:SetUserPoolMfaConfig` with sanitized execution output only.
- Fixed public `runtime.auth.session` emission so safe same-origin MFA challenge/setup/verify paths and the challenge CSRF cookie name reach Angular without exposing Cognito sessions or token material.
- Validation before final rollout: focused MFA provisioning tests passed, and full unittest suite returned `Ran 116 tests ... OK`.
