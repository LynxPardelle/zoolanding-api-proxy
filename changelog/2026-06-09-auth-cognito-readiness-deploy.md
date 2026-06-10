# 2026-06-09 CT - Auth Cognito Readiness Deploy

- Merged PR #10 into `main` as `2be60d0`.
- Deployed stack `zoolanding-api-proxy` in `us-east-1` with `AUTH_PROVISIONING_APPLY_ENABLED=false`.
- Preserved the exact provisioning caller ARN allowlist and configured live apply allowlists for `zoositioweb.com.mx` and `tenant-a`.
- Updated `samconfig.toml` so future deploys preserve the auth registry file name, provisioning state table, apply disabled flag, domain/tenant allowlists, and auth secret prefixes.
- Verified runtime auth for Zoosite still returns `enabled:false` through execute-api and the custom API domain.
- Verified unsigned provisioning requests return `403`, signed plan/dry-run work, and signed apply remains fail-closed with `501 apply-disabled`.
- Verified no Cognito user pools matching `zoosite` or `zoolanding` exist after the deploy.
- Real apply remains blocked because the live Google and Facebook provider credential refs are not present in AWS yet.
