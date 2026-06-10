# 2026-06-09 CT - Auth Provisioning Production Deploy

- Deployed `origin/main` at `409f8576f59b456aa58b15b826d21de7e41a3726` to the `zoolanding-api-proxy` SAM stack in `us-east-1` after explicit approval.
- Preflight passed: 65 unit tests, SAM lint, `pip-audit`, and `sam build --no-cached`.
- CloudFormation finished `UPDATE_COMPLETE` and now exports `AuthProvisioningExecutorEndpoint`.
- Raw execute-api and `https://api.zoolandingpage.com.mx` smoke verified Zoosite runtime auth remains `enabled:false`.
- Unsigned provisioning plan/executor POST requests remain blocked with `403`.
- Signed IAM smoke verified provisioning plan `200`, executor dry-run `200`, and executor apply fail-closed `501/manual-review-required`.
- No Cognito resources, social IdPs, users, groups, secrets, or tokens were created.
