# Zoolanding API Proxy Agent Guide

Use this file as the repository entrypoint for agents and contributors.

## Read order

1. Read [README.md](README.md) for current service behavior, security boundaries, local commands, and deployment posture.
2. Read [instructions.md](instructions.md) for the exact request, policy, auth-profile, and acceptance contracts.
3. Read [docs/auth-provisioning-rollout-and-apply-plan.md](docs/auth-provisioning-rollout-and-apply-plan.md) only when work touches Cognito provisioning or rollout design.
4. Read [changelog/README.md](changelog/README.md) only when implementation, deployment, QA, or incident history matters. Changelog entries are evidence, not the current contract.

`Codex.md` is only a compatibility pointer; it is not required after this file.

## Shared contracts

- API-proxy data sources: https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/15-runtime-api-proxy-data-sources.md
- Auth profile registry: https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/17-auth-profile-registry.md
- Fleet ownership: https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md

The hub owns cross-repository payload contracts. This repository remains canonical for implementation, service trust boundaries, deployment, and rollback; keep the critical security rules below available locally.

## Non-negotiable boundaries

- Browser input must never choose upstream URLs, credentials, secret refs, tenant/group policy, or provisioning policy. Resolve those from server-only configuration.
- Never store or print raw credentials, tokens, private keys, social IdP secrets, signed URLs, or customer data. Repository examples use placeholders and secret references only.
- Do not deploy, mutate AWS/Cognito, or create/update secrets without explicit approval for that operation. A dry run does not authorize apply.
- Keep public runtime responses secret-free. Provisioning and executor routes remain server-only and IAM-protected; Cognito apply remains disabled by default.
- If code and documentation disagree, verify runtime behavior before updating the current contract. Put dated implementation or release evidence in `changelog/`, not here or in `Codex.md`.

## Verification

Run the smallest relevant tests, with the full suite as the default closeout:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

For SAM or deployment-surface changes, also run `sam validate --lint` and `sam build --no-cached` when SAM is available. Report missing tools; never treat a skipped check as passing. Unit tests must not call live AWS services.
