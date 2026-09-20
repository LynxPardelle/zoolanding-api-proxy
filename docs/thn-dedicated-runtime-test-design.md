# Dedicated The Hair Narrative runtime API in TEST

Date: 2026-09-19 (Central Time)
Status: Design approved; implementation pending written-spec review

## Purpose and boundary

Activate the existing The Hair Narrative Journal auth-runtime discovery contract without updating `zoolanding-api-proxy-test` or any of its three shared Lambda functions. The runtime discovery endpoint returns browser-safe public metadata, not a session or permission to author. Auth Admin and Content Hub remain the owners of private sessions, MFA, article authorization, and publication.

This design is TEST-only and domain-specific. It does not alter production, the public draft host, other drafts, shared API routes, registry ownership, or the Journal article data model.

## Decision

The API Proxy repository owns a separate CloudFormation/SAM stack for THN runtime discovery, with a new template and manual, default-verify workflow. The stack contains a regional REST API with exactly `GET` and `POST /auth-v2/runtime-config`, one Lambda using the already reviewed two-file THN runtime package, a dedicated least-privilege execution role, one published `test` alias, invoke permissions, and seven-day log retention. Its fixed TEST stage remains `Prod` to preserve the existing API Gateway proxy event shape and CloudFront origin-path convention. It has no reference to the shared API ID, deployment, stage, roles, or functions.

The Lambda keeps the current closed request contract: the exact THN domain and `journal-owner` auth profile, the approved admin `Origin`, the CloudFront-overwritten forwarded host, a strongly consistent read of the exact Content Hub service-binding registry key, and a secret-free public response. The panel's actual GET/POST and `Origin` behavior must be observed before cutover; the handler's origin check must not be weakened to accommodate a missing header. A direct caller can forge HTTP origin headers; this endpoint must therefore never be treated as the private authorization boundary. It returns only public metadata. Auth Admin's existing origin proof, MFA, session, and Content Hub authorization continue to protect the editor and mutations.

The existing protected-admin CloudFront distribution changes only its exact `/auth-v2/runtime-config` behavior to use the new API endpoint as an origin. The route inventory and origin-owner seal are updated for this route alone. Existing Auth Admin and Content Hub behaviors, the public distribution, and the shared API Proxy origin remain unchanged. No browser URL or draft payload changes.

## Why not the alternatives

- A narrow exception to the first-provisioning guard would allow the observed CloudFormation `Role` modifications on three shared functions, even though their templates compare equal. That is outside this design's isolation requirement.
- Moving discovery into Auth Admin would couple public metadata to the private session BFF and require updating an existing service for all its consumers.
- A Lambda Function URL would require a different event adapter and origin-protection model. The REST API keeps the reviewed handler contract and current CloudFront integration.

## Release sequence and failure behavior

1. Preserve the failed shared-stack attempt as evidence. Do not execute its change set, remove its guard, or repeat shared-stack provisioning. Retire its selector/workflow only after the replacement route and recovery procedure are established; retain immutable artifacts and data.
2. Build and test the dedicated stack locally. Its synthesized template must contain no reference to shared API resources or roles. The artifact may contain only the two approved THN runtime modules.
3. Verify the separate deployment identity and least-privilege permissions for stack creation, package read, logs, and the exact registry-key read. Do not reuse or broaden the shared-stack operator without a reviewed policy delta.
4. Create one `CREATE` change set for the new stack. Compare it with the reviewed template and reject any update/replacement/removal or resource outside the dedicated stack. Execute only after the review passes. Verify stack protection, function package/alias, endpoint methods, registry response behavior, and negative origin/coordinate cases.
5. Synthesize the frontend TEST change. Reject any delta outside the protected-admin distribution's exact runtime origin/behavior and its required validation/configuration. Deploy that change separately. Keep the public distribution and the other protected-admin backends unchanged.
6. Run one end-to-end smoke through the admin hostname: runtime discovery, sign-in/MFA/session for the designated owner, read and write authorization, image upload, and article create/edit/preview/publish/withdraw. Verify denial for unrelated users, public Journal EN/ES, and no regression in other draft routes. Enable THN writing only after the owner path passes.

Every gate fails closed. A failed change set or deployment is diagnosed from its own event/log evidence before another attempt; there is no automatic retry. Local checks precede a single targeted CI run per repository to limit GitHub Actions use.

## Acceptance and reversal

Acceptance requires: no shared-stack update; no shared Lambda or role changes; only the THN route pointed at the dedicated origin; browser-safe runtime response; owner-only private access; working authoring and public projection; and unaffected public/other-draft routes. An Actions success alone is insufficient.

For a runtime problem, disable THN writing first and restore the admin runtime route to its previously reviewed origin/closed state without deleting article data. The dedicated stack stays retained and protected while investigated. Do not delete shared or THN data resources. Cleanup of now-unused TEST IAM policy or old workflow selector is a separate reviewed change after the replacement has passed.

## Cost and scope note

This adds a separately metered REST API, Lambda execution, and logging; no always-on compute or new CloudFront distribution is planned. Actual charges depend on use and AWS pricing. GitHub Enterprise is not required; manual targeted workflows and local validation limit Actions consumption.
