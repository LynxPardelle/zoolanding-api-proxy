# 2026-09-04 — THN auth runtime v2 build boundary

- Added a separate, default-off `GET|POST /auth-v2/runtime-config` Lambda for the dedicated The Hair Narrative TEST admin origin.
- Required exact browser request coordinates, exact origin/forwarded host, reviewed descriptor inputs, public Cognito identifiers, and one strongly consistent read of the Content-Hub-owned registry item.
- Returned only Angular-compatible public auth metadata, closed `/auth-v2/session/*` paths, and deterministic CSRF names. Private registry, tenant, writer, session, account-purpose, credential, token, and TOTP fields remain excluded.
- Granted the new function only `dynamodb:GetItem` on the exact registry table/key and kept every shared v1 function free of THN registry environment variables and permissions.
- Added a Makefile artifact builder whose output allowlist contains only the v2 handler and registry consumer.
- Kept activation disabled in ordinary SAM environments. No AWS, API Gateway, Cognito, DNS, route, registry, draft, GitHub workflow, or writer state was changed.
- Verification: focused tests, the full 150-test API Proxy suite, Python compilation, SAM lint validation, isolated reproducible SAM builds, built-artifact import, exact two-file artifact inventory, and OSV dependency audit passed.
