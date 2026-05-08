# Zoolanding API Proxy

Server-side API proxy for Zoolanding runtime drafts.

The Angular app calls:

- `POST /api-proxy/read` for configured read data sources.
- `POST /api-proxy/action` for configured mutable API actions.

The browser sends only `domain`, optional `pageId`, `sourceId` or `actionId`, and allowlisted input values. It never sends upstream URLs or credentials. The Lambda resolves the published server-only policy from `server/integrations.json`, loads credentials by `credentialRef` from AWS Secrets Manager, calls the upstream API, filters the response, and returns safe JSON.

## AWS Dependencies

- DynamoDB table: `zoolanding-config-registry`
- S3 bucket: `zoolanding-config-payloads`
- AWS Secrets Manager for `credentialRef` values
- API Gateway: `POST /api-proxy/read` and `POST /api-proxy/action`

## Local Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

The tests stub policy loading, upstream calls, and secrets. They do not call AWS and do not require real credentials.

## Local Harness

```powershell
$env:DRY_RUN = "1"
python .\local_test.py
```

## Deploy

Do not deploy or create secrets until the frontend and policy contract are reviewed.

```bash
sam deploy
```

The checked-in `samconfig.toml` targets `us-east-1`, stack `zoolanding-api-proxy`, and the production/testing browser origins. Localhost and 127.0.0.1 origins are accepted by the Lambda for local QA only.

## Security Model

- Secrets are stored only in AWS Secrets Manager and referenced by `credentialRef`.
- Draft/browser payloads must not contain tokens, client secrets, private keys, or upstream URLs with embedded credentials.
- The proxy rejects unknown `sourceId` or `actionId` values.
- The proxy rejects input fields not declared in server-only policy.
- The proxy rejects HTTP methods outside `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.
- Responses are filtered by `response.allowedFields`.
- Upstream failures return a generic public error.

See `instructions.md` for the complete contract.
