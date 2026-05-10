# Zoolanding API Proxy

Server-side API proxy for Zoolanding runtime drafts.

The Angular app calls:

- `POST /api-proxy/read` for configured read data sources.
- `POST /api-proxy/action` for configured mutable API actions.

The browser sends only `domain`, optional `pageId`, `sourceId` or `actionId`, and allowlisted input values. It never sends upstream URLs or credentials. The Lambda resolves the published server-only policy from `server/integrations.json`, loads credentials by `credentialRef` from AWS Secrets Manager, calls the upstream API, filters the response, and returns safe JSON.

Parameterized read sources can use server-owned `urlTemplate` values, for example `https://pokeapi.co/api/v2/pokemon/{pokemonName}`. Template placeholders must also appear in `allowedInputFields`; the Lambda trims and percent-encodes those values, uses them only to resolve the upstream URL, and keeps all undeclared fields blocked.

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

The checked-in `samconfig.toml` targets `us-east-1`, stack `zoolanding-api-proxy`, and the platform production/testing browser origins. Localhost and 127.0.0.1 origins are accepted by the Lambda for local QA only. Published draft domains are accepted dynamically from the config registry, so adding a new draft domain does not require editing the API Gateway/Lambda CORS parameter.

## Credential Placeholder Workflow

Credential values are not stored in this repository. To add a new API credential, add only the secret name, required JSON field names, and non-sensitive tags to `secret-placeholders/credential-placeholders.json`, then create missing placeholders:

```powershell
python .\tools\ensure_secret_placeholders.py --dry-run
python .\tools\ensure_secret_placeholders.py --region us-east-1
```

The script creates only missing Secrets Manager entries under `zoolanding/api/` and does not overwrite existing secrets. After creation, open AWS Secrets Manager and replace the `__SET_IN_AWS_CONSOLE__` placeholders with the real values.

## Security Model

- Secrets are stored only in AWS Secrets Manager and referenced by `credentialRef`.
- Draft/browser payloads must not contain tokens, client secrets, private keys, or upstream URLs with embedded credentials.
- Server-only integrations may configure safe static request headers through `headers`. Static `authorization`, `cookie`, `set-cookie`, and `x-api-key` headers are rejected so credentials keep flowing through `auth` and Secrets Manager.
- Supported auth types are `bearer`, `api-key-header`, and `oauth2-client-credentials`. The OAuth2 client-credentials flow reads `clientId` and `clientSecret` fields from the configured secret by default, exchanges them at the policy-controlled `auth.tokenUrl`, and sends only the resulting bearer token upstream.
- The proxy rejects unknown `sourceId` or `actionId` values.
- The proxy rejects input fields not declared in server-only policy.
- `urlTemplate` placeholders must be declared in `allowedInputFields`, must receive scalar non-empty values, and are percent-encoded before the upstream request.
- The proxy rejects HTTP methods outside `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.
- Responses are filtered by `response.allowedFields`.
- Upstream failures return a generic public error.
- A public draft origin may request only its own draft domain. `test.zoolandingpage.com.mx` and local QA origins may preview other domains.

See `instructions.md` for the complete contract.
