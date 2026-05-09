# Zoolanding API Proxy Contract

## Request Contract

`POST /api-proxy/read`

```json
{
  "domain": "music.lynxpardelle.com",
  "pageId": "default",
  "sourceId": "pokemon-list",
  "input": {
    "limit": 8
  }
}
```

`POST /api-proxy/action`

```json
{
  "domain": "music.lynxpardelle.com",
  "pageId": "default",
  "actionId": "newsletter-subscribe",
  "input": {
    "email": "listener@example.test",
    "language": "en"
  }
}
```

## Server-Only Policy

Published drafts can include `server/integrations.json` in the config payload bucket. Runtime-read must not expose this file to the browser.

```json
{
  "version": 1,
  "sources": [
    {
      "id": "pokemon-list",
      "method": "GET",
      "url": "https://pokeapi.co/api/v2/pokemon",
      "allowedInputFields": ["limit", "offset"],
      "response": {
        "allowedFields": ["count", "results"],
        "maxBytes": 524288
      }
    }
  ],
  "actions": [
    {
      "id": "newsletter-subscribe",
      "method": "POST",
      "url": "https://mailing.example.test/subscribe",
      "credentialRef": "zoolanding/api/music/newsletter",
      "auth": {
        "type": "bearer",
        "secretField": "accessToken"
      },
      "allowedInputFields": ["email", "language"],
      "response": {
        "allowedFields": ["status", "subscriberId"]
      }
    }
  ]
}
```

Auth options:

- `bearer`: reads `auth.secretField` from the Secrets Manager JSON object and sends `Authorization: Bearer <value>`.
- `api-key-header`: reads `auth.secretField` and sends it in the policy-controlled `auth.headerName`.
- `oauth2-client-credentials`: reads `auth.clientIdField` and `auth.clientSecretField` from the Secrets Manager JSON object, exchanges them at `auth.tokenUrl` with `grant_type=client_credentials`, and sends the returned bearer token upstream. The default field names are `clientId` and `clientSecret`.

Static request headers may be configured with `headers` when an upstream API requires non-secret metadata such as `Accept`. Do not put credentials there; `authorization`, `cookie`, `set-cookie`, and `x-api-key` are rejected.

## Creating Credential Placeholders

Use `secret-placeholders/credential-placeholders.json` as the repeatable inventory of API proxy credential placeholders. It stores only safe metadata: Secrets Manager name, expected JSON field names, description, and tags.

```powershell
python .\tools\ensure_secret_placeholders.py --dry-run
python .\tools\ensure_secret_placeholders.py --region us-east-1
```

The script is idempotent: existing secrets are left untouched so real values entered in the AWS console are not replaced. New secrets are created with placeholder JSON values such as:

```json
{
  "clientId": "__SET_IN_AWS_CONSOLE__",
  "clientSecret": "__SET_IN_AWS_CONSOLE__"
}
```

## Acceptance Criteria

- A single draft/site can configure multiple read sources and multiple actions.
- The browser cannot choose arbitrary upstream URLs.
- The browser cannot send undeclared input fields.
- The Lambda only resolves credentials by `credentialRef`.
- Secret values are never returned to the browser.
- Upstream errors are returned as generic public errors.
- The Lambda can represent `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.
- Real destructive actions require an authorization design before production enablement.

## Non-Goals

- This repo creates only placeholder Secrets Manager entries; it does not store, generate, or rotate real upstream credential values.
- This repo does not deploy itself automatically.
- This repo does not expose `server/integrations.json` through runtime-read.
