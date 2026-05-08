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

- This repo does not create or rotate real upstream API secrets.
- This repo does not deploy itself automatically.
- This repo does not expose `server/integrations.json` through runtime-read.
