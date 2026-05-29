# Codex Agent Memory

## 2026-05-29 CT - TIDAL Credential Migrated To SSM

- Runtime credential refs now use SSM SecureString parameters named `/{credentialRef}`. For `zoolanding/api/music/tidal`, the SSM parameter is `/zoolanding/api/music/tidal`.
- Existing TIDAL SecretString was copied to SSM without printing it. Old Secrets Manager secret `zoolanding/api/music/tidal` was scheduled for deletion with a 7-day recovery window.
- Deployed SAM stack `zoolanding-api-proxy` after tests and validation. The Lambda role now has app inline permissions for DynamoDB `GetItem`, S3 `GetObject`, and `ssm:GetParameter` on `parameter/zoolanding/api/*`; the deployed inline policy no longer grants Secrets Manager reads.
- Live smoke for `music.lynxpardelle.com` + `music-releases` returned `{"ok":false,"error":"Integration not found"}`, so the music/TIDAL integration is currently disabled/no-op rather than live.
- Keep browser payloads secret-free: `credentialRef` is allowed in server-only policy only; client bundles must not contain tokens, client secrets, or upstream credentials.
