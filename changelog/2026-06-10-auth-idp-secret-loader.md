# 2026-06-10 CT - Auth IdP Secret Loader

- Added `tools/auth_idp_secret_loader.py` for Zoosite Google/Facebook social IdP credential checks and upserts.
- The loader writes Secrets Manager JSON payloads under `/zoolanding/auth/zoosite/staff/{provider}` with `clientId` and `clientSecret`.
- The loader supports local environment variables, hidden prompts, `--dry-run`, and `--mode check`, and avoids putting secret values in command-line arguments.
- Documented the Zoosite external IdP redirect URI and planned callback/logout URLs in `README.md`.
- Live check confirmed the Google and Facebook refs are still missing; no real IdP credentials were created or changed.
