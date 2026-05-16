# License Key Panel (Railway-ready)

A self-hosted license-key panel for your native app. Keys are HWID-bound,
have a configurable device limit, and a per-key duration. The validation
endpoint returns an HMAC-signed token so the client can verify the response
is genuine.

## Deploy on Railway

1. Create a new GitHub repo and push these files.
2. railway.app → New Project → Deploy from GitHub repo → pick this repo.
3. In **Variables**, set:

   | Name              | Value                                            |
   | ----------------- | ------------------------------------------------ |
   | `ADMIN_USER`      | your admin username                              |
   | `ADMIN_PASS`      | a strong password (used once to derive the hash) |
   | `SESSION_SECRET`  | any long random string                           |
   | `SIGNING_SECRET`  | any long random string (**also goes in keylogin.h**) |
   | `DATA_DIR`        | `/data`                                          |

4. **Storage** → Add a Volume, mount at `/data`. This keeps the SQLite DB
   across deploys.
5. Deploy. Open the generated URL (e.g. `https://yourapp.up.railway.app`)
   and log in with `ADMIN_USER` / `ADMIN_PASS`.
6. Go to **Settings → Networking** and copy the public domain. That domain
   goes into your `keylogin.h` (replace `PANEL_HOST`). `SIGNING_SECRET`
   must match between Railway and `keylogin.h`.

## Endpoint used by the .so

```
POST https://<your-panel>/api/v1/auth
Content-Type: application/json
{ "key": "XXXX-XXXX-...", "hwid": "<device fingerprint>", "nonce": "<random>" }
```

Returns:
```json
{ "ok": true, "token": "<base64url>.<hmac>", "exp": 1735689600000 }
```

The token is `HMAC-SHA256(SIGNING_SECRET, base64url(payload))`. The client
verifies the signature and checks that `key`, `hwid`, `nonce` match what it
sent — patching `return true` is detectable because the signature will not
verify against any real response.

## Health check

`GET /health` → `{ ok: true }`
