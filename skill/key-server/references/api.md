# Key Server — raw HTTP API

Base URL: `$KEY_SERVER_URL` (e.g. `https://key-server-xxxx.vercel.app`).
All responses are JSON. AI endpoints authenticate with `Authorization: Bearer <token>`.

## Health

```
GET /health
-> 200 {"ok": true, "locked": false}
```

`locked: true` means no master key is loaded server-side — a human must log into
the web console to unlock before any key can be decrypted. Key endpoints return
`423` while locked.

## Connection / approval (no auth)

```
POST /api/connect
  form: client_name=<label>
-> 200 {"ok": true, "connect_id": "<64 hex>"}
-> 429 {"ok": false, "error": "..."}     # rate limited (30/min/IP)
```

```
GET /api/connect/<connect_id>/status
-> {"status": "pending"}
-> {"status": "approved", "token": "<bearer>"}   # returned exactly once
-> {"status": "approved"}                          # token already issued
-> {"status": "denied"}
-> {"status": "invalid"}                           # unknown connect_id
```

The token is issued on the first `status` poll after a human approves the
pending connection in the web console. Store it; it is a 30-day credential and
the server slides the expiry forward by 30 days whenever it is used within 7
days of expiring.

## Key endpoints (Bearer auth)

```
GET /api/keys
-> 200 {"ok": true, "keys": [{"name": "openai", "created_at": "..."}]}

GET /api/keys/<name>
-> 200 {"ok": true, "key": "<plaintext>"}
-> 404 {"ok": false, "error": "密钥不存在"}

POST /api/keys
  form: name=<name>&value=<plaintext>
-> 200 {"ok": true}                       # upsert

DELETE /api/keys/<name>
-> 200 {"ok": true}
```

Common error statuses on these endpoints:

- `401` — missing/invalid/revoked token. Drop the cached token and re-run the
  connect flow.
- `423` — vault locked. A human must unlock via the web console.

## Notes

- The web console (password login, key CRUD, approving connections, revoking
  tokens) is separate and not part of this API.
- Revoking a token in the web console makes it start returning `401`.
