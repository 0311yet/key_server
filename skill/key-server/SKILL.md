---
name: key-server
description: >-
  Fetch and manage API keys / credentials from a self-hosted Key Server instance
  instead of hardcoding secrets or asking the user to paste them. Use this
  whenever a task needs a platform API key (OpenAI, Anthropic, AWS, a database
  URL, a webhook secret, etc.) and the user has a Key Server deployment — or
  mentions "key server", "key-server", "从密钥服务器取", "get my <X> key",
  "拿一下 <X> 的 key". Also use it to store a new key the user gives you, list
  what keys exist, or check whether the vault is unlocked. The server holds the
  plaintext; this skill talks to it over a short REST API with a cached bearer
  token. First use on a machine needs a one-time web approval by the user.
---

# Key Server

Key Server is a self-hosted vault: the user keeps their real API keys in one
place, and agents pull them at runtime over an authenticated REST API. The
database only stores ciphertext, so this skill is the sanctioned way to get a
plaintext key onto the machine — better than the user pasting secrets into chat.

## Setup (once per environment)

The skill needs to know which deployment to talk to:

```
export KEY_SERVER_URL="https://<your-deployment>.vercel.app"
```

Optional overrides:

- `KEY_SERVER_TOKEN_FILE` — where the bearer token is cached
  (default `~/.keyserver/token`). The token is a 30-day credential that the
  server auto-renews on use; treat the file as a secret.
- `KEY_SERVER_CLIENT_NAME` — label shown to the user in the approval screen
  (default: the hostname).

If `KEY_SERVER_URL` is unset, ask the user for their deployment URL rather than
guessing.

## The one script

Everything goes through `scripts/keyserver.py`. It uses only the Python standard
library (no `pip install`), so it runs anywhere Python 3.8+ is available.

```
python scripts/keyserver.py get <name>          # print one key's plaintext to stdout
python scripts/keyserver.py list                 # list key names (no values)
python scripts/keyserver.py set <name> <value>   # add or update a key
python scripts/keyserver.py delete <name>        # remove a key
python scripts/keyserver.py status               # {ok, locked} health probe
```

`get` prints **only** the raw key value on stdout (no quotes, no newline noise),
so it composes cleanly:

```
export OPENAI_API_KEY="$(python scripts/keyserver.py get openai)"
```

## First-use approval flow

The first time a machine talks to a Key Server, it has no token. The script will:

1. Register a pending connection and print a short `connect_id`.
2. Print a message asking the user to open the Key Server web console, find the
   pending connection, and click **同意 / Approve**.
3. Poll until approved, then cache the returned token and continue.

When you hit this, relay the instruction to the user in plain language and wait —
you cannot approve it yourself, it is a deliberate human checkpoint. Once
approved the token is reused silently on every later call.

If the user denies the request, the script exits non-zero with `denied`; don't
retry in a loop — ask the user what they want to do.

## Handling the common failures

| Symptom | Meaning | What to do |
|---|---|---|
| exit code 3, `locked` | Vault is locked (nobody has logged into the web console recently) | Tell the user to log into the Key Server web console to unlock it, then retry |
| exit code 4, `unauthorized` | Cached token was revoked or expired | The script auto-deletes the dead token; just run the command again to re-trigger the approval flow |
| exit code 2, `not found` | No key by that name | Run `list` to show the user what does exist; offer to `set` it |
| exit code 5, config error | `KEY_SERVER_URL` missing / unreachable | Ask the user for the URL or check connectivity |

## Security expectations

- Never echo a fetched key back into the conversation, a commit, a log line, or a
  file the user didn't ask for. Put it straight into the environment variable or
  config field it's needed for.
- Don't cache key values yourself — call `get` again when you need it again. The
  server-side value is the source of truth.
- The token file is a bearer credential. Don't copy it elsewhere or print it.
- `set` sends the value over HTTPS to the user's own server; still, prefer having
  the user add highly sensitive keys through the web console themselves.

## Reference

`references/api.md` documents the raw HTTP endpoints — read it only if you need
to do something the script doesn't cover (e.g. scripting against the API in
another language, or debugging a response).
