#!/usr/bin/env python3
"""Key Server client - fetch/manage API keys from a self-hosted Key Server.

Standard library only (urllib), so it runs without `pip install` anywhere with
Python 3.8+.

Environment:
  KEY_SERVER_URL          base URL of the deployment (required)
  KEY_SERVER_TOKEN_FILE   token cache path (default ~/.keyserver/token)
  KEY_SERVER_CLIENT_NAME  label shown in the web approval screen (default hostname)

Commands:
  get <name>            print the plaintext value of one key
  list                  print key names, one per line
  set <name> <value>    add or update a key
  delete <name>         remove a key
  status                print JSON health {ok, locked}

Exit codes:
  0 ok
  1 generic error
  2 key not found
  3 vault locked        -> user must log into the web console to unlock
  4 unauthorized        -> token was revoked/expired (auto-cleared); just retry
  5 configuration error -> KEY_SERVER_URL missing or server unreachable
  6 connection denied by the user
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
POLL_INTERVAL = 3
POLL_TIMEOUT = 600  # 10 minutes to approve in the web console


def _die(code: int, msg: str) -> "None":
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(code)


def _base_url() -> str:
    url = os.environ.get("KEY_SERVER_URL", "").strip().rstrip("/")
    if not url:
        _die(5, "KEY_SERVER_URL is not set. Ask the user for their Key Server "
                "deployment URL, e.g. https://key-server-xxxx.vercel.app")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _token_file() -> str:
    p = os.environ.get("KEY_SERVER_TOKEN_FILE", "").strip()
    if not p:
        p = os.path.join(os.path.expanduser("~"), ".keyserver", "token")
    return p


def _load_token() -> "str | None":
    try:
        with open(_token_file(), "r", encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _save_token(token: str) -> None:
    path = _token_file()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(token)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _clear_token() -> None:
    try:
        os.remove(_token_file())
    except OSError:
        pass


def _client_name() -> str:
    return os.environ.get("KEY_SERVER_CLIENT_NAME", "").strip() or socket.gethostname() or "agent"


def _request(method: str, path: str, *, token: str = None, form: dict = None) -> "tuple[int, dict]":
    url = _base_url() + path
    data = None
    headers = {"Accept": "application/json"}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, _parse(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return e.code, _parse(body)
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        _die(5, f"Cannot reach Key Server at {_base_url()}: {e}")


def _parse(body: str) -> dict:
    try:
        out = json.loads(body)
        return out if isinstance(out, dict) else {"_raw": out}
    except ValueError:
        return {"_raw": body}


# ---------------------------------------------------------------- auth flow

def _connect_and_wait() -> str:
    """Register a pending connection, wait for web approval, return a token."""
    status, out = _request("POST", "/api/connect", form={"client_name": _client_name()})
    if status == 429:
        _die(1, "Rate limited by the server. Wait a minute and try again.")
    if not out.get("ok") or "connect_id" not in out:
        _die(1, f"connect failed: {out}")
    connect_id = out["connect_id"]

    sys.stderr.write(
        "\n"
        "Key Server needs a one-time approval for this machine.\n"
        f"  1. Open the Key Server web console: {_base_url()}\n"
        "  2. Log in, find the pending connection:\n"
        f"       client: {_client_name()}\n"
        f"       id:     {connect_id[:16]}...\n"
        "  3. Click Approve.\n"
        "Waiting for approval (up to 10 min)...\n"
    )

    deadline = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        _, s = _request("GET", f"/api/connect/{connect_id}/status")
        state = s.get("status")
        if state == "approved" and s.get("token"):
            _save_token(s["token"])
            sys.stderr.write("Approved. Token cached.\n\n")
            return s["token"]
        if state == "approved":  # already issued to another poll; shouldn't happen here
            _die(1, "connection approved but no token returned; retry")
        if state == "denied":
            _die(6, "The user denied this connection request.")
        if state == "invalid":
            _die(1, "connect_id became invalid; retry")
    _die(1, "Timed out waiting for web approval.")


def _token() -> str:
    return _load_token() or _connect_and_wait()


def _auth_request(method: str, path: str, *, form: dict = None, _retried: bool = False) -> dict:
    """Request with bearer auth, handling lock / expired-token transparently."""
    token = _token()
    status, out = _request(method, path, token=token, form=form)
    if status == 423:
        _die(3, "Key Server vault is LOCKED. Ask the user to log into the web "
                f"console ({_base_url()}) to unlock it, then retry.")
    if status == 401:
        _clear_token()
        if _retried:
            _die(4, "Still unauthorized after re-connecting. Check with the user.")
        sys.stderr.write("Cached token rejected; starting a fresh approval.\n")
        return _auth_request(method, path, form=form, _retried=True)
    if status == 404:
        _die(2, "key not found")
    if status >= 400 or (isinstance(out, dict) and out.get("ok") is False):
        _die(1, f"{method} {path} -> {status}: {out}")
    return out


# ---------------------------------------------------------------- commands

def cmd_get(name: str) -> None:
    out = _auth_request("GET", "/api/keys/" + urllib.parse.quote(name, safe=""))
    if "key" not in out:
        _die(1, f"unexpected response: {out}")
    sys.stdout.write(out["key"])
    if sys.stdout.isatty():
        sys.stdout.write("\n")


def cmd_list() -> None:
    out = _auth_request("GET", "/api/keys")
    for k in out.get("keys", []):
        print(k.get("name", ""))


def cmd_set(name: str, value: str) -> None:
    _auth_request("POST", "/api/keys", form={"name": name, "value": value})
    sys.stderr.write(f"stored: {name}\n")


def cmd_delete(name: str) -> None:
    _auth_request("DELETE", "/api/keys/" + urllib.parse.quote(name, safe=""))
    sys.stderr.write(f"deleted: {name}\n")


def cmd_status() -> None:
    _, out = _request("GET", "/health")
    print(json.dumps(out))
    if out.get("locked"):
        sys.exit(3)


def main(argv: "list[str]") -> None:
    if not argv:
        _die(1, __doc__)
    cmd, rest = argv[0], argv[1:]
    if cmd == "get" and len(rest) == 1:
        cmd_get(rest[0])
    elif cmd == "list" and not rest:
        cmd_list()
    elif cmd == "set" and len(rest) == 2:
        cmd_set(rest[0], rest[1])
    elif cmd == "delete" and len(rest) == 1:
        cmd_delete(rest[0])
    elif cmd == "status" and not rest:
        cmd_status()
    else:
        _die(1, __doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
