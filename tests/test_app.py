from __future__ import annotations
import datetime as dt
import html.parser
import json

from app import auth, crypto, db, main
from tests.conftest import PASSWORD, csrf, get_agent_token, login


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------- XSS
class _ScriptCollector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []  # (attrs, text)
        self._cur = None

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._cur = [dict(attrs), ""]

    def handle_data(self, data):
        if self._cur is not None:
            self._cur[1] += data

    def handle_endtag(self, tag):
        if tag == "script" and self._cur is not None:
            self.scripts.append(tuple(self._cur))
            self._cur = None


def test_client_name_cannot_inject_script(client):
    payload = "</script><script>alert(1)</script>"
    client.post("/api/connect", data={"client_name": payload})
    login(client)
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert payload not in page.text

    parser = _ScriptCollector()
    parser.feed(page.text)
    # 只允许两个 script：JSON 数据块和外部 app.js，不能有任何被注入的可执行脚本
    assert len(parser.scripts) == 2
    data_attrs, data_text = parser.scripts[0]
    assert data_attrs == {"type": "application/json", "id": "init-data"}
    assert parser.scripts[1][0]["src"].startswith("/static/app.js")
    # 数据本身完好：解析后还原出原始名字
    assert json.loads(data_text)["pending"][0]["client_name"] == payload


def test_security_headers(client):
    r = client.get("/login")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


# ---------------------------------------------------------------- 审批状态机
def test_token_issued_exactly_once(client):
    login(client)
    cid = client.post("/api/connect", data={"client_name": "a"}).json()["connect_id"]
    assert client.get(f"/api/connect/{cid}/status").json() == {"status": "pending"}
    assert client.post(f"/connect/{cid}/approve", headers=csrf(client)).json()["ok"]
    first = client.get(f"/api/connect/{cid}/status").json()
    assert first["status"] == "approved" and first["token"]
    assert client.get(f"/api/connect/{cid}/status").json() == {"status": "approved"}
    assert len(db.list_tokens()) == 1


def test_cannot_reapprove_issued_or_denied(client):
    login(client)
    cid = client.post("/api/connect", data={"client_name": "a"}).json()["connect_id"]
    client.post(f"/connect/{cid}/approve", headers=csrf(client))
    client.get(f"/api/connect/{cid}/status")  # issued
    r = client.post(f"/connect/{cid}/approve", headers=csrf(client)).json()
    assert not r["ok"]
    assert "token" not in client.get(f"/api/connect/{cid}/status").json()
    assert len(db.list_tokens()) == 1

    cid2 = client.post("/api/connect", data={"client_name": "b"}).json()["connect_id"]
    client.post(f"/connect/{cid2}/deny", headers=csrf(client))
    assert not client.post(f"/connect/{cid2}/approve", headers=csrf(client)).json()["ok"]
    assert client.get(f"/api/connect/{cid2}/status").json() == {"status": "denied"}


def test_expired_pending_cannot_be_approved(client):
    login(client)
    cid = client.post("/api/connect", data={"client_name": "old"}).json()["connect_id"]
    old = db.utcnow() - main.PENDING_TTL - dt.timedelta(minutes=1)
    db._execute("UPDATE pending_connections SET created_at = ? WHERE connect_id = ?", (old, cid))
    assert not client.post(f"/connect/{cid}/approve", headers=csrf(client)).json()["ok"]
    assert client.get(f"/api/connect/{cid}/status").json() == {"status": "expired"}
    assert client.get("/api/dashboard/data").json()["pending"] == []


def test_open_pending_capped(client):
    for i in range(main.MAX_OPEN_PENDING):
        db.create_pending(f"id{i}", "x", "1.1.1.1", "")
    assert client.post("/api/connect", data={"client_name": "y"}).status_code == 429


def test_approve_requires_login_and_csrf(client):
    cid = client.post("/api/connect", data={"client_name": "a"}).json()["connect_id"]
    assert client.post(f"/connect/{cid}/approve").status_code == 401
    login(client)
    assert client.post(f"/connect/{cid}/approve").status_code == 403  # 缺 CSRF 头


# ---------------------------------------------------------------- 锁定 / 退出
def test_logout_does_not_lock_vault(client):
    login(client)
    token = get_agent_token(client)
    client.post("/dashboard/add_key", data={"name": "openai", "value": "sk-1"}, headers=csrf(client))
    assert client.post("/logout", headers=csrf(client)).json()["ok"]
    assert client.get("/api/keys/openai", headers=bearer(token)).json()["key"] == "sk-1"


def test_lock_blocks_agents_until_login(client):
    login(client)
    token = get_agent_token(client)
    client.post("/dashboard/add_key", data={"name": "openai", "value": "sk-1"}, headers=csrf(client))
    assert client.post("/lock", headers=csrf(client)).json()["ok"]
    assert client.get("/api/keys/openai", headers=bearer(token)).status_code == 423
    assert client.get("/health").json()["locked"] is True
    assert client.get("/dashboard", follow_redirects=False).status_code == 302
    login(client)
    assert client.get("/api/keys/openai", headers=bearer(token)).json()["key"] == "sk-1"


def test_unauthenticated_api_gets_401_even_when_locked(client):
    assert client.get("/api/keys").status_code == 401
    assert client.get("/api/keys", headers=bearer("nope")).status_code == 401


# ---------------------------------------------------------------- 密码 / 加密
def test_change_password_keeps_data(client):
    login(client)
    token = get_agent_token(client)
    client.post("/dashboard/add_key", data={"name": "k", "value": "secret"}, headers=csrf(client))
    new = "a-brand-new-password"
    r = client.post("/dashboard/change_password",
                    data={"old_password": PASSWORD, "new_password": new}, headers=csrf(client))
    assert r.json() == {"ok": True}
    client.post("/lock", headers=csrf(client))

    assert login(client, PASSWORD)["ok"] is False
    assert login(client, new)["ok"] is True
    assert client.get("/api/keys/k", headers=bearer(token)).json()["key"] == "secret"


def test_change_password_rejects_bad_input(client):
    login(client)
    h = csrf(client)
    assert not client.post("/dashboard/change_password",
                           data={"old_password": "wrong", "new_password": "x" * 20}, headers=h).json()["ok"]
    assert not client.post("/dashboard/change_password",
                           data={"old_password": PASSWORD, "new_password": "short"}, headers=h).json()["ok"]


def test_env_password_change_does_not_overwrite_hash(client, monkeypatch):
    login(client)
    stored = db.get_password_hash()
    monkeypatch.setattr(auth.config, "LOGIN_PASSWORD", "someone-changed-the-env")
    main._init_done = False
    client.get("/health")
    assert db.get_password_hash() == stored


def test_legacy_data_migrates_on_first_login(client):
    """旧版本：数据直接用 scrypt(密码) 加密，且没有 dek_wrapped。升级后应无缝解密。"""
    db.init_db()
    db.set_password_hash(auth._hash_password(PASSWORD))
    legacy_key = crypto.derive_kek(PASSWORD)
    crypto._set_cache(legacy_key)
    db.upsert_key("old", crypto.encrypt_key("legacy-secret"))
    crypto._set_cache(None)
    assert db.get_setting(db.SETTING_DEK_WRAPPED) is None

    assert login(client)["ok"]
    assert db.get_setting(db.SETTING_DEK_WRAPPED)
    token = get_agent_token(client)
    assert client.get("/api/keys/old", headers=bearer(token)).json()["key"] == "legacy-secret"


def test_fresh_install_uses_random_dek(client):
    login(client)
    assert crypto.get_master_key() != crypto.derive_kek(PASSWORD)


# ---------------------------------------------------------------- API / 限流
def test_key_crud_via_api(client):
    login(client)
    token = get_agent_token(client)
    h = bearer(token)
    assert client.post("/api/keys", data={"name": "a", "value": "1"}, headers=h).json()["ok"]
    assert [k["name"] for k in client.get("/api/keys", headers=h).json()["keys"]] == ["a"]
    assert client.get("/api/keys/a", headers=h).json()["key"] == "1"
    assert client.delete("/api/keys/a", headers=h).json()["ok"]
    assert client.get("/api/keys/a", headers=h).status_code == 404
    assert client.delete("/api/keys/a", headers=h).status_code == 404
    assert client.post("/api/keys", data={"name": " ", "value": "1"}, headers=h).status_code == 400


def test_last_used_written_at_most_every_few_minutes(client, monkeypatch):
    login(client)
    token = get_agent_token(client)
    calls = []
    real = db.update_token
    monkeypatch.setattr(db, "update_token", lambda *a, **k: (calls.append(k), real(*a, **k)))
    for _ in range(5):
        client.get("/api/keys", headers=bearer(token))
    assert len(calls) == 1


def test_login_rate_limited(client):
    h = csrf(client)
    codes = [client.post("/login", data={"password": "wrong"}, headers=h).status_code for _ in range(12)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429


# ---------------------------------------------------------------- 查看明文 / 简介
def test_dashboard_reveal_key(client):
    login(client)
    client.post("/dashboard/add_key", data={"name": "openai", "value": "sk-abc"}, headers=csrf(client))
    r = client.post("/dashboard/reveal_key", data={"name": "openai"}, headers=csrf(client))
    assert r.json() == {"ok": True, "key": "sk-abc"}
    assert r.headers["cache-control"] == "no-store"
    assert client.post("/dashboard/reveal_key", data={"name": "nope"}, headers=csrf(client)).status_code == 404
    # 首屏数据里不能带明文
    assert "sk-abc" not in client.get("/dashboard").text


def test_reveal_requires_login_csrf_and_unlocked(client):
    login(client)
    client.post("/dashboard/add_key", data={"name": "k", "value": "v"}, headers=csrf(client))
    assert client.post("/dashboard/reveal_key", data={"name": "k"}).status_code == 403
    crypto._set_cache(None)  # 模拟已锁定
    r = client.post("/dashboard/reveal_key", data={"name": "k"}, headers=csrf(client))
    assert r.status_code == 423
    client.cookies.clear()
    assert client.post("/dashboard/reveal_key", data={"name": "k"}).status_code == 401


def test_description_set_and_kept_on_value_update(client):
    login(client)
    h = csrf(client)
    client.post("/dashboard/add_key", data={"name": "gh", "value": "v1", "description": "GitHub PAT，用于发 PR"}, headers=h)
    # 只换值、简介留空：保留原简介
    client.post("/dashboard/add_key", data={"name": "gh", "value": "v2", "description": ""}, headers=h)
    keys = client.get("/api/dashboard/data").json()["keys"]
    assert keys == [{"name": "gh", "description": "GitHub PAT，用于发 PR", "updated_at": keys[0]["updated_at"]}]
    assert client.post("/dashboard/reveal_key", data={"name": "gh"}, headers=h).json()["key"] == "v2"
    # 编辑简介 / 清空
    assert client.post("/dashboard/set_description", data={"name": "gh", "description": "新简介"}, headers=h).json()["ok"]
    assert db.get_key("gh").description == "新简介"
    assert client.post("/dashboard/set_description", data={"name": "gh", "description": ""}, headers=h).json()["ok"]
    assert db.get_key("gh").description is None
    assert client.post("/dashboard/set_description", data={"name": "x", "description": "a"}, headers=h).status_code == 404
    assert client.post("/dashboard/set_description", data={"name": "gh", "description": "a" * 501}, headers=h).status_code == 400


def test_description_visible_to_ai(client):
    login(client)
    token = get_agent_token(client)
    h = bearer(token)
    assert client.post("/api/keys", data={"name": "a", "value": "1", "description": "OpenAI 主账号"}, headers=h).json()["ok"]
    assert client.get("/api/keys", headers=h).json()["keys"][0]["description"] == "OpenAI 主账号"
    assert client.get("/api/keys/a", headers=h).json() == {"ok": True, "key": "1", "description": "OpenAI 主账号"}
    # 不传 description：保留；传了：覆盖
    client.post("/api/keys", data={"name": "a", "value": "2"}, headers=h)
    assert db.get_key("a").description == "OpenAI 主账号"
    assert client.post("/api/keys/a/description", data={"description": "备用"}, headers=h).json()["ok"]
    assert db.get_key("a").description == "备用"
    assert client.post("/api/keys/zz/description", data={"description": "x"}, headers=h).status_code == 404


def test_description_column_added_to_old_table(tmp_path, monkeypatch):
    """线上旧库的 keys 表没有 description 列：init_db 应自动补上，旧数据保留。"""
    import sqlite3
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE keys (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, value TEXT NOT NULL, created_at TEXT, updated_at TEXT)")
    conn.execute("INSERT INTO keys (name, value) VALUES ('old', 'blob')")
    conn.commit()
    conn.close()
    monkeypatch.setattr(db.config, "DB_FILE", str(path))
    db.init_db()
    db.init_db()  # 可重复执行
    assert db.get_key("old").description is None
    assert db.set_description("old", "迁移后可写")
    assert db.list_keys()[0].description == "迁移后可写"
