"""测试环境：本地 SQLite + 无 KV（进程内存锁定态），每个测试前清空数据。

config 在 import 时读取环境变量，所以必须在导入 app 之前设置好。
"""
from __future__ import annotations
import os
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix="keyserver-test-")
os.environ.update({
    "LOGIN_PASSWORD": "initial-password-123",
    "KDF_SALT": "00" * 32,
    "SESSION_SECRET": "test-session-secret",
    "DB_FILE": os.path.join(_TMP, "test.db"),
    "TURSO_DATABASE_URL": "",
    "KV_URL": "",
    "KV_TOKEN": "",
    "UPSTASH_REDIS_REST_URL": "",
    "KV_REST_API_URL": "",
})
os.environ.pop("VERCEL", None)
os.environ.pop("VERCEL_URL", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import crypto, db, main, ratelimit  # noqa: E402

PASSWORD = os.environ["LOGIN_PASSWORD"]


@pytest.fixture(autouse=True)
def fresh_state():
    db.init_db()
    for table in ("settings", "keys", "ai_tokens", "pending_connections"):
        db._execute(f"DELETE FROM {table}")
    main._init_done = False
    crypto._set_cache(None)
    ratelimit.reset()
    yield


@pytest.fixture
def client():
    return TestClient(main.app)


def csrf(client: TestClient) -> dict:
    """取 CSRF cookie（GET /login 会下发），返回要带的请求头。"""
    if not client.cookies.get("csrf_token"):
        client.get("/login")
    return {"X-CSRF-Token": client.cookies.get("csrf_token")}


def login(client: TestClient, password: str = PASSWORD) -> dict:
    r = client.post("/login", data={"password": password}, headers=csrf(client))
    return r.json()


def get_agent_token(client: TestClient, name: str = "agent") -> str:
    """走完整审批流程，返回 AI 的 Bearer token。调用前需已登录。"""
    cid = client.post("/api/connect", data={"client_name": name}).json()["connect_id"]
    assert client.post(f"/connect/{cid}/approve", headers=csrf(client)).json()["ok"]
    return client.get(f"/api/connect/{cid}/status").json()["token"]
