"""数据库层：SQLite（VPS 本地）或 httpx + Turso HTTP API（Vercel）。

切换方式：环境变量 TURSO_DATABASE_URL 非空时走 Turso 模式。
"""
from __future__ import annotations
import datetime as dt
import httpx

from . import config

_USING_TURSO = bool(config.TURSO_DATABASE_URL)


# ============================================================
# 初始化
# ============================================================
if _USING_TURSO:
    _TURSO_BASE = config.TURSO_DATABASE_URL.rstrip("/").replace("libsql://", "https://", 1)
    _TURSO_HEADERS = {"Authorization": f"Bearer {config.TURSO_AUTH_TOKEN}"}

    def _http() -> httpx.Client:
        return httpx.Client(base_url=_TURSO_BASE, headers=_TURSO_HEADERS,
                            follow_redirects=True, timeout=30.0)

    def _serialize(val):
        """Python 值 → Turso typed value dict。"""
        if val is None:
            return {"type": "null", "value": "nil"}
        if isinstance(val, bool):
            return {"type": "integer", "value": "1" if val else "0"}
        if isinstance(val, int):
            return {"type": "integer", "value": str(val)}
        if isinstance(val, float):
            return {"type": "float", "value": str(val)}
        if isinstance(val, bytes):
            import base64
            return {"type": "blob", "value": base64.b64encode(val).decode()}
        if isinstance(val, dt.datetime):
            return {"type": "text", "value": val.isoformat()}
        return {"type": "text", "value": str(val)}

    def _run(sql: str, args: tuple = ()) -> list[dict]:
        """Turso: 执行 SQL 返回行列表。"""
        with _http() as client:
            r = client.post("/v2/pipeline", json={
                "requests": [{"type": "execute", "stmt": {"sql": sql, "args": [_serialize(a) for a in args]}}]
            })
            r.raise_for_status()
            results = r.json().get("results", [])
            if not results:
                return []
            res = results[0]
            if res.get("type") == "error":
                raise RuntimeError(f"SQL error: {res}")
            resp = res.get("response", {})
            cols = resp.get("cols", [])
            rows = resp.get("rows", [])
            out = []
            for row in rows:
                obj = {}
                for i, cell in enumerate(row):
                    col_name = cols[i]["name"] if i < len(cols) else f"col{i}"
                    obj[col_name] = _deserialize(cell)
                out.append(obj)
            return out

    def _exec(sql: str, args: tuple = ()) -> None:
        """Turso: 执行写 SQL。"""
        with _http() as client:
            r = client.post("/v2/pipeline", json={
                "requests": [{"type": "execute", "stmt": {"sql": sql, "args": [_serialize(a) for a in args]}}]
            })
            r.raise_for_status()

    def _deserialize(v):
        """Turso {type,value} → Python 对象。"""
        if isinstance(v, dict) and "type" in v and "value" in v:
            t, val = v["type"], v["value"]
            if t == "integer":
                return int(val)
            if t == "float":
                return float(val)
            if t == "null":
                return None
            val = val
        else:
            return v
        if isinstance(val, str):
            try:
                return dt.datetime.fromisoformat(val)
            except ValueError:
                return val
        return val

    def _row(d: dict):
        """字典 → 属性对象，兼容调用方的 .id .name 等访问。"""
        class Row:
            def __init__(self, data):
                for k, v in data.items():
                    setattr(self, k, _deserialize(v))
        return Row(d) if d else None

    def init_db():
        stmts = [
            "CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL, value TEXT)",
            "CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, value TEXT NOT NULL, created_at TEXT, updated_at TEXT)",
            "CREATE TABLE IF NOT EXISTS ai_tokens (id INTEGER PRIMARY KEY, client_name TEXT, token_hash TEXT UNIQUE NOT NULL, expires_at TEXT, last_used_at TEXT, last_ip TEXT, status TEXT DEFAULT 'approved', created_at TEXT)",
            "CREATE TABLE IF NOT EXISTS pending_connections (id INTEGER PRIMARY KEY, connect_id TEXT UNIQUE NOT NULL, client_name TEXT, ip TEXT, ua TEXT, status TEXT DEFAULT 'pending', created_at TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name)",
            "CREATE INDEX IF NOT EXISTS idx_tokens_hash ON ai_tokens(token_hash)",
        ]
        for s in stmts:
            _exec(s)

else:
    from sqlmodel import Session, create_engine, select, SQLModel
    from .models import KeyEntry, AIToken, PendingConnection, Setting

    _engine = create_engine(
        f"sqlite:///{config.DB_FILE}",
        echo=False, connect_args={"check_same_thread": False},
    )

    def get_session():
        with Session(_engine) as s:
            yield s

    def init_db():
        SQLModel.metadata.create_all(_engine)


# ============================================================
# 公开函数（模式无关，内部引用 _USING_TURSO）
# ============================================================

SETTING_PWD_HASH = "login_password_hash"


def get_password_hash() -> str | None:
    if _USING_TURSO:
        sql = "SELECT key, value FROM settings WHERE key = ?"
        rows = _run(sql, ("login_password_hash",))
        # 调试：打印 rows 内容
        print(f"[DEBUG get_password_hash] SQL: {sql}")
        print(f"[DEBUG get_password_hash] args: ('login_password_hash',)")
        print(f"[DEBUG get_password_hash] _run returned: {repr(rows)}")
        print(f"[DEBUG get_password_hash] rows type: {type(rows)}, len: {len(rows) if rows else 0}")
        if rows and len(rows) > 0:
            row = rows[0]
            print(f"[DEBUG get_password_hash] row type: {type(row)}, content: {repr(row)}")
            return row.get("value")
        return None
    with Session(_engine) as s:
        row = s.get(Setting, SETTING_PWD_HASH)
        return row.value if row else None


def set_password_hash(h: str) -> None:
    if _USING_TURSO:
        _exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (SETTING_PWD_HASH, h))
        return
    with Session(_engine) as s:
        row = s.get(Setting, SETTING_PWD_HASH)
        if row:
            row.value = h
        else:
            s.add(Setting(key=SETTING_PWD_HASH, value=h))
        s.commit()


def list_keys() -> list:
    if _USING_TURSO:
        return [_row(r) for r in _run("SELECT name, created_at FROM keys ORDER BY name")]
    with Session(_engine) as s:
        return list(s.exec(select(KeyEntry).order_by(KeyEntry.name)).all())


def get_key(name: str):
    if _USING_TURSO:
        rows = _run("SELECT name, value, created_at, updated_at FROM keys WHERE name = ?", (name,))
        return _row(rows[0]) if rows else None
    with Session(_engine) as s:
        return s.exec(select(KeyEntry).where(KeyEntry.name == name)).first()


def upsert_key(name: str, encrypted_value: str) -> None:
    if _USING_TURSO:
        now = dt.datetime.utcnow().isoformat()
        _exec(
            "INSERT INTO keys (name, value, created_at, updated_at) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (name, encrypted_value, now, now),
        )
        return
    with Session(_engine) as s:
        row = s.exec(select(KeyEntry).where(KeyEntry.name == name)).first()
        if row:
            row.value = encrypted_value
            row.updated_at = dt.datetime.now(dt.timezone.utc)
        else:
            s.add(KeyEntry(name=name, value=encrypted_value))
        s.commit()


def delete_key(name: str) -> bool:
    if _USING_TURSO:
        if not _run("SELECT id FROM keys WHERE name = ?", (name,)):
            return False
        _exec("DELETE FROM keys WHERE name = ?", (name,))
        return True
    with Session(_engine) as s:
        row = s.exec(select(KeyEntry).where(KeyEntry.name == name)).first()
        if row:
            s.delete(row)
            s.commit()
            return True
        return False


def get_token_by_hash(token_hash: str):
    if _USING_TURSO:
        rows = _run(
            "SELECT id, client_name, token_hash, expires_at, last_used_at, last_ip, status, created_at"
            " FROM ai_tokens WHERE token_hash = ?", (token_hash,))
        return _row(rows[0]) if rows else None
    with Session(_engine) as s:
        return s.exec(select(AIToken).where(AIToken.token_hash == token_hash)).first()


def list_tokens() -> list:
    if _USING_TURSO:
        return [_row(r) for r in _run(
            "SELECT id, client_name, token_hash, expires_at, last_used_at, last_ip, status, created_at"
            " FROM ai_tokens ORDER BY created_at DESC")]
    with Session(_engine) as s:
        return list(s.exec(select(AIToken).order_by(AIToken.created_at.desc())).all())


def create_token(client_name: str, token_hash: str, expires_at: dt.datetime,
                 ip: str | None):
    if _USING_TURSO:
        now = dt.datetime.utcnow().isoformat()
        _exec(
            "INSERT INTO ai_tokens (client_name, token_hash, expires_at, last_ip, status, created_at)"
            " VALUES (?, ?, ?, ?, 'approved', ?)",
            (client_name, token_hash, expires_at.isoformat(), ip, now),
        )
        rows = _run(
            "SELECT id, client_name, token_hash, expires_at, last_used_at, last_ip, status, created_at"
            " FROM ai_tokens WHERE token_hash = ?", (token_hash,))
        return _row(rows[0])
    with Session(_engine) as s:
        row = AIToken(client_name=client_name, token_hash=token_hash,
                      expires_at=expires_at, last_ip=ip)
        s.add(row)
        s.commit()
        s.refresh(row)
        return row


def update_token(row, expires_at: dt.datetime | None = None,
                 last_used_at: dt.datetime | None = None,
                 last_ip: str | None = None, status: str | None = None) -> None:
    if _USING_TURSO:
        parts, args = [], []
        if expires_at:
            parts.append("expires_at = ?"); args.append(expires_at.isoformat())
        if last_used_at:
            parts.append("last_used_at = ?"); args.append(last_used_at.isoformat())
        if last_ip:
            parts.append("last_ip = ?"); args.append(last_ip)
        if status:
            parts.append("status = ?"); args.append(status)
        if parts:
            args.append(row.id)
            _exec(f"UPDATE ai_tokens SET {', '.join(parts)} WHERE id = ?", tuple(args))
        return
    with Session(_engine) as s:
        db_row = s.get(AIToken, row.id)
        if expires_at is not None:
            db_row.expires_at = expires_at
        if last_used_at is not None:
            db_row.last_used_at = last_used_at
        if last_ip is not None:
            db_row.last_ip = last_ip
        if status is not None:
            db_row.status = status
        s.add(db_row)
        s.commit()


def delete_token(token_id: int) -> bool:
    if _USING_TURSO:
        if not _run("SELECT id FROM ai_tokens WHERE id = ?", (token_id,)):
            return False
        _exec("DELETE FROM ai_tokens WHERE id = ?", (token_id,))
        return True
    with Session(_engine) as s:
        row = s.get(AIToken, token_id)
        if row:
            s.delete(row)
            s.commit()
            return True
        return False


def create_pending(connect_id: str, client_name: str, ip: str | None,
                   ua: str | None):
    if _USING_TURSO:
        now = dt.datetime.utcnow().isoformat()
        _exec(
            "INSERT INTO pending_connections (connect_id, client_name, ip, ua, status, created_at)"
            " VALUES (?, ?, ?, ?, 'pending', ?)",
            (connect_id, client_name, ip, ua, now),
        )
        rows = _run(
            "SELECT id, connect_id, client_name, ip, ua, status, created_at"
            " FROM pending_connections WHERE connect_id = ?", (connect_id,))
        return _row(rows[0])
    with Session(_engine) as s:
        row = PendingConnection(connect_id=connect_id, client_name=client_name, ip=ip, ua=ua)
        s.add(row)
        s.commit()
        s.refresh(row)
        return row


def get_pending(connect_id: str):
    if _USING_TURSO:
        rows = _run(
            "SELECT id, connect_id, client_name, ip, ua, status, created_at"
            " FROM pending_connections WHERE connect_id = ?", (connect_id,))
        return _row(rows[0]) if rows else None
    with Session(_engine) as s:
        return s.exec(select(PendingConnection).where(
            PendingConnection.connect_id == connect_id)).first()


def list_pending() -> list:
    if _USING_TURSO:
        return [_row(r) for r in _run(
            "SELECT id, connect_id, client_name, ip, ua, status, created_at"
            " FROM pending_connections WHERE status = 'pending' ORDER BY created_at DESC")]
    with Session(_engine) as s:
        return list(s.exec(
            select(PendingConnection).where(PendingConnection.status == "pending")
            .order_by(PendingConnection.created_at.desc())).all())


def set_pending_status(pending_id: int, status: str) -> None:
    if _USING_TURSO:
        _exec("UPDATE pending_connections SET status = ? WHERE id = ?", (status, pending_id))
        return
    with Session(_engine) as s:
        row = s.get(PendingConnection, pending_id)
        if row:
            row.status = status
            s.add(row)
            s.commit()


def bootstrap() -> None:
    init_db()