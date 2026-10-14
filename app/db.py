"""数据库层：同一套 SQL，两种后端。
- TURSO_DATABASE_URL 非空：httpx + Turso HTTP API（/v2/pipeline），用于 Vercel
- 否则：标准库 sqlite3（DB_FILE），用于本地 / VPS

所有时间一律存 naive UTC 的 ISO 字符串，读出时列名以 _at 结尾的转回 datetime。
"""
from __future__ import annotations
import datetime as dt
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace

import httpx

from . import config

_USING_TURSO = bool(config.TURSO_DATABASE_URL)

SCHEMA = [
    "CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL, value TEXT)",
    "CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, value TEXT NOT NULL, description TEXT, created_at TEXT, updated_at TEXT)",
    "CREATE TABLE IF NOT EXISTS ai_tokens (id INTEGER PRIMARY KEY, client_name TEXT, token_hash TEXT UNIQUE NOT NULL, expires_at TEXT, last_used_at TEXT, last_ip TEXT, status TEXT DEFAULT 'approved', created_at TEXT)",
    "CREATE TABLE IF NOT EXISTS pending_connections (id INTEGER PRIMARY KEY, connect_id TEXT UNIQUE NOT NULL, client_name TEXT, ip TEXT, ua TEXT, status TEXT DEFAULT 'pending', created_at TEXT)",
]
# 给旧表补列：(表, 列, 列定义)。init_db 时检查，缺了才 ALTER，可重复执行
MIGRATIONS = [
    ("keys", "description", "TEXT"),
]
_KEYS_COLUMNS_SQL = "SELECT name FROM pragma_table_info('keys')"


def utcnow() -> dt.datetime:
    """naive UTC 当前时间（库里所有时间都按这个口径存取）。"""
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def _to_db(val):
    if isinstance(val, dt.datetime):
        if val.tzinfo is not None:
            val = val.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return val.isoformat()
    if isinstance(val, bool):
        return int(val)
    return val


def _parse_dt(val):
    if not val or not isinstance(val, str):
        return val or None
    try:
        d = dt.datetime.fromisoformat(val.replace("Z", "+00:00"))
    except ValueError:
        return val
    if d.tzinfo is not None:
        d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return d


def _obj(row: dict) -> SimpleNamespace:
    """dict → 属性对象；*_at 列转 datetime。"""
    return SimpleNamespace(**{k: (_parse_dt(v) if k.endswith("_at") else v) for k, v in row.items()})


# ============================================================
# 后端
# ============================================================
if _USING_TURSO:
    _TURSO_BASE = config.TURSO_DATABASE_URL.rstrip("/").replace("libsql://", "https://", 1)
    # 全局共享 Client：复用 TCP+TLS 连接，Vercel 实例存活期内有效。
    _turso_client = httpx.Client(
        base_url=_TURSO_BASE,
        headers={"Authorization": f"Bearer {config.TURSO_AUTH_TOKEN}"},
        follow_redirects=True, timeout=30.0,
    )

    def _arg(val):
        val = _to_db(val)
        if val is None:
            return {"type": "null"}
        if isinstance(val, int):
            return {"type": "integer", "value": str(val)}
        if isinstance(val, float):
            return {"type": "float", "value": val}
        return {"type": "text", "value": str(val)}

    def _cell(c):
        if not isinstance(c, dict):
            return c
        t, v = c.get("type"), c.get("value")
        if t == "null":
            return None
        if t == "integer":
            return int(v)
        if t == "float":
            return float(v)
        return v

    def _pipeline(stmts: list[tuple[str, tuple]]) -> list[dict]:
        r = _turso_client.post("/v2/pipeline", json={"requests": [
            {"type": "execute", "stmt": {"sql": sql, "args": [_arg(a) for a in args]}}
            for sql, args in stmts
        ] + [{"type": "close"}]})
        r.raise_for_status()
        out = []
        for res in r.json().get("results", [])[:len(stmts)]:
            if res.get("type") == "error":
                raise RuntimeError(f"SQL error: {res.get('error')}")
            out.append(res.get("response", {}).get("result", {}))
        return out

    def _query(sql: str, args: tuple = ()) -> list[dict]:
        res = _pipeline([(sql, args)])[0]
        names = [c.get("name") for c in res.get("cols", [])]
        return [dict(zip(names, (_cell(c) for c in row))) for row in res.get("rows", [])]

    def _execute(sql: str, args: tuple = ()) -> int:
        """执行写 SQL，返回受影响行数。"""
        return int(_pipeline([(sql, args)])[0].get("affected_row_count", 0))

    def init_db() -> None:
        # 一次 HTTP 请求完成建表 + 读取 keys 表现有列（冷启动只多这一次往返）
        res = _pipeline([(s, ()) for s in SCHEMA] + [(_KEYS_COLUMNS_SQL, ())])[-1]
        _migrate({_cell(row[0]) for row in res.get("rows", [])})
else:
    _lock = threading.Lock()

    def _connect() -> sqlite3.Connection:
        Path(config.DB_FILE).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(config.DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

    def _run(fn):
        # sqlite3 的 with conn 只负责提交，不关闭连接，这里显式关闭
        with _lock:
            conn = _connect()
            try:
                with conn:
                    return fn(conn)
            finally:
                conn.close()

    def _query(sql: str, args: tuple = ()) -> list[dict]:
        return _run(lambda c: [dict(r) for r in c.execute(sql, tuple(_to_db(a) for a in args))])

    def _execute(sql: str, args: tuple = ()) -> int:
        return _run(lambda c: c.execute(sql, tuple(_to_db(a) for a in args)).rowcount)

    def init_db() -> None:
        _run(lambda c: [c.execute(s) for s in SCHEMA])
        _migrate({r["name"] for r in _query(_KEYS_COLUMNS_SQL)})


def _migrate(keys_columns: set) -> None:
    for table, column, decl in MIGRATIONS:
        if table == "keys" and column not in keys_columns:
            _execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


# ============================================================
# settings
# ============================================================
SETTING_PWD_HASH = "login_password_hash"
SETTING_DEK_WRAPPED = "dek_wrapped"


def get_setting(key: str) -> str | None:
    rows = _query("SELECT value FROM settings WHERE key = ?", (key,))
    return rows[0]["value"] if rows else None


def set_settings(values: dict[str, str]) -> None:
    """一条语句写入多个设置项（单语句即原子，改密码时哈希和包装密钥同时生效）。"""
    items = list(values.items())
    placeholders = ", ".join("(?, ?)" for _ in items)
    args = tuple(x for kv in items for x in kv)
    _execute(f"INSERT INTO settings (key, value) VALUES {placeholders}"
             " ON CONFLICT(key) DO UPDATE SET value = excluded.value", args)


def get_password_hash() -> str | None:
    return get_setting(SETTING_PWD_HASH)


def set_password_hash(h: str) -> None:
    set_settings({SETTING_PWD_HASH: h})


# ============================================================
# keys
# ============================================================
def list_keys() -> list:
    return [_obj(r) for r in _query(
        "SELECT name, description, created_at, updated_at FROM keys ORDER BY name")]


def has_keys() -> bool:
    return bool(_query("SELECT 1 AS x FROM keys LIMIT 1"))


def get_key(name: str):
    rows = _query("SELECT name, value, description, created_at, updated_at FROM keys WHERE name = ?", (name,))
    return _obj(rows[0]) if rows else None


def upsert_key(name: str, encrypted_value: str, description: str | None = None) -> None:
    """新增或更新密钥值。description 为 None 时保留原有简介（只换值不会把简介清掉）。"""
    now = utcnow()
    _execute(
        "INSERT INTO keys (name, value, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,"
        " description = COALESCE(excluded.description, keys.description)",
        (name, encrypted_value, description, now, now),
    )


def set_description(name: str, description: str) -> bool:
    """只改简介（空字符串即清空），返回密钥是否存在。"""
    return _execute("UPDATE keys SET description = ?, updated_at = ? WHERE name = ?",
                    (description or None, utcnow(), name)) > 0


def delete_key(name: str) -> bool:
    return _execute("DELETE FROM keys WHERE name = ?", (name,)) > 0


# ============================================================
# ai_tokens
# ============================================================
_TOKEN_COLS = "id, client_name, token_hash, expires_at, last_used_at, last_ip, status, created_at"


def get_token_by_hash(token_hash: str):
    rows = _query(f"SELECT {_TOKEN_COLS} FROM ai_tokens WHERE token_hash = ?", (token_hash,))
    return _obj(rows[0]) if rows else None


def list_tokens() -> list:
    return [_obj(r) for r in _query(f"SELECT {_TOKEN_COLS} FROM ai_tokens ORDER BY created_at DESC")]


def create_token(client_name: str, token_hash: str, expires_at: dt.datetime, ip: str | None) -> None:
    _execute(
        "INSERT INTO ai_tokens (client_name, token_hash, expires_at, last_ip, status, created_at)"
        " VALUES (?, ?, ?, ?, 'approved', ?)",
        (client_name, token_hash, expires_at, ip, utcnow()),
    )


def update_token(token_id: int, **fields) -> None:
    """只更新传入的字段：expires_at / last_used_at / last_ip / status。"""
    allowed = {"expires_at", "last_used_at", "last_ip", "status"}
    fields = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    _execute(f"UPDATE ai_tokens SET {sets} WHERE id = ?", (*fields.values(), token_id))


def delete_token(token_id: int) -> bool:
    return _execute("DELETE FROM ai_tokens WHERE id = ?", (token_id,)) > 0


# ============================================================
# pending_connections
# ============================================================
_PENDING_COLS = "id, connect_id, client_name, ip, ua, status, created_at"


def create_pending(connect_id: str, client_name: str, ip: str | None, ua: str | None) -> None:
    _execute(
        "INSERT INTO pending_connections (connect_id, client_name, ip, ua, status, created_at)"
        " VALUES (?, ?, ?, ?, 'pending', ?)",
        (connect_id, client_name, ip, ua, utcnow()),
    )


def get_pending(connect_id: str):
    rows = _query(f"SELECT {_PENDING_COLS} FROM pending_connections WHERE connect_id = ?", (connect_id,))
    return _obj(rows[0]) if rows else None


def list_pending(since: dt.datetime) -> list:
    """未过期的待审批连接（since 之后创建的）。"""
    return [_obj(r) for r in _query(
        f"SELECT {_PENDING_COLS} FROM pending_connections"
        " WHERE status = 'pending' AND created_at >= ? ORDER BY created_at DESC", (since,))]


def count_pending(since: dt.datetime) -> int:
    rows = _query("SELECT COUNT(*) AS n FROM pending_connections"
                  " WHERE status = 'pending' AND created_at >= ?", (since,))
    return int(rows[0]["n"]) if rows else 0


def transition_pending(pending_id: int, from_status: str, to_status: str) -> bool:
    """条件更新状态：只有当前状态等于 from_status 才会改，返回是否改成功。
    用来保证「同意只能作用于待审批」「token 只发一次」这类状态机约束（并发下也成立）。"""
    return _execute(
        "UPDATE pending_connections SET status = ? WHERE id = ? AND status = ?",
        (to_status, pending_id, from_status),
    ) > 0


def purge_pending(before: dt.datetime) -> int:
    """清理很久以前的连接申请记录（无论状态）。"""
    return _execute("DELETE FROM pending_connections WHERE created_at < ?", (before,))
