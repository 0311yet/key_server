"""认证。

- Web：密码登录 → 校验密码哈希 → 解锁 crypto → 发 session cookie
- AI：Bearer token → sha256 比对 → 过期校验 + 自动续期

所有存入和读出的 datetime 一律按 naive UTC 处理（见 db.utcnow）。
"""
from __future__ import annotations
import datetime as dt
import hashlib
import secrets

from fastapi import Request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from . import config, crypto, db, ratelimit

SESSION_COOKIE = "keyserver_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # Web session 7 天

TOKEN_TTL_DAYS = 30
TOKEN_RENEW_THRESHOLD_DAYS = 7
LAST_USED_WRITE_INTERVAL = dt.timedelta(minutes=5)  # last_used_at 最多每 5 分钟落一次库

MIN_PASSWORD_LENGTH = 12

_serializer = URLSafeTimedSerializer(config.SESSION_SECRET, salt="web-session")


# ---------- 密码哈希：PBKDF2-HMAC-SHA256 ----------

def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return "pbkdf2$200000$" + salt.hex() + "$" + h.hex()


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2":
            return False
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return crypto.secure_eq(h.hex(), hash_hex)
    except Exception:
        return False


# ---------- 启动时确保密码哈希已建立 ----------

def ensure_password_hash() -> None:
    """库里没有密码哈希时，用 LOGIN_PASSWORD 建立（仅首次）。

    之后库中哈希是唯一准绳：不再随环境变量自动重建。旧逻辑会在 LOGIN_PASSWORD
    改动后直接重建哈希，而数据是用旧密码派生的密钥加密的，结果就是全部密钥再也解不开。
    """
    if db.get_password_hash() is not None:
        return
    if not config.LOGIN_PASSWORD:
        raise RuntimeError("首次初始化需要设置 LOGIN_PASSWORD 环境变量")
    db.set_password_hash(_hash_password(config.LOGIN_PASSWORD))


def verify_and_unlock(password: str) -> str | None:
    """校验密码并解锁。成功返回 None，失败返回错误信息。"""
    stored = db.get_password_hash()
    if not stored or not _verify_password(password, stored):
        return "密码错误"
    try:
        crypto.unlock(password)
    except crypto.UnlockError as e:
        return str(e)
    return None


def change_password(old: str, new: str) -> str | None:
    """改管理密码：重新包装数据密钥，与新哈希在同一条语句里写入。成功返回 None。"""
    stored = db.get_password_hash()
    if not stored or not _verify_password(old, stored):
        return "原密码错误"
    if len(new) < MIN_PASSWORD_LENGTH:
        return f"新密码至少 {MIN_PASSWORD_LENGTH} 位"
    if new == old:
        return "新密码与原密码相同"
    try:
        values = crypto.rewrap_settings(old, new)
    except crypto.UnlockError as e:
        return str(e)
    values[db.SETTING_PWD_HASH] = _hash_password(new)
    db.set_settings(values)
    return None


# ---------- Web session ----------

def make_session_cookie() -> str:
    return _serializer.dumps({"u": 1})


def parse_session_cookie(raw: str) -> bool:
    """返回是否有效登录态。"""
    try:
        data = _serializer.loads(raw, max_age=SESSION_MAX_AGE)
        return bool(data.get("u"))
    except (BadSignature, SignatureExpired):
        return False


def is_logged_in(request: Request) -> bool:
    return parse_session_cookie(request.cookies.get(SESSION_COOKIE, ""))


# ---------- AI token ----------

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_new_token_value() -> str:
    return secrets.token_urlsafe(32)


def authenticate_api_request(request: Request):
    """从 Authorization: Bearer xxx 取 token，返回对应 token 行或 None。

    使用记录（last_used_at / last_ip）和续期合并为一次写入，且只在需要时才写，
    避免每次取 key 都多一次跨区域的数据库往返。
    """
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    raw = auth[7:].strip()
    if not raw:
        return None
    row = db.get_token_by_hash(token_hash(raw))
    if not row or row.status != "approved":
        return None
    now = db.utcnow()
    if not row.expires_at or row.expires_at < now:
        return None

    updates = {}
    if (row.expires_at - now) < dt.timedelta(days=TOKEN_RENEW_THRESHOLD_DAYS):
        updates["expires_at"] = now + dt.timedelta(days=TOKEN_TTL_DAYS)
    ip = ratelimit.client_ip(request)
    if not row.last_used_at or now - row.last_used_at > LAST_USED_WRITE_INTERVAL or ip != row.last_ip:
        updates["last_used_at"] = now
        updates["last_ip"] = ip
    if updates:
        db.update_token(row.id, **updates)
    return row
