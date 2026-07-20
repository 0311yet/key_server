"""认证。

- Web：密码登录 → 校验密码哈希 → 解锁 crypto → 发 session cookie
- AI：Bearer token → sha256 比对 → 过期校验 + 自动续期

注意：SQLite 不保留时区，所有存入和读出的 datetime 一律按 naive UTC 处理，
比较时用 utcnow_naive()，避免 "offset-naive vs offset-aware" 错误。
"""
from __future__ import annotations
import datetime as dt
import hashlib
import secrets

from fastapi import Request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from . import config, crypto, db

SESSION_COOKIE = "keyserver_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # Web session 7 天

TOKEN_TTL_DAYS = 30
TOKEN_RENEW_THRESHOLD_DAYS = 7


def utcnow_naive() -> dt.datetime:
    """SQLite 里所有 datetime 都是 naive UTC，比较时用这个。"""
    return dt.datetime.utcnow()


def utcnow_aware() -> dt.datetime:
    """给用户展示用，带 UTC 时区。"""
    return dt.datetime.now(dt.timezone.utc)


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
        salt = bytes.fromhex(salt_hex)
        iters_n = int(iters)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters_n)
        return crypto.secure_eq(h.hex(), hash_hex)
    except Exception:
        return False


# ---------- 启动时确保密码哈希已建立 ----------

def ensure_password_hash() -> None:
    """确保密码哈希与当前 LOGIN_PASSWORD 一致（首次创建或密码变更后自动重建）。"""
    stored = db.get_password_hash()
    if stored is None:
        db.set_password_hash(_hash_password(config.LOGIN_PASSWORD))
        return
    # 环境变量改了密码？检测并自动更新哈希
    if not _verify_password(config.LOGIN_PASSWORD, stored):
        db.set_password_hash(_hash_password(config.LOGIN_PASSWORD))


def verify_and_unlock(password: str) -> bool:
    stored = db.get_password_hash()
    if not stored:
        return False
    if not _verify_password(password, stored):
        return False
    crypto.unlock(password)
    return True


# ---------- Web session ----------

def make_session_cookie(unlocked: bool) -> str:
    return _serializer.dumps({"u": 1, "unlocked": unlocked})


def parse_session_cookie(raw: str) -> bool:
    """返回是否有效登录态。"""
    try:
        data = _serializer.loads(raw, max_age=SESSION_MAX_AGE)
        return bool(data.get("u"))
    except (BadSignature, SignatureExpired):
        return False


# ---------- AI token ----------

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_new_token_value() -> str:
    return secrets.token_urlsafe(32)


def renew_if_needed(row: db.AIToken) -> None:
    now = utcnow_naive()
    if row.expires_at.tzinfo is not None:
        exp = row.expires_at.replace(tzinfo=None)
    else:
        exp = row.expires_at
    remaining_days = (exp - now).total_seconds() / 86400.0
    if remaining_days < TOKEN_RENEW_THRESHOLD_DAYS:  # 剩余 <7 天则续期到 +30 天
        new_expires = now + dt.timedelta(days=TOKEN_TTL_DAYS)
        db.update_token(row, expires_at=new_expires)


def authenticate_api_request(request: Request) -> db.AIToken | None:
    """从 Authorization: Bearer xxx 取 token，返回对应 AIToken 或 None。"""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    raw = auth[7:].strip()
    if not raw:
        return None
    h = token_hash(raw)
    row = db.get_token_by_hash(h)
    if not row or row.status != "approved":
        return None
    now = utcnow_naive()
    exp = row.expires_at.replace(tzinfo=None) if row.expires_at.tzinfo else row.expires_at
    if exp < now:
        return None
    ip = request.client.host if request.client else None
    db.update_token(row,
                    last_used_at=now,
                    last_ip=ip)
    renew_if_needed(row)
    return row
