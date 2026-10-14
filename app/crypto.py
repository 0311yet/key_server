"""信封加密：密码派生 KEK → 包装数据密钥 DEK → DEK 用 AES-GCM 加解密每条密钥。

- KEK = scrypt(登录密码, KDF_SALT)，只在登录 / 改密码时临时算出，不落盘。
- DEK 是 32 字节随机数，用 KEK 包装后存在 settings.dek_wrapped。
  改密码只需重新包装 DEK，已存的密钥数据不用重新加密。
- 旧版本直接用 scrypt(密码) 当主密钥加密数据。升级后首次登录时，
  若库里已有数据却没有 dek_wrapped，就把这把旧主密钥本身当作 DEK 包装起来，数据无需迁移。
- 解锁 = DEK 写入 Upstash KV（带 TTL，有访问就滑窗续期）；锁定 = 从 KV 删除。
- 各 serverless 实例在进程内缓存 DEK，但每 60 秒回查一次 KV，
  这样在任一实例上「锁定」后，其他实例最多 60 秒内也会跟着锁定。
"""
from __future__ import annotations
import base64
import hmac
import os
import time

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config, db

KV_KEY = "master_key"            # 沿用旧键名：升级后 KV 里现存的旧主密钥就是 DEK，无需重新登录
_WRAP_AAD = b"keyserver-dek-v1"
_RECHECK_SECONDS = 60            # 进程缓存回查 KV 的间隔
_REFRESH_SECONDS = 3600          # 滑窗续期 TTL 的最小间隔

_cached_dek: bytes | None = None
_cached_at: float = 0.0
_last_refresh: float = 0.0

_kv_client: httpx.Client | None = None


class UnlockError(Exception):
    pass


# ---------------------------------------------------------------- KV
def _client() -> httpx.Client:
    global _kv_client
    if _kv_client is None:
        _kv_client = httpx.Client(
            base_url=config.KV_URL, timeout=10.0,
            headers={"Authorization": f"Bearer {config.KV_TOKEN}"},
        )
    return _kv_client


def _kv(*command):
    """执行一条 Upstash REST 命令（POST 根路径，JSON 数组形式），返回 result。"""
    r = _client().post("/", json=[str(c) for c in command])
    r.raise_for_status()
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"KV error: {body['error']}")
    return body.get("result")


def kv_pipeline(commands: list[list]) -> list:
    """一次请求执行多条命令（限流用）。"""
    r = _client().post("/pipeline", json=[[str(c) for c in cmd] for cmd in commands])
    r.raise_for_status()
    return [item.get("result") for item in r.json()]


# ---------------------------------------------------------------- KEK / DEK
def derive_kek(password: str) -> bytes:
    """用 scrypt 从密码派生 32 字节 KEK（旧版本里它就是主密钥）。"""
    kdf = Scrypt(salt=config.kdf_salt_bytes(), length=32, n=2 ** 16, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def wrap_dek(dek: bytes, kek: bytes) -> str:
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(kek).encrypt(nonce, dek, _WRAP_AAD)).decode("ascii")


def unwrap_dek(wrapped: str, kek: bytes) -> bytes:
    raw = base64.b64decode(wrapped)
    try:
        return AESGCM(kek).decrypt(raw[:12], raw[12:], _WRAP_AAD)
    except InvalidTag:
        raise UnlockError("无法解开数据密钥：KDF_SALT 是否被修改过？")


def load_or_create_dek(password: str) -> bytes:
    """用（已验证过的）密码取出 DEK；首次运行或从旧版本升级时创建并保存包装后的 DEK。"""
    kek = derive_kek(password)
    wrapped = db.get_setting(db.SETTING_DEK_WRAPPED)
    if wrapped:
        return unwrap_dek(wrapped, kek)
    # 旧版本的数据是直接用 KEK 加密的：沿用它作为 DEK；全新部署则随机生成
    dek = kek if db.has_keys() else os.urandom(32)
    db.set_settings({db.SETTING_DEK_WRAPPED: wrap_dek(dek, kek)})
    return dek


def rewrap_settings(old_password: str, new_password: str) -> dict[str, str]:
    """改密码：用旧密码解开 DEK，再用新密码包装。返回要写入 settings 的新值。"""
    dek = load_or_create_dek(old_password)
    return {db.SETTING_DEK_WRAPPED: wrap_dek(dek, derive_kek(new_password))}


# ---------------------------------------------------------------- 锁定状态
def _set_cache(dek: bytes | None) -> None:
    global _cached_dek, _cached_at
    _cached_dek, _cached_at = dek, time.time()


def unlock(password: str) -> None:
    """解锁：取出 DEK，写入进程缓存和 KV（带 TTL）。调用方需先验证密码。"""
    global _last_refresh
    dek = load_or_create_dek(password)
    _set_cache(dek)
    if config.KV_ENABLED:
        _kv("SET", KV_KEY, base64.b64encode(dek).decode(), "EX", config.MASTER_KEY_TTL)
        _last_refresh = time.time()


def lock() -> None:
    """锁定：从 KV 删除 DEK，并清除进程缓存。"""
    _set_cache(None)
    if config.KV_ENABLED:
        _kv("DEL", KV_KEY)


def refresh_ttl() -> None:
    """滑窗续期（Web 或 API 有访问时调用）。每实例每小时最多真正请求一次 KV。"""
    global _last_refresh
    if not config.KV_ENABLED or time.time() - _last_refresh < _REFRESH_SECONDS:
        return
    try:
        _kv("EXPIRE", KV_KEY, config.MASTER_KEY_TTL)
        _last_refresh = time.time()
    except Exception:
        pass


def _current_dek() -> bytes | None:
    """取 DEK：进程缓存在回查间隔内直接用，过期则回查 KV（拿到就回填，拿不到即锁定）。"""
    if not config.KV_ENABLED:
        return _cached_dek
    if _cached_dek is not None and time.time() - _cached_at < _RECHECK_SECONDS:
        return _cached_dek
    try:
        result = _kv("GET", KV_KEY)
    except Exception:
        # KV 暂时不可用：已有缓存就继续用，避免一次网络抖动导致整个服务锁定
        return _cached_dek
    _set_cache(base64.b64decode(result) if result else None)
    return _cached_dek


def is_unlocked() -> bool:
    return _current_dek() is not None


def get_master_key() -> bytes:
    dek = _current_dek()
    if dek is None:
        raise RuntimeError("服务端处于锁定状态，请先登录 Web 解锁")
    return dek


# ---------------------------------------------------------------- 密钥条目加解密
def encrypt_key(plaintext: str) -> str:
    """加密一条 key 明文，返回 base64(nonce || ciphertext||tag)，可安全存库。"""
    nonce = os.urandom(12)
    ct = AESGCM(get_master_key()).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_key(blob: str) -> str:
    """解密 encrypt_key 的输出，还原 key 明文。"""
    raw = base64.b64decode(blob.encode("ascii"))
    return AESGCM(get_master_key()).decrypt(raw[:12], raw[12:], None).decode("utf-8")


def secure_eq(a: str | bytes, b: str | bytes) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)
