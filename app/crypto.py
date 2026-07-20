"""方案 B（Vercel/Turso 适配版）：口令派生主密钥 + AES-GCM 加解密。

- MASTER_KEY 由登录密码经 scrypt 派生而来。
- 主密钥写入 Upstash Redis KV（不存进程内存），带滑窗 TTL。
- 每次加解密操作从 KV 取主密钥。
- 服务端锁定 = KV 中没有主密钥（从未登录或已退出/过期）。
"""
from __future__ import annotations
import os
import base64
import hmac
import httpx

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config

KV_KEY = "master_key"


def _kv_headers() -> dict:
    return {"Authorization": f"Bearer {config.KV_TOKEN}"}


def derive_master_key(password: str) -> bytes:
    """用 scrypt 从密码派生 32 字节主密钥。"""
    kdf = Scrypt(
        salt=config.kdf_salt_bytes(),
        length=32,
        n=2 ** 16,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def unlock(password: str) -> bool:
    """派生主密钥，写入 KV，TTL=30 天。调用方需先验证密码。"""
    mk = derive_master_key(password)
    b64 = base64.b64encode(mk).decode()
    r = httpx.post(
        f"{config.KV_URL}/setex/{KV_KEY}/{config.MASTER_KEY_TTL}/{b64}",
        headers=_kv_headers(),
    )
    r.raise_for_status()
    return True


def lock() -> None:
    """锁定：从 KV 删除主密钥。"""
    r = httpx.post(f"{config.KV_URL}/del/{KV_KEY}",
                   headers=_kv_headers())
    r.raise_for_status()


def refresh_ttl() -> None:
    """滑窗续期主密钥（每次访问控制台时调用）。重置 TTL 为 30 天。"""
    try:
        r = httpx.post(
            f"{config.KV_URL}/expire/{KV_KEY}/{config.MASTER_KEY_TTL}",
            headers=_kv_headers(),
        )
        r.raise_for_status()
    except Exception:
        pass  # 主密钥不在 KV 里就不续，不报错


def is_unlocked() -> bool:
    """检查 KV 中是否有主密钥。"""
    try:
        r = httpx.get(f"{config.KV_URL}/get/{KV_KEY}", headers=_kv_headers())
        r.raise_for_status()
        return r.json().get("result") is not None
    except Exception:
        return False


def get_master_key() -> bytes:
    """从 KV 取主密钥。不存在则抛异常。"""
    r = httpx.get(f"{config.KV_URL}/get/{KV_KEY}", headers=_kv_headers())
    r.raise_for_status()
    result = r.json().get("result")
    if result is None:
        raise RuntimeError("服务端处于锁定状态，请先登录 Web 解锁")
    return base64.b64decode(result)


# ---------- 密钥条目加解密 ----------

def encrypt_key(plaintext: str) -> str:
    """加密一条 key 明文，返回 base64(nonce || ciphertext||tag)，可安全存库。"""
    key = get_master_key()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_key(blob: str) -> str:
    """解密 encrypt_key 的输出，还原 key 明文。"""
    key = get_master_key()
    aes = AESGCM(key)
    raw = base64.b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    pt = aes.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


def secure_eq(a: str | bytes, b: str | bytes) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)