"""方案 B1：口令派生主密钥 + AES-GCM 加解密。

- MASTER_KEY 由登录密码经 scrypt 派生而来，只在内存里。
- 服务端启动后处于 locked 状态，直到有人登录一次 Web 才 unlocked。
- 每条密钥用 AES-GCM 加密，nonce 拼在密文前一起存库。
"""
from __future__ import annotations
import os
import base64
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config


# 内存里的全局状态（进程级单例）
class _State:
    master_key: bytes | None = None

    @property
    def unlocked(self) -> bool:
        return self.master_key is not None


_state = _State()


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
    """尝试用密码解锁服务端：派生主密钥到内存。成功返回 True。

    安全说明：登录密码的校验（与库中哈希比对）应在 auth.py 完成；
    本函数只负责把派生出来的主密钥放进内存。调用方需先校验密码。
    """
    _state.master_key = derive_master_key(password)
    return True


def lock() -> None:
    """锁定服务端（清掉内存主密钥）。一般不主动调用，留作管理用。"""
    _state.master_key = None


def is_unlocked() -> bool:
    return _state.unlocked


def get_master_key() -> bytes:
    if _state.master_key is None:
        raise RuntimeError("服务端处于锁定状态，请先登录 Web 解锁")
    return _state.master_key


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


# 用于比较 token / 密码等，避免时序攻击
def secure_eq(a: str | bytes, b: str | bytes) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)
