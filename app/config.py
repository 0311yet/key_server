"""配置加载：从环境变量 / .env 读取。"""
from __future__ import annotations
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _env(name: str, default: str | None = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"环境变量 {name} 未设置，请检查 .env")
    return val


def _first_env(*names: str) -> str:
    """按顺序取第一个非空的环境变量（兼容不同平台的命名）。"""
    for n in names:
        v = os.getenv(n, "").strip()
        if v:
            return v
    return ""


# 仅首次初始化时使用：库里还没有密码哈希时，用它建立管理密码。
# 之后以库中哈希为准，改密码请在 Web 控制台操作（改这个变量不会生效）。
LOGIN_PASSWORD: str = os.getenv("LOGIN_PASSWORD", "")
KDF_SALT_HEX: str = _env("KDF_SALT")
SESSION_SECRET: str = _env("SESSION_SECRET")

# 兼容两种数据库模式：
#   - 本地 / VPS：用 DB_FILE（SQLite 文件路径）
#   - Vercel + Turso：用 TURSO_DATABASE_URL + TURSO_AUTH_TOKEN
DB_FILE: str = os.getenv("DB_FILE", str(BASE_DIR / "data" / "key_server.db"))
TURSO_DATABASE_URL: str = os.getenv("TURSO_DATABASE_URL", "")
TURSO_AUTH_TOKEN: str = os.getenv("TURSO_AUTH_TOKEN", "")

# Upstash Redis KV（存数据密钥 + 限流计数）。本地 / 单机开发可留空：
# 此时数据密钥只存进程内存，进程重启即锁定，需重新登录。
# 同时认 Upstash 控制台和 Vercel KV 集成注入的变量名。
KV_URL: str = _first_env("KV_URL", "UPSTASH_REDIS_REST_URL", "KV_REST_API_URL").rstrip("/")
KV_TOKEN: str = _first_env("KV_TOKEN", "UPSTASH_REDIS_REST_TOKEN", "KV_REST_API_TOKEN")
KV_ENABLED: bool = bool(KV_URL and KV_TOKEN)

# 数据密钥在 KV 里的 TTL（秒）：默认 30 天，期间 Web 或 API 有访问就续期
MASTER_KEY_TTL: int = int(os.getenv("MASTER_KEY_TTL", "2592000"))

# Vercel 运行时会注入 VERCEL=1
ON_VERCEL: bool = bool(os.getenv("VERCEL") or os.getenv("VERCEL_URL"))


def kdf_salt_bytes() -> bytes:
    """把十六进制的 salt 转 bytes；如果用户填的不是合法 hex，就当原始字节用。"""
    raw = KDF_SALT_HEX.strip()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")
