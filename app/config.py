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


LOGIN_PASSWORD: str = _env("LOGIN_PASSWORD")
KDF_SALT_HEX: str = _env("KDF_SALT")
SESSION_SECRET: str = _env("SESSION_SECRET")

# 兼容两种数据库模式：
#   - 本地 / VPS：用 DB_FILE（sqlite:///...）
#   - Vercel + Turso：用 TURSO_DATABASE_URL + TURSO_AUTH_TOKEN
DB_FILE: str = os.getenv("DB_FILE", str(BASE_DIR / "data" / "key_server.db"))
TURSO_DATABASE_URL: str = os.getenv("TURSO_DATABASE_URL", "")
TURSO_AUTH_TOKEN: str = os.getenv("TURSO_AUTH_TOKEN", "")

# Upstash Redis KV（存主密钥）
KV_URL: str = _env("KV_URL")
KV_TOKEN: str = _env("KV_TOKEN")

# 主密钥在 KV 里的 TTL（秒）：默认 30 天
MASTER_KEY_TTL: int = int(os.getenv("MASTER_KEY_TTL", "2592000"))


def kdf_salt_bytes() -> bytes:
    """把十六进制的 salt 转 bytes；如果用户填的不是合法 hex，就当原始字节用。"""
    raw = KDF_SALT_HEX.strip()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")