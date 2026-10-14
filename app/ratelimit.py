"""限流：固定时间窗计数。
配了 KV 时计数存在 Upstash（所有 serverless 实例共享，真正有效）；
没配或 KV 出错时退回进程内存计数（仅对单进程有效）。
"""
from __future__ import annotations
import time

from fastapi import Request

from . import config, crypto

WINDOW = 60  # 秒
LIMITS = {
    "login": 10,          # 每 IP 每分钟登录尝试
    "login_global": 30,   # 全站每分钟登录尝试（防分散 IP 的暴力破解）
    "connect": 10,        # 每 IP 每分钟连接申请
}

_memory: dict[str, tuple[int, int]] = {}  # key -> (窗口编号, 计数)


def client_ip(request: Request) -> str:
    """取客户端 IP。Vercel 边缘会覆盖 x-real-ip / x-forwarded-for，可信；本地直接用 socket 地址。"""
    if config.ON_VERCEL:
        ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0]
        if ip.strip():
            return ip.strip()
    return request.client.host if request.client else "unknown"


def _hit_memory(key: str, bucket: int) -> int:
    b, n = _memory.get(key, (bucket, 0))
    n = n + 1 if b == bucket else 1
    _memory[key] = (bucket, n)
    if len(_memory) > 10000:  # 防止内存无限增长
        _memory.clear()
    return n


def allow(kind: str, subject: str = "*") -> bool:
    """记一次并返回是否仍在限额内。"""
    bucket = int(time.time() // WINDOW)
    count = None
    if config.KV_ENABLED:
        key = f"rl:{kind}:{subject}:{bucket}"
        try:
            count = int(crypto.kv_pipeline([["INCR", key], ["EXPIRE", key, WINDOW * 2]])[0])
        except Exception:
            count = None
    if count is None:
        count = _hit_memory(f"{kind}:{subject}", bucket)
    return count <= LIMITS[kind]


def reset() -> None:
    """测试用：清空内存计数。"""
    _memory.clear()
