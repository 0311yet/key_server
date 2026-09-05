"""Vercel serverless 入口：暴露 app/main.py 里的 FastAPI app。

Vercel rewrites 把 /(.*) 转发到 /api/index 后，ASGI scope["path"] 可能
带上 /api/index 前缀，导致 FastAPI 路由匹配失败（返回 404）。
这里用一个轻量 ASGI 包装层去掉前缀，确保路由正常匹配。
"""
import sys
import os

# 确保项目根目录在 sys.path 中（Vercel 运行时可能需要）
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.main import app as _app


async def app(scope, receive, send):
    """ASGI 入口：修正 Vercel rewrites 带来的路径前缀问题。"""
    if scope["type"] == "http":
        path = scope.get("path", "")
        # Vercel 可能把路径设置为 /api/index 或 /api/index/xxx，去掉前缀
        if path == "/api/index" or path == "/api/index/":
            scope["path"] = "/"
        elif path.startswith("/api/index/"):
            scope["path"] = path[len("/api/index"):]
        scope["raw_path"] = scope["path"].encode()
    await _app(scope, receive, send)


__all__ = ["app"]
