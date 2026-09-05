"""Vercel serverless 入口：直接暴露 FastAPI app 实例。

注意：Vercel Python 运行时要求 api/index.py 导出的 app 必须是
FastAPI/Starlette 实例，不能是普通 ASGI 函数（否则返回默认 404）。
路径修正等逻辑放在 app/main.py 的中间件里处理。
"""
from app.main import app

__all__ = ["app"]
