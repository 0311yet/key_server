"""Vercel serverless 入口：暴露 app/main.py 里的 FastAPI app。

Vercel Python 运行时默认查找 api/index.py 里的 FastAPI app 实例（名为 app）。
"""
from app.main import app as app

__all__ = ["app"]