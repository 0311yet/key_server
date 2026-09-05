"""Vercel serverless 入口 - 诊断版本

临时添加 catch-all 诊断路由，输出请求路径和已注册路由列表，
用于定位 Vercel 上返回 404 的根因。
"""
import sys
import os
import traceback

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from app.main import app as _app
except Exception as e:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    _app = FastAPI(title="Import Error")

    @_app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def import_error(path: str):
        return JSONResponse(
            status_code=500,
            content={
                "error": "import_failed",
                "detail": str(e),
                "traceback": traceback.format_exc(),
            },
        )
else:
    # 导入成功：追加诊断 catch-all（优先级最低，仅在无路由匹配时触发）
    from fastapi.responses import JSONResponse

    @_app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def _debug_catch_all(path: str):
        return JSONResponse({
            "debug": True,
            "requested_path": path,
            "route_count": len(_app.routes),
            "registered_routes": [
                {
                    "path": getattr(r, "path", None),
                    "methods": sorted(getattr(r, "methods", []) or []),
                    "type": type(r).__name__,
                }
                for r in _app.routes
            ],
        })


async def app(scope, receive, send):
    """ASGI 入口：修正 Vercel rewrites 带来的路径前缀问题。"""
    if scope["type"] == "http":
        path = scope.get("path", "")
        if path == "/api/index" or path == "/api/index/":
            scope["path"] = "/"
        elif path.startswith("/api/index/"):
            scope["path"] = path[len("/api/index"):]
        scope["raw_path"] = scope["path"].encode()
    await _app(scope, receive, send)


__all__ = ["app"]
