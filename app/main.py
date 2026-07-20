"""FastAPI 主应用：Web + AI API。"""
from __future__ import annotations
import os
import datetime as dt
import secrets
from typing import Optional

from fastapi import FastAPI, Request, Response, status, Form
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import config, crypto, db, auth

app = FastAPI(title="Key Server")

# 使用内联模板（兼容 Vercel 部署，模板文件不会被包含在 bundle 中）
import jinja2
from .templates import LOGIN_HTML, DASHBOARD_HTML
_jinja_env = jinja2.Environment(
    loader=jinja2.DictLoader({
        "login.html": LOGIN_HTML,
        "dashboard.html": DASHBOARD_HTML,
    }),
    autoescape=True,
)

def render(name: str, **context) -> HTMLResponse:
    """渲染模板并返回 HTMLResponse。"""
    template = _jinja_env.get_template(name)
    html = template.render(**context)
    return HTMLResponse(html)

app.mount("/static", StaticFiles(directory=str(config.BASE_DIR / "static")), name="static")


# 在每个请求前确保初始化完成（Vercel serverless + 本地都兼容）
@app.middleware("http")
async def init_db_if_needed(request: Request, call_next):
    from . import db as _db, auth as _auth
    # 初始化 DB schema（Turso 模式也适用）
    _db.init_db()
    # 确保密码哈希已建立（首次部署时）
    _auth.ensure_password_hash()
    return await call_next(request)


# ---------- Vercel serverless 不支持 on_event("startup")，已改用 middleware ----------


# ---------- / ----------
@app.get("/", response_class=RedirectResponse)
def root() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=302)


# ---------- /login ----------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render("login.html", request=request)


@app.post("/login")
def do_login(password: str = Form(...), response: Response = None):
    if not auth.verify_and_unlock(password):
        return {"ok": False, "error": "密码错误"}
    response.set_cookie(
        key=auth.SESSION_COOKIE,
        value=auth.make_session_cookie(unlocked=True),
        max_age=auth.SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return {"ok": True}


# ---------- /logout ----------
@app.post("/logout")
def logout(response: Response):
    crypto.lock()
    response.delete_cookie(key=auth.SESSION_COOKIE)
    return {"ok": True}


# ---------- /dashboard ----------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not auth.parse_session_cookie(request.cookies.get(auth.SESSION_COOKIE, "")):
        return RedirectResponse(url="/login", status_code=302)
    # 每次打开控制台，刷新主密钥 KV TTL
    crypto.refresh_ttl()
    keys = db.list_keys()
    pending = db.list_pending()
    tokens = db.list_tokens()
    return render("dashboard.html", request=request, keys=keys, pending=pending, tokens=tokens)


# ---------- /dashboard/add_key ----------
@app.post("/dashboard/add_key")
def add_key(name: str = Form(...), value: str = Form(...), request: Request = None):
    if not auth.parse_session_cookie(request.cookies.get(auth.SESSION_COOKIE, "")):
        return {"ok": False, "error": "未登录"}
    encrypted = crypto.encrypt_key(value)
    db.upsert_key(name, encrypted)
    return {"ok": True}


# ---------- /dashboard/delete_key ----------
@app.post("/dashboard/delete_key")
def delete_key(name: str = Form(...), request: Request = None):
    if not auth.parse_session_cookie(request.cookies.get(auth.SESSION_COOKIE, "")):
        return {"ok": False, "error": "未登录"}
    ok = db.delete_key(name)
    return {"ok": ok}


# ---------- /dashboard/delete_token ----------
@app.post("/dashboard/delete_token")
def delete_token_endpoint(token_id: int = Form(...), request: Request = None):
    if not auth.parse_session_cookie(request.cookies.get(auth.SESSION_COOKIE, "")):
        return {"ok": False, "error": "未登录"}
    ok = db.delete_token(token_id)
    return {"ok": ok}


# ---------- AI 连接流程 ----------
@app.post("/api/connect")
def connect(client_name: str = Form(...), request: Request = None):
    connect_id = secrets.token_hex(32)
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")
    db.create_pending(connect_id, client_name, ip, ua)
    return {"ok": True, "connect_id": connect_id}


@app.get("/api/connect/{connect_id}/status")
def connect_status(connect_id: str):
    pending = db.get_pending(connect_id)
    if not pending:
        return {"status": "invalid"}
    if pending.status == "approved":
        token = auth.create_new_token_value()
        token_hash = auth.token_hash(token)
        new_expires = auth.utcnow_naive() + dt.timedelta(days=auth.TOKEN_TTL_DAYS)
        db.create_token(pending.client_name, token_hash, new_expires, pending.ip)
        db.set_pending_status(pending.id, "issued")
        return {"status": "approved", "token": token}
    if pending.status == "issued":
        return {"status": "approved"}
    if pending.status == "denied":
        return {"status": "denied"}
    return {"status": "pending"}


@app.post("/connect/{connect_id}/approve")
def approve(connect_id: str, request: Request = None):
    if not auth.parse_session_cookie(request.cookies.get(auth.SESSION_COOKIE, "")):
        return {"ok": False, "error": "未登录"}
    pending = db.get_pending(connect_id)
    if not pending:
        return {"ok": False, "error": "连接不存在"}
    db.set_pending_status(pending.id, "approved")
    return {"ok": True}


@app.post("/connect/{connect_id}/deny")
def deny(connect_id: str, request: Request = None):
    if not auth.parse_session_cookie(request.cookies.get(auth.SESSION_COOKIE, "")):
        return {"ok": False, "error": "未登录"}
    pending = db.get_pending(connect_id)
    if not pending:
        return {"ok": False, "error": "连接不存在"}
    db.set_pending_status(pending.id, "denied")
    return {"ok": True}


# ---------- AI Key API（需 Bear token） ----------
@app.get("/api/keys")
def list_keys_api(request: Request):
    if not crypto.is_unlocked():
        return JSONResponse({"ok": False, "error": "服务端锁定，请先登录 Web"},
                            status_code=423)
    token = auth.authenticate_api_request(request)
    if not token:
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=401)
    keys = db.list_keys()
    return {"ok": True,
            "keys": [{"name": k.name, "created_at": k.created_at} for k in keys]}


@app.get("/api/keys/{name}")
def get_key_api(name: str, request: Request):
    if not crypto.is_unlocked():
        return JSONResponse({"ok": False, "error": "服务端锁定，请先登录 Web"},
                            status_code=423)
    token = auth.authenticate_api_request(request)
    if not token:
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=401)
    row = db.get_key(name)
    if not row:
        return JSONResponse({"ok": False, "error": "密钥不存在"}, status_code=404)
    plain = crypto.decrypt_key(row.value)
    return {"ok": True, "key": plain}


@app.post("/api/keys")
def upsert_key_api(name: str = Form(...), value: str = Form(...), request: Request = None):
    if not crypto.is_unlocked():
        return JSONResponse({"ok": False, "error": "服务端锁定，请先登录 Web"},
                            status_code=423)
    token = auth.authenticate_api_request(request)
    if not token:
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=401)
    encrypted = crypto.encrypt_key(value)
    db.upsert_key(name, encrypted)
    return {"ok": True}


@app.delete("/api/keys/{name}")
def delete_key_api(name: str, request: Request):
    if not crypto.is_unlocked():
        return JSONResponse({"ok": False, "error": "服务端锁定，请先登录 Web"},
                            status_code=423)
    token = auth.authenticate_api_request(request)
    if not token:
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=401)
    ok = db.delete_key(name)
    return {"ok": ok}


# ---------- /api/tokens (admin) ----------
@app.get("/api/tokens")
def list_tokens_api(request: Request):
    if not auth.parse_session_cookie(request.cookies.get(auth.SESSION_COOKIE, "")):
        return JSONResponse({"ok": False, "error": "未登录"}, status_code=401)
    tokens = db.list_tokens()
    return {"ok": True, "tokens": [
        {
            "id": t.id, "client_name": t.client_name, "status": t.status,
            "created_at": t.created_at.isoformat() if t.created_at else "",
            "expires_at": t.expires_at.isoformat() if t.expires_at else "",
            "last_used_at": t.last_used_at.isoformat() if t.last_used_at else "",
            "last_ip": t.last_ip,
        } for t in tokens
    ]}


# ---------- /debug ----------
# 仅开发调试用，生产环境应删除
@app.get("/debug")
def debug():
    import hashlib
    from . import config, db as _db
    stored = _db.get_password_hash()
    try:
        algo, iters, salt_hex, stored_hash = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        
        # 测试几个常见密码
        test_passwords = ["test123!@#", config.LOGIN_PASSWORD, "admin", "password"]
        results = {}
        for pwd in test_passwords:
            h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, int(iters))
            results[pwd[:8] + "***" if len(pwd) > 8 else pwd] = (h.hex() == stored_hash)
        
        return {
            "stored_algo": algo,
            "stored_iters": iters,
            "stored_salt_prefix": salt_hex[:8] + "...",
            "env_password_prefix": config.LOGIN_PASSWORD[:4] + "...",
            "env_matches_stored": config.LOGIN_PASSWORD == "test123!@#",
            "test_results": results,
        }
    except Exception as e:
        return {"error": str(e), "stored": stored}


# ---------- /health ----------
@app.get("/health")
def health():
    return {"ok": True, "locked": not crypto.is_unlocked()}
