"""FastAPI 主应用：Web + AI API。"""
from __future__ import annotations
import datetime as dt
import hmac
import secrets
from urllib.parse import quote

import jinja2
from fastapi import FastAPI, Request, Response, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import config, crypto, db, auth, ratelimit, templates

app = FastAPI(title="Key Server", docs_url=None, redoc_url=None, openapi_url=None)

# 本地开发（无 TLS）时 cookie 不加 Secure；Vercel 始终 HTTPS
_COOKIE_SECURE = config.ON_VERCEL

PENDING_TTL = dt.timedelta(minutes=15)    # 连接申请多久内可审批（客户端最多轮询 10 分钟）
PENDING_PURGE_AFTER = dt.timedelta(days=1)
MAX_OPEN_PENDING = 20                     # 同时待审批的申请上限，防止刷屏
MAX_KEY_NAME = 128
MAX_DESCRIPTION = 500

# 内容安全策略：禁止内联脚本和外部资源，即便再出现注入点也无法执行脚本
_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

_jinja_env = jinja2.Environment(
    loader=jinja2.DictLoader({"login.html": templates.LOGIN_HTML}),
    autoescape=True,
)

app.mount("/static", StaticFiles(directory=str(config.BASE_DIR / "static")), name="static")


# ============================================================
# 中间件（后注册的先执行：路径修正必须最先跑，所以放最后注册）
# ============================================================
_init_done = False


@app.middleware("http")
async def _init_and_headers(request: Request, call_next):
    """首个请求时建表 / 建立密码哈希（Vercel serverless 与本地通用），并统一加安全响应头。"""
    global _init_done
    if not _init_done:
        db.init_db()
        auth.ensure_password_hash()
        _init_done = True
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith(("/api/", "/dashboard")):
        response.headers.setdefault("Cache-Control", "no-store")  # 含密钥明文 / 控制台数据，禁止任何缓存
    return response


@app.middleware("http")
async def _vercel_path_fix(request: Request, call_next):
    """vercel.json 把所有路径改写到 /api/index/$1，这里剥掉前缀还原真实路径。"""
    path = request.scope.get("path", "")
    if path in ("/api/index", "/api/index/"):
        request.scope["path"] = "/"
        request.scope["raw_path"] = b"/"
    elif path.startswith("/api/index/"):
        request.scope["path"] = path[len("/api/index"):]
        request.scope["raw_path"] = request.scope["path"].encode()
    return await call_next(request)


# ============================================================
# 工具
# ============================================================
def _make_csrf_token() -> str:
    return secrets.token_hex(32)


def _check_csrf(request: Request) -> None:
    """double-submit cookie：cookie 与 X-CSRF-Token 头必须一致。"""
    cookie_token = request.cookies.get("csrf_token", "")
    header_token = request.headers.get("x-csrf-token", "")
    if not cookie_token or not header_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    if not hmac.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")


def _set_cookie(response: Response, name: str, value: str, max_age: int = 3600) -> None:
    flags = f"Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax"
    if _COOKIE_SECURE:
        flags += "; Secure"
    response.headers.append("Set-Cookie", f"{name}={quote(value, safe='')}; {flags}")


def _clear_session(response: Response) -> None:
    response.headers.append("Set-Cookie", f"{auth.SESSION_COOKIE}=; Path=/; Max-Age=0")
    response.headers.append("Set-Cookie", "csrf_token=; Path=/; Max-Age=0")


def _err(status: int, msg: str, **extra) -> JSONResponse:
    return JSONResponse({"ok": False, "error": msg, **extra}, status_code=status)


def _web_guard(request: Request, need_unlocked: bool = False) -> JSONResponse | None:
    """控制台写操作的统一校验：登录态 + CSRF（+ 已解锁）。通过返回 None。"""
    if not auth.is_logged_in(request):
        return _err(401, "未登录")
    _check_csrf(request)
    if need_unlocked and not crypto.is_unlocked():
        return _err(423, "密钥库已锁定，请重新登录解锁", locked=True)
    return None


def _api_guard(request: Request) -> JSONResponse | None:
    """AI API 的统一校验：先鉴权再查锁定状态（未授权的请求拿不到任何状态信息）。"""
    if not auth.authenticate_api_request(request):
        return _err(401, "未授权")
    if not crypto.is_unlocked():
        return _err(423, "服务端锁定，请先登录 Web")
    crypto.refresh_ttl()  # AI 在用也算活跃，滑窗续期
    return None


def _clean_name(name: str) -> str | None:
    name = (name or "").strip()
    return name if 0 < len(name) <= MAX_KEY_NAME else None


def _desc_error(description: str | None) -> JSONResponse | None:
    if description is not None and len(description.strip()) > MAX_DESCRIPTION:
        return _err(400, f"简介最多 {MAX_DESCRIPTION} 个字符")
    return None


def _dashboard_data() -> dict:
    return templates.dashboard_data(
        db.list_keys(), db.list_pending(db.utcnow() - PENDING_TTL), db.list_tokens())


# ============================================================
# Web
# ============================================================
@app.get("/", response_class=RedirectResponse)
def root() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page():
    token = _make_csrf_token()
    resp = HTMLResponse(_jinja_env.get_template("login.html").render(csrf_token=token))
    _set_cookie(resp, "csrf_token", token)
    return resp


@app.post("/login")
def do_login(request: Request, password: str = Form(...)):
    ip = ratelimit.client_ip(request)
    if not ratelimit.allow("login", ip) or not ratelimit.allow("login_global"):
        return _err(429, "请求过于频繁，请稍后再试")
    _check_csrf(request)
    error = auth.verify_and_unlock(password)
    if error:
        return {"ok": False, "error": error}
    resp = JSONResponse({"ok": True})
    _set_cookie(resp, auth.SESSION_COOKIE, auth.make_session_cookie(), max_age=auth.SESSION_MAX_AGE)
    return resp


@app.post("/logout")
def logout(request: Request):
    """只退出本浏览器的登录态，不锁定密钥库（AI 客户端照常可用）。"""
    _check_csrf(request)
    resp = JSONResponse({"ok": True})
    _clear_session(resp)
    return resp


@app.post("/lock")
def lock(request: Request):
    """锁定密钥库：删除 KV 里的数据密钥，所有 AI 请求立即 423，并退出登录。"""
    if (r := _web_guard(request)):
        return r
    crypto.lock()
    resp = JSONResponse({"ok": True})
    _clear_session(resp)
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    # 会话还在但密钥库已锁（TTL 到期或别处点了锁定）：回登录页，登录即解锁
    if not auth.is_logged_in(request) or not crypto.is_unlocked():
        return RedirectResponse(url="/login", status_code=302)
    crypto.refresh_ttl()
    token = _make_csrf_token()
    resp = HTMLResponse(templates.make_dashboard_html(csrf_token=token, data=_dashboard_data()))
    _set_cookie(resp, "csrf_token", token)
    return resp


@app.get("/api/dashboard/data")
def dashboard_data_api(request: Request):
    """session 认证，供前端轮询。"""
    if not auth.is_logged_in(request):
        return _err(401, "未登录")
    if not crypto.is_unlocked():
        return _err(423, "密钥库已锁定", locked=True)
    crypto.refresh_ttl()
    return {"ok": True, **_dashboard_data()}


@app.post("/dashboard/add_key")
def add_key(request: Request, name: str = Form(...), value: str = Form(...),
            description: str | None = Form(None)):
    if (r := _web_guard(request, need_unlocked=True)):
        return r
    name = _clean_name(name)
    if not name or not value:
        return _err(400, f"名称需为 1–{MAX_KEY_NAME} 个字符，值不能为空")
    if (r := _desc_error(description)):
        return r
    # 表单里简介留空 = 不改原简介（只更新值）；要清空简介用「编辑简介」
    db.upsert_key(name, crypto.encrypt_key(value), (description or "").strip() or None)
    return {"ok": True}


@app.post("/dashboard/reveal_key")
def reveal_key(request: Request, name: str = Form(...)):
    """控制台查看密钥明文：POST + CSRF（不能被跨站触发），按需单条取，不进首屏数据。"""
    if (r := _web_guard(request, need_unlocked=True)):
        return r
    row = db.get_key(name)
    if not row:
        return _err(404, "密钥不存在")
    return {"ok": True, "key": crypto.decrypt_key(row.value)}


@app.post("/dashboard/set_description")
def set_description(request: Request, name: str = Form(...), description: str = Form("")):
    if (r := _web_guard(request)):
        return r
    if (r := _desc_error(description)):
        return r
    if not db.set_description(name, description.strip()):
        return _err(404, "密钥不存在")
    return {"ok": True}


@app.post("/dashboard/delete_key")
def delete_key(request: Request, name: str = Form(...)):
    if (r := _web_guard(request)):
        return r
    return {"ok": db.delete_key(name)}


@app.post("/dashboard/delete_token")
def delete_token_endpoint(request: Request, token_id: int = Form(...)):
    if (r := _web_guard(request)):
        return r
    return {"ok": db.delete_token(token_id)}


@app.post("/dashboard/change_password")
def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...)):
    if (r := _web_guard(request)):
        return r
    if not ratelimit.allow("login", ratelimit.client_ip(request)):
        return _err(429, "请求过于频繁，请稍后再试")
    error = auth.change_password(old_password, new_password)
    return {"ok": False, "error": error} if error else {"ok": True}


# ============================================================
# AI 连接审批流程
# ============================================================
@app.post("/api/connect")
def connect(request: Request, client_name: str = Form(...)):
    client_name = (client_name or "").strip()[:64]
    if not client_name:
        return _err(400, "client_name 不能为空")
    if not ratelimit.allow("connect", ratelimit.client_ip(request)):
        return _err(429, "请求过于频繁，请稍后再试")
    now = db.utcnow()
    db.purge_pending(now - PENDING_PURGE_AFTER)
    if db.count_pending(now - PENDING_TTL) >= MAX_OPEN_PENDING:
        return _err(429, "待审批的连接过多，请先在控制台处理")
    connect_id = secrets.token_hex(32)
    db.create_pending(connect_id, client_name, ratelimit.client_ip(request),
                      request.headers.get("user-agent", "")[:256])
    return {"ok": True, "connect_id": connect_id}


def _expired(pending) -> bool:
    return not pending.created_at or pending.created_at < db.utcnow() - PENDING_TTL


@app.get("/api/connect/{connect_id}/status")
def connect_status(connect_id: str):
    pending = db.get_pending(connect_id)
    if not pending:
        return {"status": "invalid"}
    if pending.status == "approved":
        # 条件更新抢占 approved → issued：并发轮询时只有一个请求能拿到 token
        if not db.transition_pending(pending.id, "approved", "issued"):
            return {"status": "approved"}
        token = auth.create_new_token_value()
        try:
            db.create_token(pending.client_name, auth.token_hash(token),
                            db.utcnow() + dt.timedelta(days=auth.TOKEN_TTL_DAYS), pending.ip)
        except Exception:
            db.transition_pending(pending.id, "issued", "approved")  # 回滚，客户端下次轮询重试
            raise
        return {"status": "approved", "token": token}
    if pending.status == "issued":
        return {"status": "approved"}
    if pending.status == "denied":
        return {"status": "denied"}
    if _expired(pending):
        return {"status": "expired"}
    return {"status": "pending"}


def _decide(request: Request, connect_id: str, to_status: str):
    if (r := _web_guard(request)):
        return r
    pending = db.get_pending(connect_id)
    if not pending:
        return {"ok": False, "error": "连接不存在"}
    if pending.status != "pending":
        return {"ok": False, "error": f"该申请已处理（{pending.status}）"}
    if _expired(pending):
        return {"ok": False, "error": "该申请已过期，请让客户端重新发起"}
    if not db.transition_pending(pending.id, "pending", to_status):
        return {"ok": False, "error": "该申请状态已变化，请刷新"}
    return {"ok": True}


@app.post("/connect/{connect_id}/approve")
def approve(connect_id: str, request: Request):
    return _decide(request, connect_id, "approved")


@app.post("/connect/{connect_id}/deny")
def deny(connect_id: str, request: Request):
    return _decide(request, connect_id, "denied")


# ============================================================
# AI Key API（Bearer token）
# ============================================================
@app.get("/api/keys")
def list_keys_api(request: Request):
    if (r := _api_guard(request)):
        return r
    return {"ok": True, "keys": [
        {"name": k.name, "description": k.description or "",
         "created_at": k.created_at.isoformat() if k.created_at else "",
         "updated_at": k.updated_at.isoformat() if k.updated_at else ""}
        for k in db.list_keys()]}


@app.get("/api/keys/{name}")
def get_key_api(name: str, request: Request):
    if (r := _api_guard(request)):
        return r
    row = db.get_key(name)
    if not row:
        return _err(404, "密钥不存在")
    return {"ok": True, "key": crypto.decrypt_key(row.value), "description": row.description or ""}


@app.post("/api/keys")
def upsert_key_api(request: Request, name: str = Form(...), value: str = Form(...),
                   description: str | None = Form(None)):
    """description 不传 = 保留原简介；传了就覆盖（传空字符串即清空）。"""
    if (r := _api_guard(request)):
        return r
    name = _clean_name(name)
    if not name or not value:
        return _err(400, f"名称需为 1–{MAX_KEY_NAME} 个字符，值不能为空")
    if (r := _desc_error(description)):
        return r
    db.upsert_key(name, crypto.encrypt_key(value))
    if description is not None:
        db.set_description(name, description.strip())
    return {"ok": True}


@app.post("/api/keys/{name}/description")
def set_description_api(name: str, request: Request, description: str = Form("")):
    if (r := _api_guard(request)):
        return r
    if (r := _desc_error(description)):
        return r
    if not db.set_description(name, description.strip()):
        return _err(404, "密钥不存在")
    return {"ok": True}


@app.delete("/api/keys/{name}")
def delete_key_api(name: str, request: Request):
    if (r := _api_guard(request)):
        return r
    if not db.delete_key(name):
        return _err(404, "密钥不存在")
    return {"ok": True}


@app.get("/health")
def health():
    return {"ok": True, "locked": not crypto.is_unlocked()}
