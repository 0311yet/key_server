"""内联 HTML 模板（Vercel 部署时模板以字符串形式打包，不依赖模板文件）。"""
from __future__ import annotations
import json

ASSET_VERSION = "6"  # 改了 static/ 下的 JS / CSS 就加一，强制浏览器和 CDN 取新版


def _esc(s) -> str:
    """HTML 转义：& < > " '"""
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _json_for_html(data) -> str:
    """序列化成可安全嵌入 HTML 的 JSON。

    json.dumps 不转义 < > &，数据里出现 </script> 就能提前闭合标签注入脚本
    （client_name 来自未登录的 /api/connect，攻击者可控）。转成 \\u003c 等形式后
    JSON.parse 结果不变，但 HTML 解析器看不到任何标签。
    """
    return (json.dumps(data, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def _iso(d) -> str:
    return str(d)[:19] if d else ""


def dashboard_data(keys, pending, tokens) -> dict:
    """控制台数据（首屏注入和 /api/dashboard/data 共用同一份结构）。"""
    return {
        "keys": [{"name": k.name, "description": k.description or "",
                  "updated_at": _iso(k.updated_at or k.created_at)} for k in keys],
        "pending": [
            {"connect_id": p.connect_id, "client_name": p.client_name,
             "created_at": _iso(p.created_at), "ip": p.ip or ""}
            for p in pending
        ],
        "tokens": [
            {"id": t.id, "client_name": t.client_name, "status": t.status,
             "created_at": _iso(t.created_at), "expires_at": _iso(t.expires_at),
             "last_used_at": _iso(t.last_used_at), "last_ip": t.last_ip or ""}
            for t in tokens
        ],
    }


def make_dashboard_html(csrf_token: str, data: dict) -> str:
    k_cnt = str(len(data["keys"]))
    p_cnt = str(len(data["pending"]))
    t_cnt = str(len(data["tokens"]))
    csrf_hidden = '<input type="hidden" name="csrf_token" id="csrf-token" value="{}">'.format(_esc(csrf_token))
    return (
        '<!DOCTYPE html>'
        '<html lang="zh-CN">'
        '<head>'
        '    <meta charset="UTF-8">'
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">'
        '    <title>Key Server - 控制台</title>'
        '    <link rel="stylesheet" href="/static/style.css?v=' + ASSET_VERSION + '">'
        # 非可执行的 JSON 块：app.js 用 JSON.parse(textContent) 读取，配合 CSP 禁止内联脚本
        '    <script type="application/json" id="init-data">' + _json_for_html(data) + '</script>'
        '</head>'
        '<body>'
        '<header class="topbar">'
        '    <div class="topbar-left">'
        '        <div class="topbar-logo">&#128273;</div>'
        '        <span class="topbar-title">Key Server</span>'
        '        <div class="topbar-status"><span class="dot"></span>unlocked</div>'
        '    </div>'
        '    <div class="topbar-right">'
        '        <button id="lock-btn" class="logout" title="从 KV 删除数据密钥，所有 AI 客户端立即无法取 key，需重新登录解锁">锁定密钥库</button>'
        '        <button id="logout-btn" class="logout" title="只退出本浏览器，不影响 AI 客户端">退出登录</button>'
        '    </div>'
        '</header>'
        '<div class="wrap">'
        '    <div class="stats-row">'
        '        <div class="stat-card">'
        '            <div class="stat-icon keys">&#128273;</div>'
        '            <div class="stat-info">'
        '                <div class="stat-num" id="stat-keys">' + k_cnt + '</div>'
        '                <div class="stat-label">密钥总数</div>'
        '            </div>'
        '        </div>'
        '        <div class="stat-card">'
        '            <div class="stat-icon pending">&#9203;</div>'
        '            <div class="stat-info">'
        '                <div class="stat-num" id="stat-pending">' + p_cnt + '</div>'
        '                <div class="stat-label">待审批连接</div>'
        '            </div>'
        '        </div>'
        '        <div class="stat-card">'
        '            <div class="stat-icon clients">&#129302;</div>'
        '            <div class="stat-info">'
        '                <div class="stat-num" id="stat-clients">' + t_cnt + '</div>'
        '                <div class="stat-label">已授权客户端</div>'
        '            </div>'
        '        </div>'
        '    </div>'
        '    <section class="panel">'
        '        <h2>待审批连接 <span id="pending-count" class="count">(' + p_cnt + ')</span></h2>'
        '        <p class="hint">AI 第一次连接时会出现在这里，点「同意」授权它获得 30 天访问 token。申请 15 分钟内未处理会自动失效。</p>'
        '        <table>'
        '            <thead><tr><th>名称</th><th>申请时间</th><th>IP</th><th>操作</th></tr></thead>'
        '            <tbody id="pending-tbody"><tr><td colspan="4" class="empty">加载中...</td></tr></tbody>'
        '        </table>'
        '    </section>'
        '    <section class="panel">'
        '        <h2>已授权客户端 <span id="tokens-count" class="count">(' + t_cnt + ')</span></h2>'
        '        <table>'
        '            <thead><tr><th>名称</th><th>状态</th><th>创建</th><th>到期</th><th>最后使用</th><th>操作</th></tr></thead>'
        '            <tbody id="tokens-tbody"><tr><td colspan="6" class="empty">加载中...</td></tr></tbody>'
        '        </table>'
        '    </section>'
        '    <section class="panel">'
        '        <h2>密钥管理 <span id="keys-count" class="count">(' + k_cnt + ')</span></h2>'
        '        <form id="add-form" class="row-form">'
        '            ' + csrf_hidden + ''
        '            <input name="name" placeholder="名称（如 openai）" maxlength="128" required>'
        '            <input name="value" type="password" placeholder="密钥值" autocomplete="off" required>'
        '            <input name="description" placeholder="简介（可选，告诉 AI 这个 key 是干嘛的）" maxlength="500">'
        '            <button type="submit" class="btn-primary">添加/更新</button>'
        '        </form>'
        '        <p class="hint">同名即更新值；简介留空则保留原简介。简介不加密，AI 列出密钥时可见，别在里面写敏感信息。</p>'
        '        <table>'
        '            <thead><tr><th>名称</th><th>简介</th><th>更新时间</th><th>操作</th></tr></thead>'
        '            <tbody id="keys-tbody"><tr><td colspan="4" class="empty">加载中...</td></tr></tbody>'
        '        </table>'
        '    </section>'
        '    <section class="panel">'
        '        <h2>修改管理密码</h2>'
        '        <p class="hint">只需重新包装数据密钥，已存的密钥不受影响。改 LOGIN_PASSWORD 环境变量不会改密码。</p>'
        '        <form id="pwd-form" class="row-form">'
        '            <input name="old_password" type="password" placeholder="原密码" autocomplete="current-password" required>'
        '            <input name="new_password" type="password" placeholder="新密码（至少 12 位）" autocomplete="new-password" minlength="12" required>'
        '            <button type="submit" class="btn-primary">修改</button>'
        '        </form>'
        '    </section>'
        '</div>'
        '<script src="/static/app.js?v=' + ASSET_VERSION + '"></script>'
        '</body>'
        '</html>'
    )


LOGIN_HTML = (
    '<!DOCTYPE html>'
    '<html lang="zh-CN">'
    '<head>'
    '    <meta charset="UTF-8">'
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">'
    '    <title>Key Server - 登录</title>'
    '    <link rel="stylesheet" href="/static/style.css?v=' + ASSET_VERSION + '">'
    '</head>'
    '<body class="login-body">'
    '    <div class="card">'
    '        <div class="logo">&#128273;</div>'
    '        <h1>key_server</h1>'
    '        <p class="hint">authenticate to unlock the key store</p>'
    '        <form id="login-form">'
    '            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">'
    '            <input type="password" name="password" placeholder="管理密码" autocomplete="current-password" required>'
    '            <button type="submit">login</button>'
    '        </form>'
    '        <div id="err" class="err"></div>'
    '    </div>'
    '    <script src="/static/app.js?v=' + ASSET_VERSION + '"></script>'
    '</body>'
    '</html>'
)
