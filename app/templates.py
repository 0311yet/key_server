"""Inner HTML templates (Vercel deployment: templates are inlined, not file-based)."""
from __future__ import annotations
import json

def _esc(s):
    """HTML escape: & < > " '"""
    if s is None:
        return ""
    s = str(s)
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", "&#39;")
    return s

def _iso(dt):
    return str(dt)[:19]

def make_dashboard_html(csrf_token: str, keys, pending, tokens) -> str:
    data = {
        "keys": [
            {"name": k.name, "created_at": _iso(k.created_at) if k.created_at else ""}
            for k in (keys or [])
        ],
        "pending": [
            {
                "connect_id": p.connect_id,
                "client_name": p.client_name,
                "created_at": _iso(p.created_at) if p.created_at else "",
                "ip": p.ip or "",
            }
            for p in (pending or [])
        ],
        "tokens": [
            {
                "id": t.id,
                "client_name": t.client_name,
                "status": t.status,
                "created_at": _iso(t.created_at) if t.created_at else "",
                "expires_at": _iso(t.expires_at) if t.expires_at else "",
                "last_used_at": (_iso(t.last_used_at) if getattr(t, "last_used_at", None) else ""),
            }
            for t in (tokens or [])
        ],
    }
    init_js = json.dumps(data, ensure_ascii=False)
    csrf_hidden = '<input type="hidden" name="csrf_token" id="csrf-token" value="{}">'.format(_esc(csrf_token))
    k_cnt = str(len(keys) if keys else 0)
    p_cnt = str(len(pending) if pending else 0)
    t_cnt = str(len(tokens) if tokens else 0)
    return (
        '<!DOCTYPE html>'
        '<html lang="zh-CN">'
        '<head>'
        '    <meta charset="UTF-8">'
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">'
        '    <title>Key Server - 控制台</title>'
        '    <link rel="stylesheet" href="/static/style.css?v=4">'
        '    <script>'
        '        window.__DATA__ = ' + init_js + ';'
        '    </script>'
        '</head>'
        '<body>'
        '<!-- 顶部导航栏 -->'
        '<header class="topbar">'
        '    <div class="topbar-left">'
        '        <div class="topbar-logo">&#128273;</div>'
        '        <span class="topbar-title">Key Server</span>'
        '        <div class="topbar-status"><span class="dot"></span>unlocked</div>'
        '    </div>'
        '    <div class="topbar-right">'
        '        <button id="logout-btn" class="logout">退出登录</button>'
        '    </div>'
        '</header>'
        '<div class="wrap">'
        '    <!-- 统计卡片 -->'
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
        '        <p class="hint">AI 第一次连接时会出现在这里，点「同意」授权它获得 30 天访问 token。</p>'
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
        '            <input name="name" placeholder="名称（如 openai）" required>'
        '            <input name="value" placeholder="密钥值" required>'
        '            <button type="submit" class="btn-primary">添加/更新</button>'
        '        </form>'
        '        <table>'
        '            <thead><tr><th>名称</th><th>创建时间</th><th>操作</th></tr></thead>'
        '            <tbody id="keys-tbody"><tr><td colspan="3" class="empty">加载中...</td></tr></tbody>'
        '        </table>'
        '    </section>'
        '</div>'
        '<script src="/static/app.js?v=4"></script>'
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
    '    <link rel="stylesheet" href="/static/style.css?v=4">'
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
    '    <script src="/static/app.js?v=4"></script>'
    '</body>'
    '</html>'
)

DASHBOARD_HTML = (
    '<!DOCTYPE html>'
    '<html lang="zh-CN">'
    '<head>'
    '    <meta charset="UTF-8">'
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">'
    '    <title>Key Server - 控制台</title>'
    '    <link rel="stylesheet" href="/static/style.css?v=4">'
    '    <script>window.__DATA__ = {init_data};</script>'
    '</head>'
    '<body>'
    '<header class="topbar">'
    '    <div class="topbar-left">'
    '        <div class="topbar-logo">&#128273;</div>'
    '        <span class="topbar-title">Key Server</span>'
    '        <div class="topbar-status"><span class="dot"></span>unlocked</div>'
    '    </div>'
    '    <div class="topbar-right">'
    '        <button id="logout-btn" class="logout">退出登录</button>'
    '    </div>'
    '</header>'
    '<div class="wrap">'
    '    <div class="stats-row">'
    '        <div class="stat-card"><div class="stat-icon keys">&#128273;</div><div class="stat-info"><div class="stat-num">0</div><div class="stat-label">密钥总数</div></div></div>'
    '        <div class="stat-card"><div class="stat-icon pending">&#9203;</div><div class="stat-info"><div class="stat-num">0</div><div class="stat-label">待审批连接</div></div></div>'
    '        <div class="stat-card"><div class="stat-icon clients">&#129302;</div><div class="stat-info"><div class="stat-num">0</div><div class="stat-label">已授权客户端</div></div></div>'
    '    </div>'
    '    <section class="panel">'
    '        <h2>待审批连接 <span id="pending-count" class="count">(0)</span></h2>'
    '        <p class="hint">AI 第一次连接时会出现在这里，点「同意」授权它获得 30 天访问 token。</p>'
    '        <table>'
    '            <thead><tr><th>名称</th><th>申请时间</th><th>IP</th><th>操作</th></tr></thead>'
    '            <tbody id="pending-tbody"><tr><td colspan="4" class="empty">加载中...</td></tr></tbody>'
    '        </table>'
    '    </section>'
    '    <section class="panel">'
    '        <h2>已授权客户端 <span id="tokens-count" class="count">(0)</span></h2>'
    '        <table>'
    '            <thead><tr><th>名称</th><th>状态</th><th>创建</th><th>到期</th><th>最后使用</th><th>操作</th></tr></thead>'
    '            <tbody id="tokens-tbody"><tr><td colspan="6" class="empty">加载中...</td></tr></tbody>'
    '        </table>'
    '    </section>'
    '    <section class="panel">'
    '        <h2>密钥管理 <span id="keys-count" class="count">(0)</span></h2>'
    '        <form id="add-form" class="row-form">'
    '            <input type="hidden" name="csrf_token" id="csrf-token" value="{{ csrf_token }}">'
    '            <input name="name" placeholder="名称（如 openai）" required>'
    '            <input name="value" placeholder="密钥值" required>'
    '            <button type="submit" class="btn-primary">添加/更新</button>'
    '        </form>'
    '        <table>'
    '            <thead><tr><th>名称</th><th>创建时间</th><th>操作</th></tr></thead>'
    '            <tbody id="keys-tbody"><tr><td colspan="3" class="empty">加载中...</td></tr></tbody>'
    '        </table>'
    '    </section>'
    '</div>'
    '<script src="/static/app.js?v=4"></script>'
    '</body>'
    '</html>'
)
