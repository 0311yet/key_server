"""Inner HTML templates (Vercel deployment: templates are inlined, not file-based)."""
from __future__ import annotations
import json


def _esc(s):
    """HTML escape: & < > only. Double-quote not needed inside HTML attribute values."""
    if s is None:
        return ""
    s = str(s)
    s = s.replace("&", "&")
    s = s.replace("<", "<")
    s = s.replace(">", ">")
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
        '    <title>Key Server - \u63a7\u5236\u53f0</title>'
        '    <link rel="stylesheet" href="/static/style.css">'
        '    <script>'
        '        window.__DATA__ = ' + init_js + ';'
        '    </script>'
        '</head>'
        '<body>'
        '<h1 class="title">Key Server \u63a7\u5236\u53f0</h1>'
        '<div class="wrap">'
        '    <section class="panel">'
        '        <h2>\u5bc6\u94a5\u7ba1\u7406 <span id="keys-count" class="count">(' + k_cnt + ')</span></h2>'
        '        <form id="add-form" class="row-form">'
        '            ' + csrf_hidden + ''
        '            <input name="name" placeholder="\u540d\u79f0\uff08\u5982 openai\uff09" required>'
        '            <input name="value" placeholder="\u5bc6\u94a5\u503c" required>'
        '            <button type="submit">\u6dfb\u52a0/\u66f4\u65b0</button>'
        '        </form>'
        '        <table>'
        '            <thead><tr><th>\u540d\u79f0</th><th>\u521b\u5efa\u65f6\u95f4</th><th>\u64cd\u4f5c</th></tr></thead>'
        '            <tbody id="keys-tbody"><tr><td colspan="3" class="empty">\u52a0\u8f7d\u4e2d...</td></tr></tbody>'
        '        </table>'
        '    </section>'
        '    <section class="panel">'
        '        <h2>\u5f85\u5ba1\u6279\u8fde\u63a5 <span id="pending-count" class="count">(' + p_cnt + ')</span></h2>'
        '        <p class="hint">AI \u7b2c\u4e00\u6b21\u8fde\u63a5\u65f6\u4f1a\u51fa\u73b0\u5728\u8fd9\u91cc\uff0c\u70b9\u300e\u540c\u610f\u300f\u6388\u6743\u5b83\u83b7\u5f97 30 \u5929\u8bbf\u95ee token\u3002</p>'
        '        <table>'
        '            <thead><tr><th>\u540d\u79f0</th><th>\u7533\u8bf7\u65f6\u95f4</th><th>IP</th><th>\u64cd\u4f5c</th></tr></thead>'
        '            <tbody id="pending-tbody"><tr><td colspan="4" class="empty">\u52a0\u8f7d\u4e2d...</td></tr></tbody>'
        '        </table>'
        '    </section>'
        '    <section class="panel">'
        '        <h2>\u5df2\u6388\u6743\u5ba2\u6237\u7aef <span id="tokens-count" class="count">(' + t_cnt + ')</span></h2>'
        '        <table>'
        '            <thead><tr><th>\u540d\u79f0</th><th>\u72b6\u6001</th><th>\u521b\u5efa</th><th>\u5230\u671f</th><th>\u6700\u540e\u4f7f\u7528</th><th>\u64cd\u4f5c</th></tr></thead>'
        '            <tbody id="tokens-tbody"><tr><td colspan="6" class="empty">\u52a0\u8f7d\u4e2d...</td></tr></tbody>'
        '        </table>'
        '    </section>'
        '    <button id="logout-btn" class="logout">\u9000\u51fa\u767b\u5f55</button>'
        '</div>'
        '<script src="/static/app.js?v=2"></script>'
        '</body>'
        '</html>'
    )


LOGIN_HTML = (
    '<!DOCTYPE html>'
    '<html lang="zh-CN">'
    '<head>'
    '    <meta charset="UTF-8">'
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">'
    '    <title>Key Server - \u767b\u5f55</title>'
    '    <link rel="stylesheet" href="/static/style.css">'
    '</head>'
    '<body>'
    '    <div class="card">'
    '        <h1>Key Server</h1>'
    '        <p class="hint">\u8f93\u5165\u7ba1\u7406\u5bc6\u7801\u767b\u5f55\u5e76\u89e3\u9501\u670d\u52a1\u7aef</p>'
    '        <form id="login-form">'
    '            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">'
    '            <input type="password" name="password" placeholder="\u7ba1\u7406\u5bc6\u7801" autocomplete="current-password" required>'
    '            <button type="submit">\u767b\u5f55</button>'
    '        </form>'
    '        <div id="err" class="err"></div>'
    '    </div>'
    '    <script src="/static/app.js?v=2"></script>'
    '</body>'
    '</html>'
)

DASHBOARD_HTML = (
    '<!DOCTYPE html>'
    '<html lang="zh-CN">'
    '<head>'
    '    <meta charset="UTF-8">'
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">'
    '    <title>Key Server - \u63a7\u5236\u53f0</title>'
    '    <link rel="stylesheet" href="/static/style.css">'
    '    <script>window.__DATA__ = {init_data};</script>'
    '</head>'
    '<body>'
    '<h1 class="title">Key Server \u63a7\u5236\u53f0</h1>'
    '<div class="wrap">'
    '    <section class="panel">'
    '        <h2>\u5bc6\u94a5\u7ba1\u7406 <span id="keys-count" class="count">(0)</span></h2>'
    '        <form id="add-form" class="row-form">'
    '            <input type="hidden" name="csrf_token" id="csrf-token" value="{{ csrf_token }}">'
    '            <input name="name" placeholder="\u540d\u79f0\uff08\u5982 openai\uff09" required>'
    '            <input name="value" placeholder="\u5bc6\u94a5\u503c" required>'
    '            <button type="submit">\u6dfb\u52a0/\u66f4\u65b0</button>'
    '        </form>'
    '        <table>'
    '            <thead><tr><th>\u540d\u79f0</th><th>\u521b\u5efa\u65f6\u95f4</th><th>\u64cd\u4f5c</th></tr></thead>'
    '            <tbody id="keys-tbody"><tr><td colspan="3" class="empty">\u52a0\u8f7d\u4e2d...</td></tr></tbody>'
    '        </table>'
    '    </section>'
    '    <section class="panel">'
    '        <h2>\u5f85\u5ba1\u6279\u8fde\u63a5 <span id="pending-count" class="count">(0)</span></h2>'
    '        <p class="hint">AI \u7b2c\u4e00\u6b21\u8fde\u63a5\u65f6\u4f1a\u51fa\u73b0\u5728\u8fd9\u91cc\uff0c\u70b9\u300e\u540c\u610f\u300f\u6388\u6743\u5b83\u83b7\u5f97 30 \u5929\u8bbf\u95ee token\u3002</p>'
    '        <table>'
    '            <thead><tr><th>\u540d\u79f0</th><th>\u7533\u8bf7\u65f6\u95f4</th><th>IP</th><th>\u64cd\u4f5c</th></tr></thead>'
    '            <tbody id="pending-tbody"><tr><td colspan="4" class="empty">\u52a0\u8f7d\u4e2d...</td></tr></tbody>'
    '        </table>'
    '    </section>'
    '    <section class="panel">'
    '        <h2>\u5df2\u6388\u6743\u5ba2\u6237\u7aef <span id="tokens-count" class="count">(0)</span></h2>'
    '        <table>'
    '            <thead><tr><th>\u540d\u79f0</th><th>\u72b6\u6001</th><th>\u521b\u5efa</th><th>\u5230\u671f</th><th>\u6700\u540e\u4f7f\u7528</th><th>\u64cd\u4f5c</th></tr></thead>'
    '            <tbody id="tokens-tbody"><tr><td colspan="6" class="empty">\u52a0\u8f7d\u4e2d...</td></tr></tbody>'
    '        </table>'
    '    </section>'
    '    <button id="logout-btn" class="logout">\u9000\u51fa\u767b\u5f55</button>'
    '</div>'
    '<script src="/static/app.js?v=2"></script>'
    '</body>'
    '</html>'
)