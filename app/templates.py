"""内联 HTML 模板（Vercel 部署：模板文件不会被打包，必须内联）。"""

LOGIN_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Key Server - 登录</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="card">
        <h1>🔑 Key Server</h1>
        <p class="hint">输入管理密码登录并解锁服务端</p>
        <form id="login-form">
            <input type="password" name="password" placeholder="管理密码" autocomplete="current-password" required>
            <button type="submit">登录</button>
        </form>
        <div id="err" class="err"></div>
    </div>
    <script src="/static/app.js"></script>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Key Server - 控制台</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<h1 class="title">🔑 Key Server 控制台</h1>

<div class="wrap">
    <!-- 密钥管理 -->
    <section class="panel">
        <h2>密钥管理 <span class="count">({{ keys|length }})</span></h2>
        <form id="add-form" class="row-form">
            <input name="name" placeholder="名称（如 openai）" required>
            <input name="value" placeholder="密钥值" required>
            <button type="submit">添加/更新</button>
        </form>
        <table>
            <thead><tr><th>名称</th><th>创建时间</th><th>操作</th></tr></thead>
            <tbody>
            {% for k in keys %}
            <tr>
                <td>{{ k.name }}</td>
                <td>{{ k.created_at.isoformat() if k.created_at else '' }}</td>
                <td><button class="del" data-name="{{ k.name }}">删除</button></td>
            </tr>
            {% endfor %}
            {% if keys|length == 0 %}
            <tr><td colspan="3" class="empty">暂无密钥</td></tr>
            {% endif %}
            </tbody>
        </table>
    </section>

    <!-- 待审批连接 -->
    <section class="panel">
        <h2>待审批连接 <span class="count">({{ pending|length }})</span></h2>
        <p class="hint">AI 第一次连接时会出现在这里，点【同意】授权它获得 30 天访问 token。</p>
        <table>
            <thead><tr><th>名称</th><th>申请时间</th><th>IP</th><th>操作</th></tr></thead>
            <tbody>
            {% for p in pending %}
            <tr>
                <td>{{ p.client_name }}</td>
                <td>{{ p.created_at.isoformat() if p.created_at else '' }}</td>
                <td>{{ p.ip }}</td>
                <td>
                    <button class="approve" data-id="{{ p.connect_id }}">同意</button>
                    <button class="deny" data-id="{{ p.connect_id }}">拒绝</button>
                </td>
            </tr>
            {% endfor %}
            {% if pending|length == 0 %}
            <tr><td colspan="4" class="empty">暂无待审批连接</td></tr>
            {% endif %}
            </tbody>
        </table>
    </section>

    <!-- 已授权客户端 -->
    <section class="panel">
        <h2>已授权客户端 <span class="count">({{ tokens|length }})</span></h2>
        <table>
            <thead><tr><th>名称</th><th>状态</th><th>创建</th><th>到期</th><th>最后使用</th><th>操作</th></tr></thead>
            <tbody>
            {% for t in tokens %}
            <tr>
                <td>{{ t.client_name }}</td>
                <td>{{ t.status }}</td>
                <td>{{ t.created_at.isoformat() if t.created_at else '' }}</td>
                <td>{{ t.expires_at.isoformat() if t.expires_at else '' }}</td>
                <td>{{ t.last_used_at.isoformat() if t.last_used_at else '从未使用' }}</td>
                <td><button class="revoke" data-id="{{ t.id }}">删除</button></td>
            </tr>
            {% endfor %}
            {% if tokens|length == 0 %}
            <tr><td colspan="6" class="empty">暂无已授权客户端</td></tr>
            {% endif %}
            </tbody>
        </table>
    </section>

    <button id="logout-btn" class="logout">退出登录</button>
</div>

<script src="/static/app.js"></script>
</body>
</html>"""