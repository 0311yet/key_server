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
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="password" name="password" placeholder="管理密码" autocomplete="current-password" required>
            <button type="submit">登录</button>
        </form>
        <div id="err" class="err"></div>
    </div>
    <script src="/static/app.js?v=2"></script>
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
        <h2>密钥管理 <span id="keys-count" class="count">(0)</span></h2>
        <form id="add-form" class="row-form">
            <input type="hidden" name="csrf_token" id="csrf-token" value="{{ csrf_token }}">
            <input name="name" placeholder="名称（如 openai）" required>
            <input name="value" placeholder="密钥值" required>
            <button type="submit">添加/更新</button>
        </form>
        <table>
            <thead><tr><th>名称</th><th>创建时间</th><th>操作</th></tr></thead>
            <tbody id="keys-tbody">
                <tr><td colspan="3" class="empty">加载中...</td></tr>
            </tbody>
        </table>
    </section>

    <!-- 待审批连接 -->
    <section class="panel">
        <h2>待审批连接 <span id="pending-count" class="count">(0)</span></h2>
        <p class="hint">AI 第一次连接时会出现在这里，点【同意】授权它获得 30 天访问 token。</p>
        <table>
            <thead><tr><th>名称</th><th>申请时间</th><th>IP</th><th>操作</th></tr></thead>
            <tbody id="pending-tbody">
                <tr><td colspan="4" class="empty">加载中...</td></tr>
            </tbody>
        </table>
    </section>

    <!-- 已授权客户端 -->
    <section class="panel">
        <h2>已授权客户端 <span id="tokens-count" class="count">(0)</span></h2>
        <table>
            <thead><tr><th>名称</th><th>状态</th><th>创建</th><th>到期</th><th>最后使用</th><th>操作</th></tr></thead>
            <tbody id="tokens-tbody">
                <tr><td colspan="6" class="empty">加载中...</td></tr>
            </tbody>
        </table>
    </section>

    <button id="logout-btn" class="logout">退出登录</button>
</div>

<script src="/static/app.js?v=2"></script>
</body>
</html>"""