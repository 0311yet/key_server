// ====== 通用工具 ======
(function () {
    function getCsrfToken() {
        // 1. 优先从隐藏表单字段（SSR 注入，最可靠）
        const el = document.querySelector('input[name="csrf_token"]');
        if (el && el.value) return el.value;
        // 2. fallback：cookie
        const cookies = document.cookie ? document.cookie.split(';') : [];
        for (const c of cookies) {
            const [k, ...v] = c.trim().split('=');
            if (k === 'csrf_token' && v.length) return v.join('=');
        }
        return "";
    }
    async function postForm(url, data) {
        const body = new URLSearchParams(data);
        const headers = { "Content-Type": "application/x-www-form-urlencoded" };
        const csrf = getCsrfToken();
        if (csrf) headers["X-CSRF-Token"] = csrf;
        const r = await fetch(url, {
            method: "POST",
            headers: headers,
            body: body.toString(),
        });
        return r.json();
    }
    async function getJson(url) {
        const r = await fetch(url, { signal: AbortSignal.timeout(30000) });
        if (r.status === 401 || r.status === 423) {
            window.location.href = "/login";  // 会话失效或密钥库已锁定：回登录页（登录即解锁）
            return new Promise(() => {});
        }
        if (!r.ok) {
            const err = new Error(`HTTP ${r.status}`);
            err.status = r.status;
            throw err;
        }
        return r.json();
    }
    // ====== 登录页 ======
    const loginForm = document.getElementById("login-form");
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const err = document.getElementById("err");
            err.textContent = "";
            const formData = new FormData(loginForm);
            const res = await postForm("/login", { password: formData.get("password") });
            if (res.ok) {
                window.location.href = "/dashboard";
            } else {
                err.textContent = res.error || "登录失败";
            }
        });
        return;
    }
    // ====== 控制台 ======
    let pollTimer = null;
    function renderPage(data) {
        const keys = data.keys || [];
        const pending = data.pending || [];
        const tokens = data.tokens || [];
        renderKeys(keys);
        renderPending(pending);
        renderTokens(tokens);
        // 同步更新顶部统计卡片
        const sk = document.getElementById("stat-keys");
        const sp = document.getElementById("stat-pending");
        const sc = document.getElementById("stat-clients");
        if (sk) sk.textContent = keys.length;
        if (sp) sp.textContent = pending.length;
        if (sc) sc.textContent = tokens.length;
    }
    // 已点开查看的明文：name -> { value, timer }。轮询重绘表格时保留，60 秒后自动隐藏
    const revealed = new Map();
    const REVEAL_MS = 60000;
    let lastKeys = [];
    function hideKey(name) {
        const r = revealed.get(name);
        if (r) clearTimeout(r.timer);
        revealed.delete(name);
        renderKeys(lastKeys);
    }
    function renderKeys(keys) {
        lastKeys = keys;
        const tbody = document.getElementById("keys-tbody");
        const countEl = document.getElementById("keys-count");
        countEl.textContent = `(${keys.length})`;
        if (keys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty">暂无密钥</td></tr>';
            return;
        }
        tbody.innerHTML = keys.map(k => {
            const shown = revealed.get(k.name);
            const row = `
            <tr>
                <td>${escHtml(k.name)}</td>
                <td class="key-desc">${k.description ? escHtml(k.description) : '<span class="muted">—</span>'}</td>
                <td>${escHtml(k.updated_at || '')}</td>
                <td class="actions">
                    <button class="reveal" data-name="${escHtml(k.name)}">${shown ? '隐藏' : '查看'}</button>
                    <button class="edit-desc" data-name="${escHtml(k.name)}">简介</button>
                    <button class="del" data-name="${escHtml(k.name)}">删除</button>
                </td>
            </tr>`;
            if (!shown) return row;
            return row + `
            <tr class="reveal-row">
                <td colspan="4">
                    <code class="secret">${escHtml(shown.value)}</code>
                    <button class="copy" data-name="${escHtml(k.name)}">复制</button>
                </td>
            </tr>`;
        }).join("");
        tbody.querySelectorAll(".reveal").forEach(btn => {
            btn.onclick = async () => {
                const name = btn.dataset.name;
                if (revealed.has(name)) { hideKey(name); return; }
                const res = await postForm("/dashboard/reveal_key", { name });
                if (!res.ok) { alert(res.error || "失败"); return; }
                revealed.set(name, { value: res.key, timer: setTimeout(() => hideKey(name), REVEAL_MS) });
                renderKeys(lastKeys);
            };
        });
        tbody.querySelectorAll(".copy").forEach(btn => {
            btn.onclick = async () => {
                const r = revealed.get(btn.dataset.name);
                if (!r) return;
                try {
                    await navigator.clipboard.writeText(r.value);
                    btn.textContent = "已复制";
                    setTimeout(() => { btn.textContent = "复制"; }, 1500);
                } catch (e) {
                    alert("复制失败，请手动选中复制");
                }
            };
        });
        tbody.querySelectorAll(".edit-desc").forEach(btn => {
            btn.onclick = async () => {
                const name = btn.dataset.name;
                const cur = (lastKeys.find(k => k.name === name) || {}).description || "";
                const desc = prompt(`「${name}」的简介（留空即清空，最多 500 字）：`, cur);
                if (desc === null) return;
                const res = await postForm("/dashboard/set_description", { name, description: desc });
                if (res.ok) loadDashboard();
                else alert(res.error || "失败");
            };
        });
        tbody.querySelectorAll(".del").forEach(btn => {
            btn.onclick = async () => {
                const name = btn.dataset.name;
                if (!confirm(`确认删除密钥 "${name}"？`)) return;
                const res = await postForm("/dashboard/delete_key", { name });
                if (res.ok) { revealed.delete(name); loadDashboard(); }
                else alert(res.error || "失败");
            };
        });
    }
    function renderPending(pending) {
        const tbody = document.getElementById("pending-tbody");
        const countEl = document.getElementById("pending-count");
        countEl.textContent = `(${pending.length})`;
        if (pending.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty">暂无待审批连接</td></tr>';
            return;
        }
        tbody.innerHTML = pending.map(p => `
            <tr>
                <td>${escHtml(p.client_name)}</td>
                <td>${escHtml(p.created_at || '')}</td>
                <td>${escHtml(p.ip || '')}</td>
                <td>
                    <button class="approve" data-id="${escHtml(p.connect_id)}">同意</button>
                    <button class="deny" data-id="${escHtml(p.connect_id)}">拒绝</button>
                </td>
            </tr>
        `).join("");
        tbody.querySelectorAll(".approve").forEach(btn => {
            btn.onclick = async () => {
                const res = await postForm(`/connect/${btn.dataset.id}/approve`, {});
                if (res.ok) {
                    alert("已同意");
                    loadDashboard();
                } else alert(res.error || "失败");
            };
        });
        tbody.querySelectorAll(".deny").forEach(btn => {
            btn.onclick = async () => {
                if (!confirm("确认拒绝此连接？")) return;
                const res = await postForm(`/connect/${btn.dataset.id}/deny`, {});
                if (res.ok) loadDashboard();
                else alert(res.error || "失败");
            };
        });
    }
    function renderTokens(tokens) {
        const tbody = document.getElementById("tokens-tbody");
        const countEl = document.getElementById("tokens-count");
        countEl.textContent = `(${tokens.length})`;
        if (tokens.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty">暂无已授权客户端</td></tr>';
            return;
        }
        tbody.innerHTML = tokens.map(t => `
            <tr>
                <td>${escHtml(t.client_name)}</td>
                <td><span class="status-badge ${escHtml(t.status)}">${escHtml(t.status)}</span></td>
                <td>${escHtml(t.created_at || '')}</td>
                <td>${escHtml(t.expires_at || '')}</td>
                <td>${escHtml(t.last_used_at || '从未使用')}</td>
                <td><button class="revoke" data-id="${t.id}">删除</button></td>
            </tr>
        `).join("");
        tbody.querySelectorAll(".revoke").forEach(btn => {
            btn.onclick = async () => {
                if (!confirm("确认删除此客户端？此操作不可撤销。")) return;
                const res = await postForm("/dashboard/delete_token", { token_id: btn.dataset.id });
                if (res.ok) loadDashboard();
                else alert(res.error || "失败");
            };
        });
    }
    function escHtml(s) {
        const div = document.createElement("div");
        div.textContent = s;
        return div.innerHTML;
    }
    async function loadDashboard(retries = 3, backoff = 1000) {
        try {
            const data = await getJson("/api/dashboard/data");
            if (!data.ok) {
                clearInterval(pollTimer);
                window.location.href = "/login";
                return;
            }
            renderPage(data);
        } catch (e) {
            console.warn("Dashboard API error:", e.status || e.message);
            if (retries > 0) {
                setTimeout(() => loadDashboard(retries - 1, backoff * 2), backoff);
            }
            // 不覆盖首屏数据，用户仍可看到已渲染的内容
        }
    }
    // 首屏渲染：优先用服务端注入的 JSON 块（<script type="application/json">，不可执行）
    let ssrData = null;
    const initEl = document.getElementById("init-data");
    if (initEl) {
        try { ssrData = JSON.parse(initEl.textContent); } catch (e) { ssrData = null; }
    }
    const hasSsrData = !!ssrData;
    if (hasSsrData) {
        renderPage(ssrData);
    }
    // SSR 已注入数据则跳过首次 AJAX（数据不可能在毫秒级变化），减少一次服务端查询
    if (!hasSsrData) {
        loadDashboard();
    }
    // 每 15 秒轮询（原 3 秒过于频繁，对 Serverless 函数造成不必要的冷启动和 DB 查询）
    pollTimer = setInterval(loadDashboard, 15000);
    // 添加 key 表单
    const addForm = document.getElementById("add-form");
    if (addForm) {
        addForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const formData = new FormData(addForm);
            const res = await postForm("/dashboard/add_key", {
                name: formData.get("name"),
                value: formData.get("value"),
                description: formData.get("description") || "",
            });
            if (res.ok) {
                addForm.reset();
                loadDashboard();
            } else {
                alert(res.error || "失败");
            }
        });
    }
    // 修改管理密码
    const pwdForm = document.getElementById("pwd-form");
    if (pwdForm) {
        pwdForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const formData = new FormData(pwdForm);
            const res = await postForm("/dashboard/change_password", {
                old_password: formData.get("old_password"),
                new_password: formData.get("new_password"),
            });
            if (res.ok) {
                pwdForm.reset();
                alert("密码已修改，下次登录请用新密码");
            } else {
                alert(res.error || "失败");
            }
        });
    }
    // 退出登录：只退出本浏览器，不影响 AI 客户端
    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
        logoutBtn.onclick = async () => {
            clearInterval(pollTimer);
            await postForm("/logout", {});
            window.location.href = "/login";
        };
    }
    // 锁定密钥库：所有 AI 客户端立即无法取 key
    const lockBtn = document.getElementById("lock-btn");
    if (lockBtn) {
        lockBtn.onclick = async () => {
            if (!confirm("锁定后所有 AI 客户端将无法取 key，直到你重新登录。确认锁定？")) return;
            clearInterval(pollTimer);
            await postForm("/lock", {});
            window.location.href = "/login";
        };
    }
})();
