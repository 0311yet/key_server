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
        renderKeys(data.keys || []);
        renderPending(data.pending || []);
        renderTokens(data.tokens || []);
    }

    function renderKeys(keys) {
        const tbody = document.getElementById("keys-tbody");
        const countEl = document.getElementById("keys-count");
        countEl.textContent = `(${keys.length})`;
        if (keys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="empty">暂无密钥</td></tr>';
            return;
        }
        tbody.innerHTML = keys.map(k => `
            <tr>
                <td>${escHtml(k.name)}</td>
                <td>${escHtml(k.created_at || '')}</td>
                <td><button class="del" data-name="${escHtml(k.name)}">删除</button></td>
            </tr>
        `).join("");

        // 重新绑定删除按钮
        tbody.querySelectorAll(".del").forEach(btn => {
            btn.onclick = async () => {
                const name = btn.dataset.name;
                if (!confirm(`确认删除密钥 "${name}"？`)) return;
                const res = await postForm("/dashboard/delete_key", { name });
                if (res.ok) loadDashboard();
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
                <td>${escHtml(t.status)}</td>
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

    // 首屏渲染：优先用 window.__DATA__（服务端注入，立即显示）
    if (window.__DATA__) {
        renderPage(window.__DATA__);
    }
    // 立即后台拉取最新数据（首屏已有则无感更新）
    loadDashboard();
    // 每 3 秒轮询
    pollTimer = setInterval(loadDashboard, 3000);

    // 添加 key 表单
    const addForm = document.getElementById("add-form");
    if (addForm) {
        addForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const formData = new FormData(addForm);
            const res = await postForm("/dashboard/add_key", {
                name: formData.get("name"),
                value: formData.get("value"),
            });
            if (res.ok) {
                addForm.reset();
                loadDashboard();
            } else {
                alert(res.error || "失败");
            }
        });
    }

    // 退出登录
    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
        logoutBtn.onclick = async () => {
            clearInterval(pollTimer);
            await postForm("/logout", {});
            window.location.href = "/login";
        };
    }

})();