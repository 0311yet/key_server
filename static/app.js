// ====== 登录页 ======
(function () {
    async function postForm(url, data) {
        const body = new URLSearchParams(data);
        const r = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
        });
        return r.json();
    }

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
    }

    // ====== 控制台 ======
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
                window.location.reload();
            } else {
                alert(res.error || "失败");
            }
        });
    }

    document.querySelectorAll(".del").forEach((btn) => {
        btn.addEventListener("click", async () => {
            const name = btn.dataset.name;
            if (!confirm(`确认删除密钥 "${name}"？`)) return;
            const res = await postForm("/dashboard/delete_key", { name });
            if (res.ok) window.location.reload();
            else alert(res.error || "失败");
        });
    });

    document.querySelectorAll(".approve").forEach((btn) => {
        btn.addEventListener("click", async () => {
            const id = btn.dataset.id;
            const res = await postForm(`/connect/${id}/approve`, {});
            if (res.ok) {
                alert("已同意，AI 将在下次轮询时拿到 token");
                window.location.reload();
            } else {
                alert(res.error || "失败");
            }
        });
    });

    document.querySelectorAll(".deny").forEach((btn) => {
        btn.addEventListener("click", async () => {
            const id = btn.dataset.id;
            if (!confirm("确认拒绝此连接？")) return;
            // 拒绝 = 删除 pending 记录（简化）
            const res = await postForm(`/connect/${id}/deny`, {});
            if (res.ok) window.location.reload();
            else alert(res.error || "失败");
        });
    });

    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", async () => {
            await postForm("/logout", {});
            window.location.href = "/login";
        });
    }
})();
