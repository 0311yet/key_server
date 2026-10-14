# Key Server

自托管的密钥管理服务，用于集中存储各平台 API 密钥，供 AI 客户端安全调用。

**生产地址**：部署后自行记录（Vercel 分配的 `*.vercel.app` 域名或自定义域名）
**管理密码**：首次部署由 `LOGIN_PASSWORD` 环境变量建立，之后在 Web 控制台修改，切勿写入仓库

---

## 特性

- **信封加密**：每条密钥用随机数据密钥（DEK，AES-GCM）加密存 Turso；DEK 由管理密码经 scrypt 派生的 KEK 包装后存库。改密码只需重新包装 DEK，数据不用重新加密
- **Web 管理界面**：密码登录，添加/删除密钥，审批 AI 连接，吊销授权，修改管理密码，一键锁定
- **AI 授权流程**：首次连接需 Web 审批，30 天 Bearer token，剩余不足 7 天时自动续期
- **API 接口**：供 AI 调用的 RESTful 接口（列出/获取/上传/删除密钥）
- **密钥简介**：每个密钥可写一段简介（如「OpenAI 主账号」「GitHub PAT，用于发 PR」），AI 列出密钥时能看到，据此选对 key。简介不加密，不要写敏感信息
- **控制台查看明文**：点「查看」按需解密单条密钥，可一键复制，60 秒后自动隐藏
- **双模式部署**：Vercel + Turso + Upstash（生产）/ 本地 SQLite（开发）

---

## 部署

### Vercel（生产推荐）

```bash
git clone git@github.com:0311yet/key_server.git
cd key_server
```

在 **Vercel Dashboard → Settings → Environment Variables** 中填入：

| 变量 | 说明 |
|------|------|
| `LOGIN_PASSWORD` | 初始管理密码，仅在库里还没有密码时使用；初始化后可删除 |
| `KDF_SALT` | scrypt 盐，生成：`python3 -c "import secrets; print(secrets.token_hex(32))"`。**部署后不能再改** |
| `SESSION_SECRET` | Web session 签名密钥，任意长随机字符串 |
| `TURSO_DATABASE_URL` | 从 Turso 控制台复制，如 `libsql://xxx.turso.io` |
| `TURSO_AUTH_TOKEN` | 从 Turso 控制台复制认证 Token |
| `KV_URL` | Upstash 控制台 → REST API 的 URL（也认 `UPSTASH_REDIS_REST_URL` / `KV_REST_API_URL`） |
| `KV_TOKEN` | Upstash 控制台 → REST API 的 Token（也认 `UPSTASH_REDIS_REST_TOKEN` / `KV_REST_API_TOKEN`） |

`vercel.json` 把函数固定在 `hnd1`（东京）。请让 Turso 库和 Upstash 库也在东京附近，
否则每次取 key 都要跨洋往返多次；如果你的数据库在别的区域，相应修改 `regions`。

触发一次 `git push` 即可自动部署。

### 本地开发

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt     # Windows: .venv\Scripts\pip
cp .env.example .env    # 编辑；TURSO_* / KV_* 留空即走本地 SQLite + 进程内存
.venv/bin/uvicorn app.main:app --reload --port 8000
```

**本地 SQLite 降级**：`TURSO_DATABASE_URL` 未配置时自动使用 `data/key_server.db`；
`KV_*` 未配置时数据密钥只存进程内存，进程重启即锁定，需重新登录。

### 测试

```bash
.venv/bin/python -m pytest
```

---

## 安全模型

```
管理密码 ──scrypt(KDF_SALT)──► KEK ──AES-GCM 包装──► DEK（settings.dek_wrapped）
                                                     │
密钥明文 ─────────────────── AES-GCM(DEK) ──────────► Turso（密文）

登录成功 → 解开 DEK → 写入 Upstash KV（TTL 30 天，Web 或 API 有访问即续期）
锁定     → 从 KV 删除 DEK（各实例的进程缓存最多 60 秒内失效）

Bearer token（AI 用）：
    token = secrets.token_urlsafe(32)   # 明文仅 AI 端保存
    库里只存 sha256(token)
```

能保护什么、不能保护什么：

- **只泄露 Turso**：只有密文和被包装的 DEK，没有密码无法解密。✅
- **Turso + Upstash 同时泄露，且服务处于解锁状态**：KV 里的 DEK 可直接解密全部数据。❌
- **Vercel 环境变量泄露**：若 `LOGIN_PASSWORD` 仍在环境变量里，等于泄露管理密码，
  再加上 Turso 即可解密。初始化完成后建议从 Vercel 删除 `LOGIN_PASSWORD`。
- **改 `KDF_SALT`**：KEK 改变，DEK 再也解不开，所有密钥丢失。部署后不要改。
- **忘记管理密码**：同上，无法找回。

### 修改管理密码

在 Web 控制台底部「修改管理密码」中输入原密码和新密码（至少 12 位）。
**直接改 `LOGIN_PASSWORD` 环境变量不会生效**——库中的密码哈希才是准绳。

### 退出与锁定

- **退出登录**：只清除本浏览器的登录态，AI 客户端不受影响。
- **锁定密钥库**：删除 KV 中的 DEK，所有 AI 请求立即返回 423，直到再次登录解锁。

---

## AI 授权流程

```
AI 客户端首次运行
    │
    ▼ POST /api/connect {client_name} → connect_id（pending，15 分钟内有效）
    │
    ├─► 用户在 Web 控制台看到「待审批连接」，点「同意」
    │
    ▼ GET /api/connect/{connect_id}/status → status=approved + token（只发一次）
    │
AI 存储 token，后续直接用：
    │
    ▼ GET /api/keys/{name}  Headers: Authorization: Bearer {token}
    │
    ├─ 剩余 <7 天时自动续期到 +30 天
    └─ 从 Web 可吊销授权
```

`status` 可能的取值：`pending` / `approved`（带 `token` 仅第一次）/ `denied` / `expired` / `invalid`。

---

## AI 接入

推荐直接用配套的 Agent Skill（见下），它只依赖 Python 标准库。自己写客户端的话：

```python
import httpx, time, os

BASE = os.environ["KEY_SERVER_URL"]
TOKEN_FILE = os.path.expanduser("~/.keyserver/token")

def ensure_token(client_name: str) -> str:
    if os.path.exists(TOKEN_FILE):
        return open(TOKEN_FILE).read().strip()
    r = httpx.post(BASE + "/api/connect", data={"client_name": client_name}, timeout=10)
    r.raise_for_status()
    connect_id = r.json()["connect_id"]
    print(f"首次连接，请在 Web 审批。connect_id: {connect_id[:16]}...")
    while True:
        s = httpx.get(BASE + f"/api/connect/{connect_id}/status", timeout=10).json()
        if s["status"] == "approved" and "token" in s:
            os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
            open(TOKEN_FILE, "w").write(s["token"])
            return s["token"]
        if s["status"] in ("denied", "expired", "invalid"):
            raise RuntimeError(f"连接请求未通过：{s['status']}")
        time.sleep(3)

def get_key(name: str, client_name: str = "my-app") -> str:
    token = ensure_token(client_name)
    r = httpx.get(BASE + f"/api/keys/{name}",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    r.raise_for_status()
    return r.json()["key"]
```

### Agent Skill

`skill/key-server/` 是一个可移植的 Agent Skill：任意支持 skills 的 agent 工具
（Claude Code / Claude.ai 等）把 `skill/key-server/` 目录拷进自己的 skills 目录后，
只需 `export KEY_SERVER_URL=<部署地址>`，即可让 agent 通过自然语言取用密钥
（"从 key server 取 openai 的 key"）。首次连接仍需在 Web 控制台点「同意」。

依赖仅标准库，命令：

```bash
python skill/key-server/scripts/keyserver.py get <name>       # 取明文
python skill/key-server/scripts/keyserver.py list             # 列名称 + 简介
printf '%s' "$VALUE" | python skill/key-server/scripts/keyserver.py set <name> - --desc "简介"   # 增改（值走 stdin）
python skill/key-server/scripts/keyserver.py describe <name> "简介"   # 只改简介
python skill/key-server/scripts/keyserver.py delete <name>    # 删除
python skill/key-server/scripts/keyserver.py status           # 健康检查
```

---

## API 文档

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| `POST` | `/login` | CSRF | 登录并解锁，Form: `password` |
| `POST` | `/logout` | CSRF | 退出本浏览器（不锁定） |
| `POST` | `/lock` | CSRF+Session | 锁定密钥库并退出 |
| `GET` | `/dashboard` | Session | Web 控制台页（已锁定则跳转登录） |
| `GET` | `/api/dashboard/data` | Session | JSON: `{keys, pending, tokens}` |
| `POST` | `/dashboard/add_key` | CSRF+Session | 添加/更新密钥，Form: `name`, `value`, `description`（可选，留空保留原简介） |
| `POST` | `/dashboard/reveal_key` | CSRF+Session | 查看明文，Form: `name` → `{key}` |
| `POST` | `/dashboard/set_description` | CSRF+Session | 改简介，Form: `name`, `description`（空即清空） |
| `POST` | `/dashboard/delete_key` | CSRF+Session | 删除密钥，Form: `name` |
| `POST` | `/dashboard/delete_token` | CSRF+Session | 吊销授权，Form: `token_id` |
| `POST` | `/dashboard/change_password` | CSRF+Session | 修改管理密码，Form: `old_password`, `new_password` |
| `POST` | `/connect/{id}/approve` | CSRF+Session | 同意 AI 连接（仅限未过期的 pending） |
| `POST` | `/connect/{id}/deny` | CSRF+Session | 拒绝 AI 连接 |
| `POST` | `/api/connect` | - | AI 敲门，Form: `client_name` |
| `GET` | `/api/connect/{id}/status` | - | AI 轮询审批状态 |
| `GET` | `/api/keys` | Bearer | 列出所有 key：`name`, `description`, `created_at`, `updated_at`（不含明文） |
| `GET` | `/api/keys/{name}` | Bearer | 获取 key 明文：`{key, description}` |
| `POST` | `/api/keys` | Bearer | 添加/更新 key，Form: `name`, `value`, `description`（可选；不传则保留原简介） |
| `POST` | `/api/keys/{name}/description` | Bearer | 只改简介，Form: `description` |
| `DELETE` | `/api/keys/{name}` | Bearer | 删除 key（不存在返回 404） |
| `GET` | `/health` | - | `{"ok":true,"locked":bool}` |

AI API 先校验 token（401），再检查锁定状态（423）。

---

## 项目结构

```
key_server/
├── app/
│   ├── main.py       # FastAPI 路由 + 中间件（路径修正 / 初始化 / 安全响应头）
│   ├── templates.py  # 内联 HTML 模板
│   ├── auth.py       # PBKDF2 密码 / Session / Bearer token
│   ├── crypto.py     # 信封加密（scrypt KEK + AES-GCM DEK），解锁状态存 Upstash KV
│   ├── ratelimit.py  # 限流（KV 共享计数，退回进程内存）
│   ├── db.py         # 同一套 SQL：Turso HTTP API 或标准库 sqlite3
│   └── config.py     # .env 配置加载
├── static/           # app.js + style.css
├── api/index.py      # Vercel 入口
├── tests/            # pytest
├── skill/key-server/ # 配套 Agent Skill（SKILL.md + scripts/keyserver.py + references/）
├── .env.example      # 配置模板
├── vercel.json       # rewrites + 区域（hnd1）
├── requirements.txt      # 生产依赖
├── requirements-dev.txt  # 开发 / 测试依赖
└── pyproject.toml
```
