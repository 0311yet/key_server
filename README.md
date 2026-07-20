# Key Server

自托管的密钥管理服务，用于集中存储各平台 API 密钥，供 AI 客户端安全调用。

**生产地址**：`https://key-server-wine.vercel.app`
**管理密码**：`test123!@#`（生产环境请在 Vercel Dashboard 修改环境变量）

---

## 特性

- **方案 B1 加密**：密钥用 scrypt 派生的主密钥（AES-GCM）加密存 Turso，主密钥存 Upstash KV（滑动窗口 30 天 TTL）
- **Web 管理界面**：密码登录，添加/删除/查看密钥，待审批连接管理
- **AI 授权流程**：首次连接需 Web 审批，30 天 Bearer token，到期前自动续期
- **API 接口**：供 AI 调用的 RESTful 接口（列出/获取/上传/删除密钥）
- **安全隔离**：Web 密码和 AI token 分开，数据库泄露无法反解出明文
- **双模式部署**：Vercel（生产）+ 本地 SQLite（开发）

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
| `LOGIN_PASSWORD` | Web 登录密码 |
| `KDF_SALT` | scrypt 盐，生成：`python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `SESSION_SECRET` | itsdangerous 签名密钥，任意长随机字符串 |
| `TURSO_DATABASE_URL` | 从 Turso 控制台复制，如 `libsql://xxx.turso.io` |
| `TURSO_AUTH_TOKEN` | 从 Turso 控制台复制认证 Token |
| `UPSTASH_REDIS_REST_URL` | 从 Upstash 控制台 → REST API 复制 |
| `UPSTASH_REDIS_REST_TOKEN` | 从 Upstash 控制台 → REST API 复制 |

触发一次 `git push` 即可自动部署。

### 本地开发

```bash
pip install -r requirements.txt
cp .env.example .env  # 编辑填入 TURSO_*/UPSTASH_* 配置（或留空走 SQLite）
uvicorn app.main:app --reload --port 8000
```

**本地 SQLite 降级**：如果 `TURSO_DATABASE_URL` 未配置，自动使用本地 `data/key_server.db`，无需 Turso/Upstash。

---

## 安全模型

```
LOGIN_PASSWORD
    │
    ▼ scrypt(password, KDF_SALT, n=65536, r=8, p=1) ──► 32 字节主密钥
    │
    ▼ AES-GCM
密钥明文 ──► Turso 数据库（encrypted blob）

Bearer token（AI 用）：
    token_value = secrets.token_urlsafe(32)   # 原始 token 仅 AI 端保存
    token_hash  = sha256(token.encode())       # 数据库只存 hash
```

- **锁定态**：进程启动后 Upstash KV 无主密钥，`/health` 返回 `locked: true`
- **解锁**：用户登录 Web，主密钥写入 Upstash KV（30 天 TTL，每次解锁刷新）
- **重启需重新登录**：KV 主密钥 TTL 到期后需重新登录

---

## AI 授权流程

```
AI 客户端首次运行
    │
    ▼ POST /api/connect {client_name} → connect_id（pending）
    │
    ├─► 用户在 Web 控制台看到「待审批连接」，点「同意」
    │
    ▼ GET /api/connect/{connect_id}/status → status=approved + token=xxx
    │
AI 存储 token，后续直接用：
    │
    ▼ GET /api/keys/{name}  Headers: Authorization: Bearer {token}
    │
    ├─ 剩余 <7 天时自动续期到 +30 天
    └─ 从 Web 可吊销授权
```

---

## AI 接入（两行代码）

```python
import httpx, time, os

BASE = os.environ["KEY_SERVER_URL"]
TOKEN_FILE = ".keyserver_token"

def _load_token():
    return open(TOKEN_FILE).read().strip() if os.path.exists(TOKEN_FILE) else None

def ensure_token(client_name: str) -> str:
    token = _load_token()
    if token:
        return token
    r = httpx.post(BASE + "/api/connect", data={"client_name": client_name}, timeout=10)
    r.raise_for_status()
    connect_id = r.json()["connect_id"]
    print(f"首次连接，请在 Web 审批。connect_id: {connect_id}")
    while True:
        r = httpx.get(BASE + f"/api/connect/{connect_id}/status", timeout=10)
        r.raise_for_status()
        s = r.json()
        if s["status"] == "approved" and "token" in s:
            open(TOKEN_FILE, "w").write(s["token"])
            return s["token"]
        elif s["status"] == "denied":
            raise RuntimeError("Key Server 拒绝了连接请求")
        time.sleep(3)

def get_key(name: str, client_name: str = "my-app") -> str:
    token = ensure_token(client_name=client_name)
    r = httpx.get(BASE + f"/api/keys/{name}",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    r.raise_for_status()
    return r.json()["key"]

# 用法
# api_key = get_key("openai")
```

---

## API 文档

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| `POST` | `/login` | CSRF | 登录，Form: `password` |
| `POST` | `/logout` | CSRF+Session | 退出，锁定服务端 |
| `GET` | `/dashboard` | Session | Web 控制台页 |
| `GET` | `/api/dashboard/data` | Session | JSON: `{keys, pending, tokens}` |
| `POST` | `/dashboard/add_key` | CSRF+Session | 添加密钥，Form: `name`, `value` |
| `POST` | `/dashboard/delete_key` | CSRF+Session | 删除密钥，Form: `name` |
| `POST` | `/dashboard/delete_token` | CSRF+Session | 吊销授权，Form: `token_id` |
| `POST` | `/connect/{id}/approve` | CSRF+Session | 同意 AI 连接 |
| `POST` | `/connect/{id}/deny` | CSRF+Session | 拒绝 AI 连接 |
| `POST` | `/api/connect` | - | AI 敲门，Form: `client_name` |
| `GET` | `/api/connect/{id}/status` | - | AI 轮询审批状态 |
| `GET` | `/api/keys` | Bearer | 列出所有 key 名称（不含明文） |
| `GET` | `/api/keys/{name}` | Bearer | 获取 key 明文 |
| `POST` | `/api/keys` | Bearer | 添加/更新 key，Form: `name`, `value` |
| `DELETE` | `/api/keys/{name}` | Bearer | 删除 key |
| `GET` | `/health` | - | `{"ok":true,"locked":bool}` |

---

## 项目结构

```
key_server/
├── app/
│   ├── main.py       # FastAPI 路由（内联模板，兼容 Vercel）
│   ├── templates.py  # 内联 Jinja2 模板
│   ├── auth.py       # PBKDF2 密码 / Session / Bearer token
│   ├── crypto.py     # scrypt + AES-GCM（主密钥存 Upstash KV）
│   ├── db.py         # Turso HTTP API 或 SQLite
│   ├── models.py     # SQLModel（SQLite 模式）
│   └── config.py     # .env 配置加载
├── static/
│   ├── app.js        # AJAX + CSRF + 轮询
│   └── style.css
├── api/
│   └── index.py      # Vercel 入口
├── .env              # 配置（不提交）
├── .env.example      # 配置模板
├── vercel.json
├── pyproject.toml
└── requirements.txt
```