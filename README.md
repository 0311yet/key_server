# Key Server

自托管的密钥管理服务，用于集中存储各平台 API 密钥，供 AI 客户端安全调用。

## 特性

- **方案 B1 加密**：密钥用 scrypt 派生的主密钥（AES-GCM）加密存储在 SQLite，主密钥只驻留内存
- **Web 管理界面**：密码登录，添加 / 删除 / 查看密钥
- **AI 授权流程**：AI 第一次连接需在 Web 上审批，之后获取 30 天 token 自动续期
- **API 接口**：给 AI 调用的 RESTful 接口（列出 / 获取 / 上传 / 删除密钥）
- **安全隔离**：Web 密码和 AI token 分开，DB 泄露无法反解出明文

## 部署（Linux 服务器）

```bash
# 1. 克隆 / 拷贝项目
cd key_server

# 2. 生成配置
cp .env.example .env
# 编辑 .env，修改 LOGIN_PASSWORD、KDF_SALT、SESSION_SECRET

# 3. 启动
bash run.sh
```

启动后访问 `http://<服务器IP>:8000`。

## 首次部署

1. 用 `LOGIN_PASSWORD` 登录 Web → 服务端解锁，密钥可读写
2. 添加所需密钥
3. AI 端接入（见下）

## AI 接入方式

AI 客户端只需两行代码即可：

```python
import httpx, time

CONNECT_ID = None  # 第一次填 None，脚本会申请并等待审批

def get_token():
    client_name = "MyClaude"
    if not CONNECT_ID:
        r = httpx.post(BASE + "/api/connect", data={"client_name": client_name})
        CONNECT_ID = r.json()["connect_id"]
        print(f"申请连接，ID: {CONNECT_ID}，请在 Web 上审批")
    while True:
        r = httpx.get(BASE + f"/api/connect/{CONNECT_ID}/status")
        s = r.json()
        if s["status"] == "approved":
            return s["token"]
        time.sleep(3)

BASE = "http://你的服务器:8000"
token = get_token()   # 首次需审批，之后直接返回

# 获取密钥
r = httpx.get(BASE + "/api/keys/mykey", headers={"Authorization": f"Bearer {token}"})
api_key = r.json()["key"]
```

审批后 token 自动续期（剩余 <7 天时每次调用自动延期 30 天），无需重新审批。

## API 文档

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| `GET /api/keys` | 列出所有密钥名称 | | Bearer token |
| `GET /api/keys/{name}` | 获取指定密钥明文 | | Bearer token |
| `POST /api/keys` | 添加 / 更新密钥 | Form: `name`, `value` | Bearer token |
| `DELETE /api/keys/{name}` | 删除密钥 | | Bearer token |
| `POST /api/connect` | AI 首次连接申请 | Form: `client_name` | 无 |
| `GET /api/connect/{id}/status` | AI 轮询审批状态 | | 无 |
| `GET /health` | 服务状态 | `locked` = 是否需登录 Web 解锁 | 无 |
| `POST /login` | Web 登录 | Form: `password` | 无 |
| `POST /dashboard/add_key` | Web 添加密钥 | Form: `name`, `value` | Session cookie |
| `POST /connect/{id}/approve` | Web 审批 AI 连接 | | Session cookie |

## 安全说明

- **方案 B1**：主密钥由登录密码经 scrypt 派生，只在内存中。服务端重启后需重新登录一次 Web 解锁。
- **token 只存 hash**：即使数据库泄露，攻击者也无法恢复 AI token。
- **DB 泄露**：只有 Web 密码哈希（PBKDF2 + salt），无法反推主密钥，无法解密密钥明文。
- 建议 Web 密码使用足够长的随机字符串（≥16 字符）。

## 项目结构

```
key_server/
├── app/
│   ├── main.py      # FastAPI 路由（Web + AI API）
│   ├── auth.py       # 密码 / token 认证
│   ├── crypto.py     # scrypt + AES-GCM 加解密
│   ├── db.py         # SQLite 操作层
│   ├── models.py     # 数据模型
│   └── config.py     # 配置加载
├── templates/        # Jinja2 HTML 模板
├── static/           # CSS + JS
├── data/             # SQLite 数据库文件（自动创建）
├── .env              # 配置文件（不提交）
├── .env.example      # 配置模板
├── requirements.txt
└── run.sh            # 启动脚本
```